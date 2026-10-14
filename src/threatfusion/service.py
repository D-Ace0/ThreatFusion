import asyncio
import hashlib
from uuid import uuid4

from .config import Settings
from .demo import demo_providers
from .models import Analysis, IOCType, ProviderResult
from .providers import Provider, live_providers
from .scoring import score
from .storage import Store
from .validation import validate


class Fusion:
    def __init__(self, settings: Settings, client=None, providers: list[Provider] | None = None):
        self.settings = settings
        self.store = Store(settings.db_path)
        self.providers = (
            providers
            if providers is not None
            else (demo_providers() if settings.demo else live_providers(settings, client))
        )
        names = [p.name for p in self.providers]
        if len(set(names)) != len(names) or not names:
            raise ValueError("Provider names must be unique; at least one provider is required")
        self.semaphore = asyncio.Semaphore(8)

    async def analyze(self, value: str, allow_url: bool = False, refresh: bool = False) -> Analysis:
        ioc = validate(value)
        mode = "demo" if self.settings.demo else "live"

        async def enrich(provider):
            if ioc.type not in provider.supported:
                return ProviderResult(source=provider.name, status="unsupported")
            # Policy runs BEFORE cache access and before any plugin call.
            if not self.settings.demo and (
                not ioc.public or (ioc.type == IOCType.url and not allow_url)
            ):
                return ProviderResult(
                    source=provider.name,
                    status="blocked",
                    message="Non-public indicator or URL disclosure not authorized",
                )
            key = hashlib.sha256(
                f"v1|{mode}|{provider.name}|{ioc.type.value}|{ioc.value}".encode()
            ).hexdigest()
            if not refresh and (cached := await asyncio.to_thread(self.store.cached, key)):
                return cached
            try:
                async with self.semaphore:
                    result = await asyncio.wait_for(provider.enrich(ioc), timeout=120)
                if result.source != provider.name:
                    raise ValueError("Provider attribution mismatch")
                if any(e.source != provider.name for e in result.evidence):
                    raise ValueError("Evidence attribution mismatch")
            except Exception:
                # A plugin failure must not discard other sources or leak request secrets.
                result = ProviderResult(
                    source=provider.name, status="error", message="Provider failed"
                )
            if result.status in ("ok", "not_found"):
                await asyncio.to_thread(self.store.cache, key, result, self.settings.cache_ttl)
            return result

        results = await asyncio.gather(*(enrich(p) for p in self.providers))
        analysis = Analysis(
            id=str(uuid4()), ioc=ioc, mode=mode, results=results, score=score(results)
        )
        await asyncio.to_thread(self.store.save, analysis)
        return analysis
