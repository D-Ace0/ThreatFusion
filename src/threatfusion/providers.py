"""Fixed-origin, GET-only adapters. Plugins implement the Provider protocol."""

import asyncio
import base64
import math
import random
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Protocol
from urllib.parse import quote

import httpx

from .config import Settings
from .models import IOC, Evidence, IOCType, ProviderResult, utcnow


class Provider(Protocol):
    name: str
    supported: set[IOCType]

    async def enrich(self, ioc: IOC) -> ProviderResult: ...


def timestamp(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC)
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def count_value(value) -> int:
    """Reject negative/fractional/boolean counts rather than silently truncating."""
    if isinstance(value, bool):
        raise ValueError("Boolean is not a count")
    result = int(value)
    if result < 0 or float(value) != result:
        raise ValueError("Invalid count")
    return result


def retry_delay(value: str | None) -> float | None:
    if not value:
        return None
    try:
        delay = float(value)
        return max(0.0, delay) if math.isfinite(delay) else None
    except ValueError:
        try:
            return max(0.0, (parsedate_to_datetime(value) - utcnow()).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return None


class HTTPProvider:
    name = "base"
    supported: set[IOCType] = set()
    base = ""
    key_field = ""
    header = ""

    def __init__(self, settings: Settings, client: httpx.AsyncClient):
        self.settings = settings
        self.client = client
        self.lock = asyncio.Lock()
        self.cooldown = 0.0

    def request(self, ioc: IOC) -> tuple[str, dict]:
        raise NotImplementedError

    def normalize(self, data: dict, ioc: IOC, endpoint: str) -> list[Evidence]:
        raise NotImplementedError

    async def enrich(self, ioc: IOC) -> ProviderResult:
        if ioc.type not in self.supported:
            return ProviderResult(source=self.name, status="unsupported")
        key = getattr(self.settings, self.key_field).get_secret_value()
        if not key:
            return ProviderResult(
                source=self.name, status="unconfigured", message="API key missing"
            )
        # Serialize each provider to keep simultaneous local requests from bursting quotas.
        async with self.lock:
            loop = asyncio.get_running_loop()
            if loop.time() < self.cooldown:
                return ProviderResult(
                    source=self.name,
                    status="rate_limited",
                    retry_after=self.cooldown - loop.time(),
                    message="Provider cooldown",
                )
            endpoint, params = self.request(ioc)
            for attempt in range(1, self.settings.retries + 2):
                delay = None
                try:
                    response = await self.client.get(
                        self.base + endpoint,
                        params=params,
                        headers={self.header: key, "Accept": "application/json"},
                        timeout=self.settings.timeout,
                        follow_redirects=False,
                    )
                    code = response.status_code
                    if code == 404:
                        return ProviderResult(
                            source=self.name,
                            status="not_found",
                            attempts=attempt,
                            message="No existing record; not evidence of safety",
                        )
                    if code in (401, 403):
                        return ProviderResult(
                            source=self.name,
                            status="error",
                            attempts=attempt,
                            message="Authentication or entitlement denied",
                        )
                    if code == 429:
                        delay = retry_delay(response.headers.get("Retry-After"))
                        delay = delay if delay is not None else 2**attempt
                        if delay > self.settings.retry_cap or attempt > self.settings.retries:
                            self.cooldown = loop.time() + max(delay, 1)
                            return ProviderResult(
                                source=self.name,
                                status="rate_limited",
                                attempts=attempt,
                                retry_after=delay,
                                message="Quota reached; retry later",
                            )
                    elif 500 <= code < 600:
                        delay = min(2 ** (attempt - 1) + random.random(), self.settings.retry_cap)
                    elif code != 200:
                        return ProviderResult(
                            source=self.name,
                            status="error",
                            attempts=attempt,
                            message=f"Provider HTTP {code}",
                        )
                    else:
                        # Do not persist raw responses, free text, or response bodies in errors.
                        if len(response.content) > 2_000_000:
                            raise ValueError("Response too large")
                        evidence = self.normalize(response.json(), ioc, self.base + endpoint)
                        return ProviderResult(
                            source=self.name, status="ok", evidence=evidence, attempts=attempt
                        )
                except httpx.RequestError:
                    delay = min(2 ** (attempt - 1) + random.random(), self.settings.retry_cap)
                except (ValueError, KeyError, TypeError, OverflowError):
                    return ProviderResult(
                        source=self.name,
                        status="error",
                        attempts=attempt,
                        message="Malformed provider response",
                    )
                if attempt <= self.settings.retries:
                    await asyncio.sleep(delay or 0)
            return ProviderResult(
                source=self.name,
                status="error",
                attempts=attempt,
                message="Transport or server failure after bounded retries",
            )


class VirusTotal(HTTPProvider):
    name = "virustotal"
    supported = set(IOCType)
    base = "https://www.virustotal.com/api/v3"
    key_field, header = "vt_key", "x-apikey"

    def request(self, ioc):
        route = {
            IOCType.ipv4: "ip_addresses",
            IOCType.ipv6: "ip_addresses",
            IOCType.domain: "domains",
            IOCType.url: "urls",
        }.get(ioc.type, "files")
        identifier = (
            base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
            if ioc.type == IOCType.url
            else ioc.value
        )
        return f"/{route}/{quote(identifier, safe='')}", {}

    def normalize(self, data, ioc, endpoint):
        attrs = data["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
        malicious = count_value(stats["malicious"])
        total = sum(count_value(v) for v in stats.values())
        if total <= 0 or malicious > total:
            raise ValueError("Invalid analysis stats")
        return [
            Evidence(
                source=self.name,
                metric="detections",
                value=malicious,
                total=total,
                description="Engines reporting malicious; engines are correlated",
                source_url=endpoint,
                observed_at=timestamp(attrs.get("last_analysis_date")),
            )
        ]


class AbuseIPDB(HTTPProvider):
    name = "abuseipdb"
    supported = {IOCType.ipv4, IOCType.ipv6}
    base = "https://api.abuseipdb.com/api/v2"
    key_field, header = "abuse_key", "Key"

    def request(self, ioc):
        return "/check", {"ipAddress": ioc.value, "maxAgeInDays": 90}

    def normalize(self, data, ioc, endpoint):
        d = data["data"]
        value = float(d["abuseConfidenceScore"])
        if not 0 <= value <= 100:
            raise ValueError("Invalid confidence")
        return [
            Evidence(
                source=self.name,
                metric="abuse_confidence",
                value=value,
                description="Provider abuse score, not ThreatFusion confidence",
                source_url="https://www.abuseipdb.com/check/" + quote(ioc.value, safe=""),
                observed_at=timestamp(d.get("lastReportedAt")),
            )
        ]


class AlienVaultOTX(HTTPProvider):
    name = "otx"
    supported = set(IOCType)
    base = "https://otx.alienvault.com/api/v1"
    key_field, header = "otx_key", "X-OTX-API-KEY"

    def request(self, ioc):
        kind = {
            IOCType.ipv4: "IPv4",
            IOCType.ipv6: "IPv6",
            IOCType.domain: "domain",
            IOCType.url: "url",
        }.get(ioc.type, "file")
        return f"/indicators/{kind}/{quote(ioc.value, safe='')}/general", {}

    def normalize(self, data, ioc, endpoint):
        pulses = data["pulse_info"]
        count = count_value(pulses["count"])
        dates = [timestamp(p.get("modified") or p.get("created")) for p in pulses.get("pulses", [])]
        return [
            Evidence(
                source=self.name,
                metric="pulse_count",
                value=count,
                description="Community pulse association does not establish maliciousness",
                source_url=endpoint,
                observed_at=max((d for d in dates if d), default=None),
            )
        ]


def live_providers(settings, client) -> list[Provider]:
    return [
        VirusTotal(settings, client),
        AbuseIPDB(settings, client),
        AlienVaultOTX(settings, client),
    ]
