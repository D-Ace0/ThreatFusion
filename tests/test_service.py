import asyncio

import httpx
import pytest

from threatfusion.models import Evidence, IOCType, ProviderResult, utcnow
from threatfusion.scoring import score
from threatfusion.service import Fusion
from threatfusion.storage import Store


@pytest.mark.parametrize(
    "value,consent",
    [
        ("10.0.0.1", False),
        ("127.0.0.1", True),
        ("::1", True),
        ("https://example.com/a?secret=1", False),
        ("https://192.168.0.1", True),
        ("service.internal", True),
        ("https://[::ffff:127.0.0.1]/", True),
    ],
)
async def test_privacy_no_network(settings, value, consent):
    settings.demo = False
    settings.vt_key = settings.abuse_key = settings.otx_key = type(settings.vt_key)("key")

    def fail(_):
        pytest.fail("Privacy violation: outbound request")

    async with httpx.AsyncClient(transport=httpx.MockTransport(fail)) as client:
        result = await Fusion(settings, client).analyze(value, allow_url=consent)
    assert all(r.status in ("blocked", "unsupported") for r in result.results)
    assert result.score.risk is None


async def test_explicit_url_lookup(settings):
    settings.demo = False
    settings.vt_key = settings.otx_key = type(settings.vt_key)("key")
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.url.host in ("www.virustotal.com", "otx.alienvault.com")
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        fusion = Fusion(settings, client)
        first = await fusion.analyze("https://example.com/a", allow_url=True)
        blocked = await fusion.analyze("https://example.com/a", allow_url=False)
    assert len(calls) == 2
    assert first.score.risk is None
    assert blocked.results[0].status == "blocked"  # consent checked before cache


async def test_cache_history_refresh(settings):
    fusion = Fusion(settings)
    first = await fusion.analyze("203.0.113.42")
    second = await fusion.analyze("203.0.113.42")
    third = await fusion.analyze("203.0.113.42", refresh=True)
    assert not any(r.cached for r in first.results)
    assert all(r.cached for r in second.results)
    assert not any(r.cached for r in third.results)
    assert second.results[0].retrieved_at == first.results[0].retrieved_at
    assert fusion.store.get(first.id) == first
    assert len(fusion.store.history()) == 3
    fusion.store.clear()
    assert not fusion.store.history()


async def test_cache_expiry(settings):
    settings.cache_ttl = 0
    fusion = Fusion(settings)
    await fusion.analyze("203.0.113.42")
    assert not any(r.cached for r in (await fusion.analyze("203.0.113.42")).results)


async def test_demo_no_network_and_unknown(settings):
    fusion = Fusion(settings)
    a = await fusion.analyze("203.0.113.42")
    assert a.mode == "demo" and a.score.risk == 76
    assert a.score.coverage == 100 and a.score.freshness >= 97
    assert (await fusion.analyze("unknown.example")).score.risk is None
    stale = await fusion.analyze("2001:db8::42")
    assert stale.score.freshness == 0 and stale.score.confidence == 40


async def test_plugin_failure_isolated(settings):
    class Broken:
        name = "broken"
        supported = set(IOCType)

        async def enrich(self, ioc):
            raise RuntimeError("secret")

    from threatfusion.demo import demo_providers

    fusion = Fusion(settings, providers=[Broken(), demo_providers()[0]])
    result = await fusion.analyze("203.0.113.42")
    assert result.results[0].status == "error" and result.results[1].status == "ok"
    assert "secret" not in result.model_dump_json()


async def test_concurrent_history(settings):
    fusion = Fusion(settings)
    results = await asyncio.gather(*(fusion.analyze("203.0.113.42") for _ in range(12)))
    assert len({a.id for a in results}) == 12 and len(fusion.store.history()) == 12


def test_no_weight_redistribution():
    e = Evidence(
        source="otx",
        metric="pulse_count",
        value=100,
        description="test",
        source_url="fixture://test",
        observed_at=utcnow(),
    )
    s = score(
        [
            ProviderResult(source="otx", status="ok", evidence=[e]),
            ProviderResult(source="vt", status="error"),
        ]
    )
    assert s.risk == 10 and s.coverage == 50 and s.confidence == 25
    e.observed_at = None
    assert score([ProviderResult(source="otx", status="ok", evidence=[e])]).freshness == 0


def test_sql_parameterization(settings):
    assert Store(settings.db_path).get("' OR 1=1 --") is None
