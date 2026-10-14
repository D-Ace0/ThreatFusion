from datetime import timedelta
from email.utils import format_datetime

import httpx
import pytest

from threatfusion.models import utcnow
from threatfusion.providers import AbuseIPDB, AlienVaultOTX, VirusTotal, retry_delay
from threatfusion.validation import validate


@pytest.mark.parametrize(
    "cls,payload,metric,value,path,header",
    [
        (
            VirusTotal,
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 4, "harmless": 6},
                        "last_analysis_date": 1700000000,
                    }
                }
            },
            "detections",
            4,
            "/api/v3/ip_addresses/8.8.8.8",
            "x-apikey",
        ),
        (
            AbuseIPDB,
            {"data": {"abuseConfidenceScore": 90, "lastReportedAt": "2026-01-01T00:00:00Z"}},
            "abuse_confidence",
            90,
            "/api/v2/check",
            "Key",
        ),
        (
            AlienVaultOTX,
            {"pulse_info": {"count": 3, "pulses": [{"modified": "2026-01-01T00:00:00Z"}]}},
            "pulse_count",
            3,
            "/api/v1/indicators/IPv4/8.8.8.8/general",
            "X-OTX-API-KEY",
        ),
    ],
)
async def test_normalization(settings, cls, payload, metric, value, path, header):
    settings.vt_key = settings.abuse_key = settings.otx_key = type(settings.vt_key)("secret")

    def handler(request):
        assert request.method == "GET"
        assert request.url.path == path
        assert request.headers[header] == "secret"
        if cls is AbuseIPDB:
            assert request.url.params["ipAddress"] == "8.8.8.8"
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await cls(settings, client).enrich(validate("8.8.8.8"))
    assert result.status == "ok"
    assert result.evidence[0].metric == metric
    assert result.evidence[0].value == value
    assert result.evidence[0].observed_at.tzinfo
    assert "secret" not in result.model_dump_json()


@pytest.mark.parametrize(
    "status,expected",
    [
        (401, "error"),
        (403, "error"),
        (404, "not_found"),
        (429, "rate_limited"),
        (500, "error"),
        (302, "error"),
    ],
)
async def test_http_failures(settings, status, expected):
    settings.vt_key = type(settings.vt_key)("secret")
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            status,
            headers={"Retry-After": "600", "Location": "https://evil.example"},
            text="secret error",
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = VirusTotal(settings, client)
        result = await provider.enrich(validate("8.8.8.8"))
        if status == 429:
            second = await provider.enrich(validate("1.1.1.1"))
            assert second.status == "rate_limited" and len(calls) == 1
    assert result.status == expected
    assert len(calls) == (2 if status == 500 else 1)
    assert "secret" not in result.model_dump_json()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"data": {}},
        {"data": {"attributes": {"last_analysis_stats": {"malicious": -1}}}},
        {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 0}}}},
    ],
)
async def test_malformed(settings, payload):
    settings.vt_key = type(settings.vt_key)("secret")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
    ) as client:
        assert (await VirusTotal(settings, client).enrich(validate("8.8.8.8"))).status == "error"


async def test_transport_retry(settings):
    settings.vt_key = type(settings.vt_key)("secret")
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ReadTimeout("secret URL", request=request)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await VirusTotal(settings, client).enrich(validate("8.8.8.8"))
    assert result.status == "not_found" and result.attempts == 2


async def test_rate_limit_retry(settings):
    settings.vt_key = type(settings.vt_key)("secret")
    settings.retry_cap = 1
    calls = []

    def handler(request):
        calls.append(request)
        return (
            httpx.Response(429, headers={"Retry-After": "0"})
            if len(calls) == 1
            else httpx.Response(404)
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await VirusTotal(settings, client).enrich(validate("8.8.8.8"))
    assert result.status == "not_found" and result.attempts == 2


async def test_no_key_or_unsupported(settings):
    def fail(_):
        pytest.fail("Unexpected external request")

    async with httpx.AsyncClient(transport=httpx.MockTransport(fail)) as client:
        assert (
            await VirusTotal(settings, client).enrich(validate("8.8.8.8"))
        ).status == "unconfigured"
        assert (
            await AbuseIPDB(settings, client).enrich(validate("example.com"))
        ).status == "unsupported"


@pytest.mark.parametrize(
    "value,segment",
    [
        ("example.com", "domains"),
        ("a" * 32, "files"),
        ("a" * 40, "files"),
        ("a" * 64, "files"),
        ("https://example.com/x?q=1", "urls"),
        ("2001:4860::1", "ip_addresses"),
    ],
)
def test_vt_paths(settings, value, segment):
    path, _ = VirusTotal(settings, None).request(validate(value))
    assert path.startswith("/" + segment + "/")
    if segment == "urls":
        assert "?" not in path and "=" not in path


def test_retry_after_dates():
    assert 0 <= retry_delay(format_datetime(utcnow() + timedelta(seconds=30))) <= 30
    assert retry_delay("garbage") is None
    assert retry_delay("-1") == 0
