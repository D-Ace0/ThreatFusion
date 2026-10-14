import json
from datetime import timedelta
from importlib.resources import files

from .models import Evidence, IOCType, ProviderResult, utcnow


def fixtures():
    return json.loads(files("threatfusion").joinpath("fixtures/demo.json").read_text())


class DemoProvider:
    def __init__(self, name, supported):
        self.name = name
        self.supported = supported

    async def enrich(self, ioc):
        if ioc.type not in self.supported:
            return ProviderResult(source=self.name, status="unsupported", message="Synthetic demo")
        data = fixtures()
        profile = data["indicators"].get(ioc.value)
        if not profile:
            return ProviderResult(
                source=self.name, status="not_found", message="No synthetic fixture for this IOC"
            )
        d = data["profiles"][profile]
        metric, value, total = {
            "virustotal": ("detections", d["malicious"], d["total"]),
            "abuseipdb": ("abuse_confidence", d["abuse"], None),
            "otx": ("pulse_count", d["pulses"], None),
        }[self.name]
        e = Evidence(
            source=self.name,
            metric=metric,
            value=value,
            total=total,
            description="SYNTHETIC demo evidence; not real provider intelligence",
            source_url="fixture://demo/" + profile,
            observed_at=utcnow() - timedelta(days=d["age_days"]),
        )
        return ProviderResult(source=self.name, status="ok", evidence=[e], message="SYNTHETIC demo")


def demo_providers():
    return [
        DemoProvider("virustotal", set(IOCType)),
        DemoProvider("abuseipdb", {IOCType.ipv4, IOCType.ipv6}),
        DemoProvider("otx", set(IOCType)),
    ]
