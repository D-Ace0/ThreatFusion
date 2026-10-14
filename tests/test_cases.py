import asyncio
from io import BytesIO

import httpx
import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
from typer.testing import CliRunner

from threatfusion.api import create_app
from threatfusion.case_models import AuditEntry, EnrichmentJob
from threatfusion.case_reports import case_pdf, csv_report
from threatfusion.cases import Cases
from threatfusion.cli import app
from threatfusion.extraction import extract_case, refang
from threatfusion.service import Fusion
from threatfusion.storage import Store
from threatfusion.triage import prioritize

TEXT = """Failed login from 10.0.0.7 to 8.8.8.8
src=10.0.0.7 download=hxxps://bad[.]example/login action=blocked process=powershell
src=10.0.0.7 download=hxxps://bad[.]example/login action=deny
sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
ipv6=2001:4860::8888
"""


def test_extraction_context_dedup_relations():
    c = prioritize(extract_case("test", "events.log", TEXT))
    by_value = {i.ioc.value: i for i in c.indicators}
    ip = by_value["10.0.0.7"]
    assert ip.occurrences == 3 and not ip.ioc.public and ip.priority == "high"
    assert [o.line for o in ip.observations] == [1, 2, 3]
    assert "authentication failure" in ip.tags and "execution context" in ip.tags
    assert any("process tree" in step for step in ip.next_steps)
    assert by_value["https://bad.example/login"].occurrences == 2
    assert "bad.example" in by_value
    assert any(e.kind == "url_host" and e.count == 2 for e in c.relationships)
    assert len(c.input_sha256) == 64 and c.audit[0].action == "import"
    assert all(i.analysis is None for i in c.indicators)
    assert "hxxps://bad[.]example/login" in ip.observations[1].excerpt
    assert "2001:4860::8888" in by_value


@pytest.mark.parametrize(
    "text",
    ["", "nothing supported here", "\x00binary", "x" * 200001, "\n" * 10001 + "8.8.8.8"],
    ids=["empty", "no-iocs", "binary", "oversized", "too-many-lines"],
)
def test_bad_imports(text):
    with pytest.raises(ValueError):
        extract_case("test", "text", text)


def test_bounded_extraction_and_hashes():
    c = extract_case("test", "list", "\n".join(f"item{i}.example" for i in range(220)))
    assert len(c.indicators) == 200
    assert any("first 200" in w for w in c.warnings)
    c = extract_case("test", "list", "a" * 32 + " " + "b" * 40 + " " + "c" * 64)
    assert {i.ioc.type.value for i in c.indicators} == {"md5", "sha1", "sha256"}
    assert refang("hxxp://a[.]example") == "http://a.example"
    with pytest.raises(ValueError):
        extract_case("test", "files", "powershell.exe cmd.exe report.csv")


async def finish(manager, job):
    task = manager.tasks.get(job.id)
    if task:
        await task
    return manager.store.get_job(job.id)


async def test_offline_import_notes_persistence(settings):
    manager = Cases(Fusion(settings))
    c = await manager.create("case", "events.log", TEXT)
    i = c.indicators[0]
    c = await manager.review(c.id, i.id, "investigate", "Checked endpoint logs")
    assert next(x for x in c.indicators if x.id == i.id).note == "Checked endpoint logs"
    assert (await manager.get(c.id)).audit[-1].action == "review"
    assert manager.store.cases()[0].id == c.id
    await manager.delete(c.id)
    with pytest.raises(KeyError):
        await manager.get(c.id)
    await manager.close()


async def test_demo_batch_isolated(settings):
    manager = Cases(Fusion(settings))
    c = await manager.create(
        "training", "synthetic", "203.0.113.42 suspicious.example 10.0.0.7", True
    )
    job = await manager.start(c.id, "demo")
    done = await finish(manager, job)
    assert done.status == "completed" and done.completed == 3
    c = await manager.get(c.id)
    assert all(i.analysis.mode == "demo" for i in c.indicators)
    assert any("SIMULATED" in reason for i in c.indicators for reason in i.reasons)
    with pytest.raises(ValueError):
        await manager.start(c.id, "live", selected=[i.id for i in c.indicators])
    with pytest.raises(ValueError):
        await manager.start(c.id, "demo", selected=["not-in-case"])
    await manager.close()


async def test_live_batch_privacy_and_concurrent_notes(settings):
    settings.demo = False
    settings.vt_key = type(settings.vt_key)("mock-test-key")
    calls = []
    gate = asyncio.Event()

    async def handler(request):
        calls.append(str(request.url))
        await gate.wait()
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        manager = Cases(Fusion(settings, client))
        c = await manager.create("real", "logs", "10.0.0.7 https://example.com/secret 8.8.8.8")
        with pytest.raises(ValueError, match="explicitly"):
            await manager.start(c.id, "live")
        job = await manager.start(c.id, "live", selected=[i.id for i in c.indicators])
        await asyncio.sleep(0.02)
        with pytest.raises(ValueError, match="active"):
            await manager.start(c.id, "live", selected=[i.id for i in c.indicators])
        with pytest.raises(ValueError):
            await manager.delete(c.id)
        item = next(i for i in c.indicators if i.ioc.value == "8.8.8.8")
        await manager.review(c.id, item.id, "expected", "Known resolver confirmed by owner")
        gate.set()
        done = await finish(manager, job)
        assert done.status == "completed" and done.skipped == 2
        assert done.completed == 2  # public IP and derived hostname; never full URL/private IP
        assert all("secret" not in u and "10.0.0.7" not in u and "/urls/" not in u for u in calls)
        c = await manager.get(c.id)
        item = next(i for i in c.indicators if i.id == item.id)
        assert item.note == "Known resolver confirmed by owner" and item.disposition == "expected"
        assert item.analysis.score.risk is None
        await manager.close()


async def test_cancel_and_recovery(settings):
    class Slow:
        name = "slow"
        from threatfusion.models import IOCType

        supported = set(IOCType)

        async def enrich(self, ioc):
            await asyncio.sleep(60)

    manager = Cases(Fusion(settings, providers=[Slow()]))
    settings.demo = False
    c = await manager.create("real", "text", "8.8.8.8")
    job = await manager.start(c.id, "live", selected=[i.id for i in c.indicators])
    await asyncio.sleep(0.02)
    done = await manager.cancel(job.id)
    assert done.status == "cancelled" and done.completed == 0
    assert c.id not in manager.active_cases
    queued = EnrichmentJob(id="crashed", case_id=c.id, mode="live", total=1)
    manager.store.save_job(queued)
    manager.store.recover_jobs()
    assert manager.store.get_job("crashed").status == "interrupted"
    with pytest.raises(KeyError):
        await manager.cancel("missing")
    await manager.close()


def test_case_exports_escape_and_decisions():
    c = prioritize(extract_case("<script>alert(1)</script>", "test", TEXT))
    c.indicators[0].note = '=HYPERLINK("https://example.com")'
    c.indicators[0].disposition = "escalate"
    c.audit.append(AuditEntry(action="review", detail="escalation recorded"))
    csv = csv_report(c).decode("utf-8-sig")
    assert "'=HYPERLINK" in csv and "escalate" in csv
    reader = PdfReader(BytesIO(case_pdf(c)))
    text = "".join(p.extract_text() for p in reader.pages)
    assert "Investigation brief" in text and "escalation recorded" in text
    assert "Line 1" in text and "process tree" in text


def test_case_api_workflow(settings):
    with TestClient(create_app(settings)) as client:
        c = client.post("/api/cases", json={"title": "Example", "text": TEXT}).json()
        assert c["id"] and not c["synthetic"]
        assert client.get("/api/cases").json()[0]["indicator_count"] == len(c["indicators"])
        item = c["indicators"][0]
        updated = client.patch(
            f"/api/cases/{c['id']}/indicators/{item['id']}",
            json={"disposition": "investigate", "note": "Context reviewed"},
        )
        assert updated.status_code == 200
        for fmt in ("json", "csv", "pdf"):
            report = client.get(f"/api/cases/{c['id']}/report?format={fmt}")
            assert report.status_code == 200
        assert client.get("/api/cases/missing").status_code == 404
        assert (
            client.post("/api/cases", json={"title": "empty", "text": "no indicators"}).status_code
            == 422
        )
        assert client.post(f"/api/cases/{c['id']}/enrich", json={"mode": "live"}).status_code == 409
        assert client.post("/api/jobs/missing/cancel").status_code == 404
        assert client.get("/api/jobs/missing").status_code == 404
        demo = client.post("/api/cases/demo").json()
        assert demo["synthetic"] and len(demo["indicators"]) >= 8
        job = client.post(f"/api/cases/{demo['id']}/enrich", json={"mode": "demo"}).json()
        assert client.get("/api/jobs/" + job["id"]).status_code == 200
        client.post(f"/api/jobs/{job['id']}/cancel")
        assert client.delete(f"/api/cases/{c['id']}").status_code == 200
        assert client.get(f"/api/cases/{c['id']}").status_code == 404


def test_case_auth_and_large_import(settings):
    settings.api_key = type(settings.api_key)("secret")
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/cases").status_code == 401
        assert client.post("/api/cases/demo").status_code == 401
        headers = {"X-API-Key": "secret"}
        text = "8.8.8.8\n" + "context " * 2000
        assert (
            client.post(
                "/api/cases", json={"title": "long", "text": text}, headers=headers
            ).status_code
            == 201
        )
        assert (
            client.post("/api/cases", content="x" * 1_048_577, headers=headers).status_code == 413
        )


def test_case_cli(monkeypatch, tmp_path):
    path = tmp_path / "cases.sqlite3"
    monkeypatch.setenv("THREATFUSION_DB_PATH", str(path))
    source = tmp_path / "events.log"
    source.write_text(TEXT)
    runner = CliRunner()
    result = runner.invoke(app, ["case-import", str(source), "--title", "Test case"])
    assert result.exit_code == 0, result.output
    case = Store(path).cases()[0]
    assert "Test case" in runner.invoke(app, ["case-list"]).output
    for format in ("json", "csv", "pdf"):
        target = tmp_path / ("case." + format)
        result = runner.invoke(app, ["case-report", case.id, str(target)])
        assert result.exit_code == 0 and target.stat().st_size > 0
    assert runner.invoke(app, ["case-report", "missing", "report.pdf"]).exit_code == 2
    assert runner.invoke(app, ["case-import", str(tmp_path / "missing.txt")]).exit_code == 2
