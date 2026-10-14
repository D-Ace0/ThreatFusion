from io import BytesIO

from fastapi.testclient import TestClient
from pypdf import PdfReader
from typer.testing import CliRunner

from threatfusion.api import create_app
from threatfusion.cli import app


def test_api_end_to_end(settings):
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/health").json()["mode"] == "demo"
        assert client.get("/").status_code == 200
        assert "Same-origin REST explorer" in client.get("/docs").text
        assert client.get("/static/app.js").status_code == 200
        assert client.get("/openapi.json").status_code == 200
        response = client.post("/api/analyze", json={"value": "203.0.113.42"})
        assert response.status_code == 200
        a = response.json()
        assert a["score"]["risk"] == 76
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "script-src 'self'" in response.headers["Content-Security-Policy"]
        assert client.get("/api/analyses/" + a["id"]).json() == a
        assert len(client.get("/api/history").json()) == 1
        assert client.get("/api/history?limit=0").status_code == 422
        assert client.get("/api/analyses/missing").status_code == 404
        assert client.post("/api/analyze", json={"value": "bad"}).status_code == 422
        assert client.get(f"/api/analyses/{a['id']}/report?format=csv").status_code == 422
        exported = client.get(f"/api/analyses/{a['id']}/report?format=json")
        assert exported.json() == a
        pdf = client.get(f"/api/analyses/{a['id']}/report?format=pdf")
        assert pdf.content.startswith(b"%PDF")
        reader = PdfReader(BytesIO(pdf.content))
        text = "".join(p.extract_text() for p in reader.pages)
        assert "203.0.113.42" in text and "SYNTHETIC" in text and "unvalidated" in text
        assert client.delete("/api/history").json() == {"cleared": True}
        assert not client.get("/api/history").json()


def test_auth_csrf_size(settings):
    settings.api_key = type(settings.api_key)("test-key")
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/history").status_code == 401
        assert client.post("/api/analyze", json={"value": "203.0.113.42"}).status_code == 401
        headers = {"X-API-Key": "test-key"}
        assert client.get("/api/history", headers=headers).status_code == 200
        assert (
            client.post(
                "/api/analyze",
                json={"value": "203.0.113.42"},
                headers={**headers, "Origin": "https://evil.example"},
            ).status_code
            == 403
        )
        assert client.post("/api/analyze", content="x" * 9000, headers=headers).status_code == 413


def test_cli(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATFUSION_DB_PATH", str(tmp_path / "cli.sqlite3"))
    monkeypatch.setenv("THREATFUSION_DEMO", "true")
    runner = CliRunner()
    assert runner.invoke(app, ["validate", "8.8.8.8"]).exit_code == 0
    assert runner.invoke(app, ["validate", "bad"]).exit_code == 2
    result = runner.invoke(
        app, ["analyze", "203.0.113.42", "--json", "--output", str(tmp_path / "report.json")]
    )
    assert result.exit_code == 0, result.output
    assert '"risk": 76' in result.output
    assert (tmp_path / "report.json").exists()
    pdf = runner.invoke(app, ["analyze", "203.0.113.42", "--output", str(tmp_path / "report.pdf")])
    assert pdf.exit_code == 0 and (tmp_path / "report.pdf").read_bytes().startswith(b"%PDF")
    assert runner.invoke(app, ["analyze", "bad"]).exit_code == 2
    assert runner.invoke(app, ["analyze", "203.0.113.42", "--output", "bad.txt"]).exit_code == 2
    assert runner.invoke(app, ["demo"]).exit_code == 0
    assert "203.0.113.42" in runner.invoke(app, ["history"]).output
    assert runner.invoke(app, ["clear-history"]).exit_code == 2
    assert runner.invoke(app, ["clear-history", "--yes"]).exit_code == 0
    monkeypatch.setenv("THREATFUSION_API_KEY", "")
    assert runner.invoke(app, ["serve", "--host", "0.0.0.0"]).exit_code == 2
