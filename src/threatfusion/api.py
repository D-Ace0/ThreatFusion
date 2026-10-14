import asyncio
import secrets
from contextlib import asynccontextmanager
from importlib.resources import files
from typing import Annotated, Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .body_limit import BodyLimitMiddleware
from .case_models import Case, Disposition, EnrichmentJob
from .case_reports import case_pdf, csv_report
from .cases import Cases
from .config import Settings
from .demo import fixtures
from .models import Analysis
from .reports import pdf_report
from .service import Fusion


class AnalyzeRequest(BaseModel):
    value: str = Field(min_length=1, max_length=2048)
    allow_url: bool = False
    refresh: bool = False


class ImportCase(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    source_name: str = Field(default="pasted text", min_length=1, max_length=120)
    text: str = Field(min_length=1, max_length=200_000)


class ReviewRequest(BaseModel):
    disposition: Disposition
    note: str = Field(default="", max_length=4000)


class EnrichCase(BaseModel):
    mode: Literal["demo", "live"] = "demo"
    selected: list[str] = Field(default_factory=list, max_length=200)
    allow_url: bool = False


def create_app(settings: Settings | None = None, providers=None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(
            trust_env=False, limits=httpx.Limits(max_connections=12)
        ) as client:
            app.state.fusion = Fusion(settings, client, providers)
            app.state.cases = Cases(app.state.fusion)
            try:
                yield
            finally:
                await app.state.cases.close()

    app = FastAPI(
        title="ThreatFusion",
        version="1.1.0",
        lifespan=lifespan,
        description="Privacy-conscious IOC enrichment. Scores are unvalidated heuristics.",
        docs_url=None,
        redoc_url=None,
    )
    app.add_middleware(BodyLimitMiddleware)

    @app.middleware("http")
    async def secure_response(request: Request, call_next):
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            if origin and origin != str(request.base_url).rstrip("/"):
                return Response("Cross-origin mutation blocked", status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    async def auth(x_api_key: Annotated[str | None, Header()] = None):
        expected = settings.api_key.get_secret_value()
        if expected and (
            not x_api_key or not secrets.compare_digest(x_api_key.encode(), expected.encode())
        ):
            raise HTTPException(401, "Valid X-API-Key required")

    guard = [Depends(auth)]

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "version": "1.1.0", "mode": "demo" if settings.demo else "live"}

    @app.get("/api/demo", dependencies=guard)
    async def demo():
        return {"notice": fixtures()["notice"], "indicators": list(fixtures()["indicators"])}

    @app.post("/api/analyze", response_model=Analysis, dependencies=guard)
    async def analyze(body: AnalyzeRequest, request: Request):
        try:
            return await request.app.state.fusion.analyze(body.value, body.allow_url, body.refresh)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/history", response_model=list[Analysis], dependencies=guard)
    async def history(
        request: Request, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)
    ):
        return await asyncio.to_thread(request.app.state.fusion.store.history, limit, offset)

    @app.delete("/api/history", dependencies=guard)
    async def clear(request: Request):
        await asyncio.to_thread(request.app.state.fusion.store.clear)
        return {"cleared": True}

    async def lookup(identifier, request):
        result = await asyncio.to_thread(request.app.state.fusion.store.get, identifier)
        if not result:
            raise HTTPException(404, "Analysis not found")
        return result

    @app.get("/api/analyses/{identifier}", response_model=Analysis, dependencies=guard)
    async def get_analysis(identifier: str, request: Request):
        return await lookup(identifier, request)

    @app.get("/api/analyses/{identifier}/report", dependencies=guard)
    async def report(
        identifier: str, request: Request, format: str = Query("json", pattern="^(json|pdf)$")
    ):
        result = await lookup(identifier, request)
        payload = (
            await asyncio.to_thread(pdf_report, result)
            if format == "pdf"
            else result.model_dump_json(indent=2).encode()
        )
        return Response(
            payload,
            media_type="application/pdf" if format == "pdf" else "application/json",
            headers={
                "Content-Disposition": f'attachment; filename="threatfusion-{result.id}.{format}"'
            },
        )

    @app.post("/api/cases", response_model=Case, dependencies=guard, status_code=201)
    async def import_case(body: ImportCase, request: Request):
        try:
            return await request.app.state.cases.create(body.title, body.source_name, body.text)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/api/cases/demo", response_model=Case, dependencies=guard, status_code=201)
    async def demo_case(request: Request):
        text = files("threatfusion").joinpath("fixtures/incident.txt").read_text()
        return await request.app.state.cases.create(
            "Suspicious workstation activity (training)", "synthetic-incident.log", text, True
        )

    @app.get("/api/cases", dependencies=guard)
    async def list_cases(
        request: Request, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)
    ):
        cases = await asyncio.to_thread(request.app.state.fusion.store.cases, limit, offset)
        return [
            {
                "id": c.id,
                "title": c.title,
                "source_name": c.source_name,
                "synthetic": c.synthetic,
                "updated_at": c.updated_at,
                "indicator_count": len(c.indicators),
                "unreviewed": sum(i.disposition == "unreviewed" for i in c.indicators),
            }
            for c in cases
        ]

    @app.get("/api/cases/{case_id}", response_model=Case, dependencies=guard)
    async def get_case(case_id: str, request: Request):
        try:
            return await request.app.state.cases.get(case_id)
        except KeyError as exc:
            raise HTTPException(404, "Case not found") from exc

    @app.patch(
        "/api/cases/{case_id}/indicators/{indicator_id}", response_model=Case, dependencies=guard
    )
    async def review(case_id: str, indicator_id: str, body: ReviewRequest, request: Request):
        try:
            return await request.app.state.cases.review(
                case_id, indicator_id, body.disposition, body.note
            )
        except KeyError as exc:
            raise HTTPException(404, "Case or indicator not found") from exc

    @app.post(
        "/api/cases/{case_id}/enrich",
        response_model=EnrichmentJob,
        dependencies=guard,
        status_code=202,
    )
    async def enrich_case(case_id: str, body: EnrichCase, request: Request):
        try:
            return await request.app.state.cases.start(
                case_id, body.mode, body.selected, body.allow_url
            )
        except KeyError as exc:
            raise HTTPException(404, "Case not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/jobs/{job_id}", response_model=EnrichmentJob, dependencies=guard)
    async def job_status(job_id: str, request: Request):
        job = await asyncio.to_thread(request.app.state.fusion.store.get_job, job_id)
        if not job:
            raise HTTPException(404, "Job not found")
        return job

    @app.post("/api/jobs/{job_id}/cancel", response_model=EnrichmentJob, dependencies=guard)
    async def cancel_job(job_id: str, request: Request):
        try:
            return await request.app.state.cases.cancel(job_id)
        except KeyError as exc:
            raise HTTPException(404, "Job not found") from exc

    @app.delete("/api/cases/{case_id}", dependencies=guard)
    async def delete_case(case_id: str, request: Request):
        try:
            await request.app.state.cases.delete(case_id)
            return {"deleted": True}
        except KeyError as exc:
            raise HTTPException(404, "Case not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/cases/{case_id}/report", dependencies=guard)
    async def export_case(
        case_id: str, request: Request, format: str = Query("json", pattern="^(json|csv|pdf)$")
    ):
        case = await get_case(case_id, request)
        if format == "pdf":
            payload, media_type = await asyncio.to_thread(case_pdf, case), "application/pdf"
        elif format == "csv":
            payload, media_type = await asyncio.to_thread(csv_report, case), "text/csv"
        else:
            payload, media_type = case.model_dump_json(indent=2).encode(), "application/json"
        return Response(
            payload,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="threatfusion-case-{case.id}.{format}"'
            },
        )

    static = str(files("threatfusion").joinpath("static"))
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/", include_in_schema=False)
    async def dashboard():
        return FileResponse(static + "/cases.html")

    @app.get("/lookup", include_in_schema=False)
    async def lookup_dashboard():
        return FileResponse(static + "/index.html")

    @app.get("/docs", include_in_schema=False)
    async def documentation():
        return FileResponse(static + "/docs.html")

    return app
