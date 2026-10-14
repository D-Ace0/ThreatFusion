import asyncio
import secrets
from contextlib import asynccontextmanager
from importlib.resources import files
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import Settings
from .demo import fixtures
from .models import Analysis
from .reports import pdf_report
from .service import Fusion


class AnalyzeRequest(BaseModel):
    value: str = Field(min_length=1, max_length=2048)
    allow_url: bool = False
    refresh: bool = False


def create_app(settings: Settings | None = None, providers=None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(
            trust_env=False, limits=httpx.Limits(max_connections=12)
        ) as client:
            app.state.fusion = Fusion(settings, client, providers)
            yield

    app = FastAPI(
        title="ThreatFusion",
        version="1.0.0",
        lifespan=lifespan,
        description="Privacy-conscious IOC enrichment. Scores are unvalidated heuristics.",
        docs_url=None,
        redoc_url=None,
    )

    @app.middleware("http")
    async def secure_response(request: Request, call_next):
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            if origin and origin != str(request.base_url).rstrip("/"):
                return Response("Cross-origin mutation blocked", status_code=403)
        length = request.headers.get("content-length")
        if length and (not length.isdigit() or int(length) > 8192):
            return Response("Request too large", status_code=413)
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
        return {"status": "ok", "version": "1.0.0", "mode": "demo" if settings.demo else "live"}

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

    static = str(files("threatfusion").joinpath("static"))
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/", include_in_schema=False)
    async def dashboard():
        return FileResponse(static + "/index.html")

    @app.get("/docs", include_in_schema=False)
    async def documentation():
        return FileResponse(static + "/docs.html")

    return app
