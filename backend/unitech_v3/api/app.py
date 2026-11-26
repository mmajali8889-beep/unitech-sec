from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .. import __version__, security
from ..config import Settings
from ..db import DB
from ..ratelimit import RateLimiter
from ..services import Ctx, start_background
from . import admin_routes, agent_routes, auth_routes, core_routes

CSP = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    settings.ensure()
    db = DB(settings.db_path)
    db.migrate()
    ctx = Ctx(settings, db, security.load_secret(settings.secret_path), RateLimiter())
    app = FastAPI(title="UNITECH Security Center V3", version=__version__, docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.state.ctx = ctx
    for r in (auth_routes.router, core_routes.router, admin_routes.router, agent_routes.router):
        app.include_router(r)

    @app.middleware("http")
    async def sec_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        if not request.url.path.startswith("/api/"):
            resp.headers.setdefault("Content-Security-Policy", CSP)
        return resp

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        return JSONResponse({"detail": "internal error"}, status_code=500)   # never leak internals

    dist = settings.frontend_dist
    if dist.exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith("api/"):
                return JSONResponse({"detail": "not found"}, status_code=404)
            f = (dist / path).resolve()
            if path and f.is_file() and dist.resolve() in f.parents:
                return FileResponse(f)
            return FileResponse(dist / "index.html")

    if settings.start_scheduler:
        @app.on_event("startup")
        def _start():
            start_background(ctx)

        @app.on_event("shutdown")
        def _stop():
            ctx.stop.set()
    return app
