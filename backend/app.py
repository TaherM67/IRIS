"""FastAPI transport. HTTP/runtime tests must be run on the target computer."""
from __future__ import annotations

import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import __version__
from .config import Settings
from .core import INPUTS, BusyError, Engine, view
from .security import Guard

STATIC = Path(__file__).with_name("static")


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    disposition: Literal["approve_follow_up", "reject_suggestion"]
    comment: str = Field(min_length=5, max_length=2000)


def require_role(request: Request, *roles: str) -> str:
    role = getattr(request.state, "principal", None)
    if role not in roles:
        raise HTTPException(403, "This role is not allowed to perform that action")
    return role


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.load()

    @asynccontextmanager
    async def lifespan(app):
        app.state.engine = Engine(settings)  # One load per process, never per request.
        yield
        app.state.engine = None

    app = FastAPI(title="IRIS shadow backend", version=__version__, lifespan=lifespan, redoc_url=None)
    app.add_middleware(Guard, settings=settings)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    router = APIRouter(prefix="/api", dependencies=[Depends(APIKeyHeader(name="X-IRIS-Key"))])

    @app.get("/", include_in_schema=False)
    def home():
        return FileResponse(STATIC / "index.html")

    @app.get("/health")
    def health():
        return {"status": "alive", "mode": "shadow_only", "automatic_execution": False}

    @router.get("/me")
    def me(request: Request):
        role = require_role(request, "admin", "soc", "grc")
        return {"role": role, "views": ["admin", "soc", "grc"] if role == "admin" else [role], "mode": "shadow_only"}

    @router.get("/model")
    def model(request: Request):
        return request.app.state.engine.adapter.status()

    @router.get("/runs")
    def runs(request: Request):
        return request.app.state.engine.store.runs()

    async def execute(request, paths, role):
        try:
            return await run_in_threadpool(request.app.state.engine.run, paths, role)
        except BusyError as exc:
            raise HTTPException(409, str(exc)) from exc
        except (ValueError, UnicodeError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.post("/runs/sample")
    async def sample(request: Request):
        role = require_role(request, "admin", "soc")
        from .model_adapter import SAMPLES
        return await execute(request, {key: SAMPLES / name for key, name in INPUTS.items()}, role)

    @router.post("/runs")
    async def upload(request: Request, asset_inventory: UploadFile = File(...),
                     risk_register: UploadFile = File(...), siem_alerts: UploadFile = File(...)):
        role = require_role(request, "admin", "soc")
        form = await request.form()
        if len(list(form.multi_items())) != 3 or set(form) != set(INPUTS):
            raise HTTPException(422, "Exactly three files are allowed; no labels or model uploads")
        incoming = settings.state_dir / "incoming"
        incoming.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="batch-", dir=incoming) as directory:
            paths = {}
            for key, item in {"asset_inventory": asset_inventory, "risk_register": risk_register, "siem_alerts": siem_alerts}.items():
                path = Path(directory) / INPUTS[key]  # Never trust client filenames as server paths.
                maximum = (20 if key == "siem_alerts" else 5) * 1024 * 1024
                size = 0
                with path.open("xb") as stream:
                    while chunk := await item.read(65536):
                        size += len(chunk)
                        if size > maximum:
                            raise HTTPException(413, f"{key}: file-size limit exceeded")
                        stream.write(chunk)
                paths[key] = path
            return await execute(request, paths, role)

    def case_or_404(engine, case_id):
        try:
            return engine.store.case(case_id)
        except KeyError as exc:
            raise HTTPException(404, "Case not found") from exc

    def list_view(request, audience, run_id, limit, offset):
        require_role(request, audience, "admin")
        result = request.app.state.engine.store.cases(run_id, limit, offset)
        result["items"] = [view(case, audience) for case in result["items"]]
        return result

    @router.get("/soc/cases")
    def soc_cases(request: Request, run_id: str | None = None, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
        return list_view(request, "soc", run_id, limit, offset)

    @router.get("/grc/cases")
    def grc_cases(request: Request, run_id: str | None = None, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
        return list_view(request, "grc", run_id, limit, offset)

    @router.get("/soc/cases/{case_id}")
    def soc_case(request: Request, case_id: str):
        require_role(request, "soc", "admin")
        return view(case_or_404(request.app.state.engine, case_id), "soc")

    @router.get("/grc/cases/{case_id}")
    def grc_case(request: Request, case_id: str):
        require_role(request, "grc", "admin")
        return view(case_or_404(request.app.state.engine, case_id), "grc")

    @router.post("/grc/cases/{case_id}/review")
    def review(request: Request, case_id: str, body: Review):
        role = require_role(request, "grc")  # Admin is not a substitute risk reviewer.
        case_or_404(request.app.state.engine, case_id)
        try:
            saved = request.app.state.engine.store.review(case_id, body.disposition, body.comment, role)
            return {"review": saved, "scope": "LOCAL_FOLLOW_UP_ONLY", "official_risk_register_write": False,
                    "automatic_execution": False, "external_delivery": False}
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @router.get("/admin/status")
    def admin_status(request: Request):
        require_role(request, "admin")
        engine = request.app.state.engine
        return {"storage": engine.store.health(), "model": engine.adapter.status(),
                "live_connectors": False, "external_delivery": False, "single_worker_only": True,
                "processing": engine.lock.locked(), "batch_limits": {"bytes": settings.max_body_bytes,
                "alert_rows": settings.max_alert_rows, "sessions": settings.max_sessions}}

    @router.get("/admin/audit")
    def audit(request: Request):
        require_role(request, "admin")
        return request.app.state.engine.store.audit_events()

    app.include_router(router)
    return app
