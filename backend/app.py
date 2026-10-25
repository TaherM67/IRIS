# IRIS EXPLAIN: File purpose: Earlier FastAPI transport: public static pages plus authenticated three-file batch analysis and
# IRIS EXPLAIN: local follow-up reviews; not the active demo HTTP server.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""FastAPI transport. HTTP/runtime tests must be run on the target computer."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import tempfile to create fresh isolated run/upload/test directories.
import tempfile
# IRIS EXPLAIN: Import asynccontextmanager from contextlib to manage connection/lifespan/lock cleanup reliably.
from contextlib import asynccontextmanager
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path
# IRIS EXPLAIN: Import Literal from typing to declare expected interfaces/types for readers and type-checking tools.
from typing import Literal

# IRIS EXPLAIN: Import APIRouter, Depends, FastAPI, File, HTTPException, Query, Request, UploadFile from fastapi to declare the
# IRIS EXPLAIN: earlier HTTP routes, uploads, authorization responses and schemas.
from fastapi import APIRouter, Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
# IRIS EXPLAIN: Import FileResponse from fastapi.responses to declare the earlier HTTP routes, uploads, authorization responses
# IRIS EXPLAIN: and schemas.
from fastapi.responses import FileResponse
# IRIS EXPLAIN: Import APIKeyHeader from fastapi.security to declare the earlier HTTP routes, uploads, authorization responses
# IRIS EXPLAIN: and schemas.
from fastapi.security import APIKeyHeader
# IRIS EXPLAIN: Import StaticFiles from fastapi.staticfiles to declare the earlier HTTP routes, uploads, authorization responses
# IRIS EXPLAIN: and schemas.
from fastapi.staticfiles import StaticFiles
# IRIS EXPLAIN: Import BaseModel, ConfigDict, Field from pydantic to validate the earlier FastAPI request body without accepting
# IRIS EXPLAIN: extra fields.
from pydantic import BaseModel, ConfigDict, Field
# IRIS EXPLAIN: Import run_in_threadpool from starlette.concurrency to run synchronous batch work outside the earlier FastAPI
# IRIS EXPLAIN: event loop.
from starlette.concurrency import run_in_threadpool

# IRIS EXPLAIN: Import __version__ from . to reuse the shared project contract/implementation rather than duplicate it.
from . import __version__
# IRIS EXPLAIN: Import Settings from .config to reuse the shared project contract/implementation rather than duplicate it.
from .config import Settings
# IRIS EXPLAIN: Import INPUTS, BusyError, Engine, view from .core to reuse the shared project contract/implementation rather
# IRIS EXPLAIN: than duplicate it.
from .core import INPUTS, BusyError, Engine, view
# IRIS EXPLAIN: Import Guard from .security to reuse the shared project contract/implementation rather than duplicate it.
from .security import Guard

# IRIS EXPLAIN: Store the result of Path(__file__).with_name('static') in STATIC; later lines use this named result.
STATIC = Path(__file__).with_name("static")


# IRIS EXPLAIN: Class Review: Strict earlier-FastAPI review request schema: disposition/comment only, with extra fields
# IRIS EXPLAIN: forbidden.
class Review(BaseModel):
    # IRIS EXPLAIN: Store the result of ConfigDict(extra='forbid', str_strip_whitespace=True) in model_config; later lines use
    # IRIS EXPLAIN: this named result.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    # IRIS EXPLAIN: Declare the existing disposition field and its type; the surrounding dataclass/schema supplies construction
    # IRIS EXPLAIN: behavior.
    disposition: Literal["approve_follow_up", "reject_suggestion"]
    # IRIS EXPLAIN: Store the result of Field(min_length=5, max_length=2000) in comment; later lines use this named result.
    comment: str = Field(min_length=5, max_length=2000)


# IRIS EXPLAIN: Function require_role: Read the role already established by server authentication and reject access outside the
# IRIS EXPLAIN: endpoint's allowed roles.
# IRIS EXPLAIN: Inputs: request: the incoming HTTP request; roles: the explicit allowlisted role names for this operation.
# IRIS EXPLAIN: Declared return type: str; the return statements below show each actual result/fallback.
def require_role(request: Request, *roles: str) -> str:
    # IRIS EXPLAIN: Store the result of getattr(request.state, 'principal', None) in role; later lines use this named result.
    role = getattr(request.state, "principal", None)
    # IRIS EXPLAIN: Enter this branch only when role not in roles.
    if role not in roles:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising HTTPException(403, 'This role is not allowed to
        # IRIS EXPLAIN: perform that action'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise HTTPException(403, "This role is not allowed to perform that action")
    # IRIS EXPLAIN: Return role to the caller; this ends the current function path.
    return role


# IRIS EXPLAIN: Function create_app: Construct the earlier FastAPI app, install the security guard and static assets, and
# IRIS EXPLAIN: register authenticated API routes.
# IRIS EXPLAIN: Inputs: settings: validated local credentials, state path and processing bounds.
# IRIS EXPLAIN: Declared return type: FastAPI; the return statements below show each actual result/fallback.
def create_app(settings: Settings | None = None) -> FastAPI:
    # IRIS EXPLAIN: Store settings or Settings.load() in settings; later lines use this named result.
    settings = settings or Settings.load()

    # IRIS EXPLAIN: Turn the following yield-based function into a context manager so its existing cleanup runs on exit.
    @asynccontextmanager
    # IRIS EXPLAIN: Function lifespan: Load one shared Engine for an application lifespan and release its application reference
    # IRIS EXPLAIN: at shutdown.
    # IRIS EXPLAIN: Inputs: app: the application instance.
    async def lifespan(app):
        # IRIS EXPLAIN: Store the result of Engine(settings) in app.state.engine; later lines use this named result.
        app.state.engine = Engine(settings)  # One load per process, never per request.
        # IRIS EXPLAIN: Yield control/value to the existing context/lifespan consumer; execution resumes here for the declared
        # IRIS EXPLAIN: cleanup when the consumer finishes.
        yield
        # IRIS EXPLAIN: Store None (no result/value) in app.state.engine; later lines use this named result.
        app.state.engine = None

    # IRIS EXPLAIN: Store the result of FastAPI(title='IRIS shadow backend', version=__version__, lifespan=lifespan,
    # IRIS EXPLAIN: redoc_url=None) in app; later lines use this named result.
    app = FastAPI(title="IRIS shadow backend", version=__version__, lifespan=lifespan, redoc_url=None)
    # IRIS EXPLAIN: Call app.add_middleware(Guard, settings=settings) using the existing explicit arguments.
    app.add_middleware(Guard, settings=settings)
    # IRIS EXPLAIN: Call app.mount('/static', StaticFiles(directory=STATIC), name='static') using the existing explicit
    # IRIS EXPLAIN: arguments.
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    # IRIS EXPLAIN: Store the result of APIRouter(prefix='/api', dependencies=[Depends(APIKeyHeader(name='X-IRIS-Key'))]) in
    # IRIS EXPLAIN: router; later lines use this named result.
    router = APIRouter(prefix="/api", dependencies=[Depends(APIKeyHeader(name="X-IRIS-Key"))])

    # IRIS EXPLAIN: Register the following existing function with app.get("/", include_in_schema=False); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @app.get("/", include_in_schema=False)
    # IRIS EXPLAIN: Function home: Serve the existing static HTML page from the fixed server-owned static directory.
    def home():
        # IRIS EXPLAIN: Return the result of FileResponse(STATIC / 'index.html') to the caller; this ends the current function
        # IRIS EXPLAIN: path.
        return FileResponse(STATIC / "index.html")

    # IRIS EXPLAIN: Register the following existing function with app.get("/health"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @app.get("/health")
    # IRIS EXPLAIN: Function health: Return the existing minimal service/storage health data; this does not run new inference or
    # IRIS EXPLAIN: disclose keys.
    def health():
        # IRIS EXPLAIN: Return a mapping containing status, mode, automatic_execution to the caller; this ends the current
        # IRIS EXPLAIN: function path.
        return {"status": "alive", "mode": "shadow_only", "automatic_execution": False}

    # IRIS EXPLAIN: Register the following existing function with router.get("/me"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @router.get("/me")
    # IRIS EXPLAIN: Function me: Return the authenticated role and its allowed read views; the client cannot choose its own
    # IRIS EXPLAIN: identity.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request.
    def me(request: Request):
        # IRIS EXPLAIN: Store the result of require_role(request, 'admin', 'soc', 'grc') in role; later lines use this named
        # IRIS EXPLAIN: result.
        role = require_role(request, "admin", "soc", "grc")
        # IRIS EXPLAIN: Return a mapping containing role, views, mode to the caller; this ends the current function path.
        return {"role": role, "views": ["admin", "soc", "grc"] if role == "admin" else [role], "mode": "shadow_only"}

    # IRIS EXPLAIN: Register the following existing function with router.get("/model"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @router.get("/model")
    # IRIS EXPLAIN: Function model: Return the already loaded model adapter's traceable status; do not train on this request.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request.
    def model(request: Request):
        # IRIS EXPLAIN: Return the result of request.app.state.engine.adapter.status() to the caller; this ends the current
        # IRIS EXPLAIN: function path.
        return request.app.state.engine.adapter.status()

    # IRIS EXPLAIN: Register the following existing function with router.get("/runs"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @router.get("/runs")
    # IRIS EXPLAIN: Function runs: Return saved run metadata from the shared store; inference is not performed on this read.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request.
    def runs(request: Request):
        # IRIS EXPLAIN: Return the result of request.app.state.engine.store.runs() to the caller; this ends the current function
        # IRIS EXPLAIN: path.
        return request.app.state.engine.store.runs()

    # IRIS EXPLAIN: Function execute: Run synchronous core analysis in a worker thread and translate busy/invalid-input failures
    # IRIS EXPLAIN: to HTTP status responses.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request; paths: the exact three named operational input paths; role: the
    # IRIS EXPLAIN: authenticated role or explicitly constructed test fixture role.
    async def execute(request, paths, role):
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Return the awaited result of the result of run_in_threadpool(request.app.state.engine.run, paths,
            # IRIS EXPLAIN: role) to the caller; this ends the current function path.
            return await run_in_threadpool(request.app.state.engine.run, paths, role)
        # IRIS EXPLAIN: Catch BusyError as exc; execute the existing error/fallback path rather than silently treating it as
        # IRIS EXPLAIN: success.
        except BusyError as exc:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising HTTPException(409, str(exc)); the caller's
            # IRIS EXPLAIN: existing boundary determines rollback or the HTTP diagnostic.
            raise HTTPException(409, str(exc)) from exc
        # IRIS EXPLAIN: Catch (ValueError, UnicodeError) as exc; execute the existing error/fallback path rather than silently
        # IRIS EXPLAIN: treating it as success.
        except (ValueError, UnicodeError) as exc:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising HTTPException(422, str(exc)); the caller's
            # IRIS EXPLAIN: existing boundary determines rollback or the HTTP diagnostic.
            raise HTTPException(422, str(exc)) from exc

    # IRIS EXPLAIN: Register the following existing function with router.post("/runs/sample"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @router.post("/runs/sample")
    # IRIS EXPLAIN: Function sample: Pass the existing bundled sample through the same authorized three-input analysis path.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request.
    async def sample(request: Request):
        # IRIS EXPLAIN: Store the result of require_role(request, 'admin', 'soc') in role; later lines use this named result.
        role = require_role(request, "admin", "soc")
        # IRIS EXPLAIN: Import SAMPLES from .model_adapter to reuse the shared project contract/implementation rather than
        # IRIS EXPLAIN: duplicate it.
        from .model_adapter import SAMPLES
        # IRIS EXPLAIN: Return the awaited result of the result of execute(request, {key: SAMPLES / name for key, name in
        # IRIS EXPLAIN: INPUTS.items()}, role) (run the existing SQL with its separately supplied parameters) to the caller;
        # IRIS EXPLAIN: this ends the current function path.
        return await execute(request, {key: SAMPLES / name for key, name in INPUTS.items()}, role)

    # IRIS EXPLAIN: Register the following existing function with router.post("/runs"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @router.post("/runs")
    # IRIS EXPLAIN: Function upload: Accept exactly three named file uploads, ignore client-supplied paths, enforce per-file
    # IRIS EXPLAIN: byte limits, and pass temporary copies to the shared batch engine.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request; asset_inventory: the explicit asset inventory input used by the
    # IRIS EXPLAIN: unchanged statements below; risk_register: the explicit risk register input used by the unchanged statements
    # IRIS EXPLAIN: below; siem_alerts: the explicit siem alerts input used by the unchanged statements below.
    async def upload(request: Request, asset_inventory: UploadFile = File(...),
                     # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                     # IRIS EXPLAIN: arguments/items: risk_register: UploadFile = File(...), siem_alerts: UploadFile =
                     # IRIS EXPLAIN: File(...)):.
                     risk_register: UploadFile = File(...), siem_alerts: UploadFile = File(...)):
        # IRIS EXPLAIN: Store the result of require_role(request, 'admin', 'soc') in role; later lines use this named result.
        role = require_role(request, "admin", "soc")
        # IRIS EXPLAIN: Store the awaited result of the result of request.form() in form; later lines use this named result.
        form = await request.form()
        # IRIS EXPLAIN: Enter this branch only when len(list(form.multi_items())) != 3 or set(form) != set(INPUTS).
        if len(list(form.multi_items())) != 3 or set(form) != set(INPUTS):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising HTTPException(422, 'Exactly three files are
            # IRIS EXPLAIN: allowed; no labels or model uploads'); the caller's existing boundary determines rollback or the
            # IRIS EXPLAIN: HTTP diagnostic.
            raise HTTPException(422, "Exactly three files are allowed; no labels or model uploads")
        # IRIS EXPLAIN: Store the computed value settings.state_dir / 'incoming' in incoming; later lines use this named result.
        incoming = settings.state_dir / "incoming"
        # IRIS EXPLAIN: Call incoming.mkdir(parents=True, exist_ok=True): create the required directory if permitted by the
        # IRIS EXPLAIN: existing flags.
        incoming.mkdir(parents=True, exist_ok=True)
        # IRIS EXPLAIN: Enter tempfile.TemporaryDirectory(prefix='batch-', dir=incoming) as directory; its context manager
        # IRIS EXPLAIN: supplies the existing cleanup/transaction/expected-exception behavior.
        with tempfile.TemporaryDirectory(prefix="batch-", dir=incoming) as directory:
            # IRIS EXPLAIN: Store a mapping containing  in paths; later lines use this named result.
            paths = {}
            # IRIS EXPLAIN: Iterate {'asset_inventory': asset_inventory, 'risk_register': risk_register, 'siem_alerts':
            # IRIS EXPLAIN: siem_alerts}.items(), binding each item to (key, item); process only the existing observed/fixture
            # IRIS EXPLAIN: collection.
            for key, item in {"asset_inventory": asset_inventory, "risk_register": risk_register, "siem_alerts": siem_alerts}.items():
                # IRIS EXPLAIN: Store the computed value Path(directory) / INPUTS[key] in path; later lines use this named
                # IRIS EXPLAIN: result.
                path = Path(directory) / INPUTS[key]  # Never trust client filenames as server paths.
                # IRIS EXPLAIN: Store the computed value (20 if key == 'siem_alerts' else 5) * 1024 * 1024 in maximum; later
                # IRIS EXPLAIN: lines use this named result.
                maximum = (20 if key == "siem_alerts" else 5) * 1024 * 1024
                # IRIS EXPLAIN: Store 0 in size; later lines use this named result.
                size = 0
                # IRIS EXPLAIN: Enter path.open('xb') as stream; its context manager supplies the existing
                # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
                with path.open("xb") as stream:
                    # IRIS EXPLAIN: Repeat while (chunk := (await item.read(65536))); the block advances the read/window/history
                    # IRIS EXPLAIN: state.
                    while chunk := await item.read(65536):
                        # IRIS EXPLAIN: Update size using the existing Add operation and len(chunk).
                        size += len(chunk)
                        # IRIS EXPLAIN: Enter this branch only when size > maximum.
                        if size > maximum:
                            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising HTTPException(413, f'{key}:
                            # IRIS EXPLAIN: file-size limit exceeded'); the caller's existing boundary determines rollback or
                            # IRIS EXPLAIN: the HTTP diagnostic.
                            raise HTTPException(413, f"{key}: file-size limit exceeded")
                        # IRIS EXPLAIN: Call stream.write(chunk): write the already prepared payload.
                        stream.write(chunk)
                # IRIS EXPLAIN: Store path in paths[key]; later lines use this named result.
                paths[key] = path
            # IRIS EXPLAIN: Return the awaited result of the result of execute(request, paths, role) (run the existing SQL with
            # IRIS EXPLAIN: its separately supplied parameters) to the caller; this ends the current function path.
            return await execute(request, paths, role)

    # IRIS EXPLAIN: Function case_or_404: Translate an absent saved case into an HTTP 404 without fabricating a result.
    # IRIS EXPLAIN: Inputs: engine: the existing shared demo/model coordinator instance; case_id: the immutable saved analysis
    # IRIS EXPLAIN: case identifier.
    def case_or_404(engine, case_id):
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Return the result of engine.store.case(case_id) to the caller; this ends the current function path.
            return engine.store.case(case_id)
        # IRIS EXPLAIN: Catch KeyError as exc; execute the existing error/fallback path rather than silently treating it as
        # IRIS EXPLAIN: success.
        except KeyError as exc:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising HTTPException(404, 'Case not found'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise HTTPException(404, "Case not found") from exc

    # IRIS EXPLAIN: Function list_view: Authorize a SOC/GRC case-list read and project the paged immutable cases to that
    # IRIS EXPLAIN: audience.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request; audience: the SOC/GRC projection requested after authorization;
    # IRIS EXPLAIN: run_id: the saved batch/run identifier; limit: the bounded maximum result/preview count; offset: the
    # IRIS EXPLAIN: nonnegative page offset.
    def list_view(request, audience, run_id, limit, offset):
        # IRIS EXPLAIN: Call require_role(request, audience, 'admin') using the existing explicit arguments.
        require_role(request, audience, "admin")
        # IRIS EXPLAIN: Store the result of request.app.state.engine.store.cases(run_id, limit, offset) in result; later lines
        # IRIS EXPLAIN: use this named result.
        result = request.app.state.engine.store.cases(run_id, limit, offset)
        # IRIS EXPLAIN: Store the comprehension [view(case, audience) for case in result['items']] in result['items']; later
        # IRIS EXPLAIN: lines use this named result.
        result["items"] = [view(case, audience) for case in result["items"]]
        # IRIS EXPLAIN: Return result to the caller; this ends the current function path.
        return result

    # IRIS EXPLAIN: Register the following existing function with router.get("/soc/cases"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @router.get("/soc/cases")
    # IRIS EXPLAIN: Function soc_cases: Serve a bounded, authorized SOC case list, optionally filtered by completed run.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request; run_id: the saved batch/run identifier; limit: the bounded
    # IRIS EXPLAIN: maximum result/preview count; offset: the nonnegative page offset.
    def soc_cases(request: Request, run_id: str | None = None, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
        # IRIS EXPLAIN: Return the result of list_view(request, 'soc', run_id, limit, offset) to the caller; this ends the
        # IRIS EXPLAIN: current function path.
        return list_view(request, "soc", run_id, limit, offset)

    # IRIS EXPLAIN: Register the following existing function with router.get("/grc/cases"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @router.get("/grc/cases")
    # IRIS EXPLAIN: Function grc_cases: Serve a bounded, authorized GRC case list with registered-risk context.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request; run_id: the saved batch/run identifier; limit: the bounded
    # IRIS EXPLAIN: maximum result/preview count; offset: the nonnegative page offset.
    def grc_cases(request: Request, run_id: str | None = None, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
        # IRIS EXPLAIN: Return the result of list_view(request, 'grc', run_id, limit, offset) to the caller; this ends the
        # IRIS EXPLAIN: current function path.
        return list_view(request, "grc", run_id, limit, offset)

    # IRIS EXPLAIN: Register the following existing function with router.get("/soc/cases/{case_id}"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @router.get("/soc/cases/{case_id}")
    # IRIS EXPLAIN: Function soc_case: Authorize SOC/Admin access and return one technical case view.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request; case_id: the immutable saved analysis case identifier.
    def soc_case(request: Request, case_id: str):
        # IRIS EXPLAIN: Call require_role(request, 'soc', 'admin') using the existing explicit arguments.
        require_role(request, "soc", "admin")
        # IRIS EXPLAIN: Return the result of view(case_or_404(request.app.state.engine, case_id), 'soc') to the caller; this
        # IRIS EXPLAIN: ends the current function path.
        return view(case_or_404(request.app.state.engine, case_id), "soc")

    # IRIS EXPLAIN: Register the following existing function with router.get("/grc/cases/{case_id}"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @router.get("/grc/cases/{case_id}")
    # IRIS EXPLAIN: Function grc_case: Authorize GRC/Admin access and return one registered-risk case view.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request; case_id: the immutable saved analysis case identifier.
    def grc_case(request: Request, case_id: str):
        # IRIS EXPLAIN: Call require_role(request, 'grc', 'admin') using the existing explicit arguments.
        require_role(request, "grc", "admin")
        # IRIS EXPLAIN: Return the result of view(case_or_404(request.app.state.engine, case_id), 'grc') to the caller; this
        # IRIS EXPLAIN: ends the current function path.
        return view(case_or_404(request.app.state.engine, case_id), "grc")

    # IRIS EXPLAIN: Register the following existing function with router.post("/grc/cases/{case_id}/review"); preserve the exact
    # IRIS EXPLAIN: HTTP path/method/options.
    @router.post("/grc/cases/{case_id}/review")
    # IRIS EXPLAIN: Function review: Require the GRC key and save only an append-once local follow-up opinion; this earlier
    # IRIS EXPLAIN: endpoint does not apply working-system changes.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request; case_id: the immutable saved analysis case identifier; body: the
    # IRIS EXPLAIN: validated command/review JSON payload.
    def review(request: Request, case_id: str, body: Review):
        # IRIS EXPLAIN: Store the result of require_role(request, 'grc') in role; later lines use this named result.
        role = require_role(request, "grc")  # Admin is not a substitute risk reviewer.
        # IRIS EXPLAIN: Call case_or_404(request.app.state.engine, case_id) using the existing explicit arguments.
        case_or_404(request.app.state.engine, case_id)
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Store the result of request.app.state.engine.store.review(case_id, body.disposition, body.comment,
            # IRIS EXPLAIN: role) in saved; later lines use this named result.
            saved = request.app.state.engine.store.review(case_id, body.disposition, body.comment, role)
            # IRIS EXPLAIN: Return a mapping containing review, scope, official_risk_register_write, automatic_execution,
            # IRIS EXPLAIN: external_delivery to the caller; this ends the current function path.
            return {"review": saved, "scope": "LOCAL_FOLLOW_UP_ONLY", "official_risk_register_write": False,
                    # IRIS EXPLAIN: Set/describe these existing record fields: automatic_execution: safety flag separating
                    # IRIS EXPLAIN: recommendations from automatic control execution.
                    "automatic_execution": False, "external_delivery": False}
        # IRIS EXPLAIN: Catch ValueError as exc; execute the existing error/fallback path rather than silently treating it as
        # IRIS EXPLAIN: success.
        except ValueError as exc:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising HTTPException(409, str(exc)); the caller's
            # IRIS EXPLAIN: existing boundary determines rollback or the HTTP diagnostic.
            raise HTTPException(409, str(exc)) from exc

    # IRIS EXPLAIN: Register the following existing function with router.get("/admin/status"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @router.get("/admin/status")
    # IRIS EXPLAIN: Function admin_status: Return Admin-only storage/model status, processing lock state and documented batch
    # IRIS EXPLAIN: limits.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request.
    def admin_status(request: Request):
        # IRIS EXPLAIN: Call require_role(request, 'admin') using the existing explicit arguments.
        require_role(request, "admin")
        # IRIS EXPLAIN: Store request.app.state.engine in engine; later lines use this named result.
        engine = request.app.state.engine
        # IRIS EXPLAIN: Return a mapping containing storage, model, live_connectors, external_delivery, single_worker_only,
        # IRIS EXPLAIN: processing, batch_limits to the caller; this ends the current function path.
        return {"storage": engine.store.health(), "model": engine.adapter.status(),
                # IRIS EXPLAIN: Continue the current record with live_connectors, external_delivery, single_worker_only; each
                # IRIS EXPLAIN: value comes from the expression shown on this unchanged line.
                "live_connectors": False, "external_delivery": False, "single_worker_only": True,
                # IRIS EXPLAIN: Continue the current record with processing, batch_limits, bytes; each value comes from the
                # IRIS EXPLAIN: expression shown on this unchanged line.
                "processing": engine.lock.locked(), "batch_limits": {"bytes": settings.max_body_bytes,
                # IRIS EXPLAIN: Continue the current record with alert_rows, sessions; each value comes from the expression
                # IRIS EXPLAIN: shown on this unchanged line.
                "alert_rows": settings.max_alert_rows, "sessions": settings.max_sessions}}

    # IRIS EXPLAIN: Register the following existing function with router.get("/admin/audit"); preserve the exact HTTP
    # IRIS EXPLAIN: path/method/options.
    @router.get("/admin/audit")
    # IRIS EXPLAIN: Function audit: Require Admin and return persisted audit records from the shared store.
    # IRIS EXPLAIN: Inputs: request: the incoming HTTP request.
    def audit(request: Request):
        # IRIS EXPLAIN: Call require_role(request, 'admin') using the existing explicit arguments.
        require_role(request, "admin")
        # IRIS EXPLAIN: Return the result of request.app.state.engine.store.audit_events() to the caller; this ends the current
        # IRIS EXPLAIN: function path.
        return request.app.state.engine.store.audit_events()

    # IRIS EXPLAIN: Call app.include_router(router) using the existing explicit arguments.
    app.include_router(router)
    # IRIS EXPLAIN: Return app to the caller; this ends the current function path.
    return app
