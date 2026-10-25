import asyncio
import logging
import logging.handlers
import os
import time as _time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

from backend.database import init_db
from backend.cache import cache_sweep
from backend.metrics import record_response
from backend.security import rate_limit_sweep
from backend.chunk_upload import chunk_upload_sweep
from backend.telegram_client import SessionRevokedError
from backend.upload_sessions import session_sweep
from backend.routes import auth as auth_router
from backend.routes import files as files_router
from backend.routes import folders as folders_router
from backend.routes import admin as admin_router
from backend.routes import upload as upload_router

load_dotenv()

_log_handlers: list[logging.Handler] = [logging.StreamHandler()]
if os.getenv("LOG_TO_FILE"):
    _log_handlers.append(
        logging.handlers.RotatingFileHandler(
            "app.log", maxBytes=5 * 1024 * 1024, backupCount=3
        )
    )
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=_log_handlers,
)
logger = logging.getLogger(__name__)

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "static")
_APP_DIR = os.path.join(_STATIC_DIR, "app")
_SPA_INDEX = os.path.join(_APP_DIR, "index.html")

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:5001")
origins = [o.strip() for o in ALLOWED_ORIGINS.split(",") if o.strip()]


async def _maintenance_loop():
    while True:
        await asyncio.sleep(900)
        try:
            cache_sweep()
            rate_limit_sweep()
            chunk_upload_sweep()
            await session_sweep()
        except Exception as e:
            logger.error(f"Maintenance loop error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting TeleCloud")
    init_db()
    for d in ("uploads", "thumbs"):
        os.makedirs(d, exist_ok=True)
    task = asyncio.create_task(_maintenance_loop())
    yield
    task.cancel()
    logger.info("TeleCloud shutting down")


app = FastAPI(lifespan=lifespan, title="TeleCloud")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Range", "Accept-Ranges", "Content-Length"],
)


@app.middleware("http")
async def timing_middleware(request: Request, call_next):
    start = _time.perf_counter()
    try:
        response = await call_next(request)
        elapsed_ms = (_time.perf_counter() - start) * 1000
        # Skip streaming responses (file downloads) — they skew averages to minutes
        content_type = response.headers.get("content-type", "")
        is_stream = isinstance(response, Response) and response.headers.get("transfer-encoding") == "chunked"
        if not is_stream and "application/json" in content_type or content_type == "":
            record_response(elapsed_ms, is_error=response.status_code >= 500)
        return response
    except Exception as e:
        elapsed_ms = (_time.perf_counter() - start) * 1000
        record_response(elapsed_ms, is_error=True)
        logger.error(f"Unhandled error in {request.method} {request.url.path}: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": "Internal server error"})


@app.exception_handler(SessionRevokedError)
async def session_revoked_handler(request: Request, exc: SessionRevokedError):
    # 401 (not 500) so the frontend's apiFetch clears the JWT and redirects to login —
    # a revoked Telegram auth key can never recover on its own.
    return JSONResponse(status_code=401, content={"status": "error", "message": str(exc)})


@app.get("/health")
async def health():
    return {"status": "ok"}


app.include_router(auth_router.router)
app.include_router(files_router.router)
app.include_router(folders_router.router)
app.include_router(admin_router.router)
app.include_router(upload_router.router)

if os.path.isdir(_APP_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(_APP_DIR, "assets")), name="assets")

if os.path.isdir(_STATIC_DIR):
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    if full_path.startswith(("static/", "assets/")):
        return JSONResponse(status_code=404, content={"message": "Not found"})
    if os.path.isfile(_SPA_INDEX):
        return FileResponse(_SPA_INDEX)
    return JSONResponse(
        status_code=503,
        content={"message": "React app not built. Run: cd frontend && npm run build"},
    )
