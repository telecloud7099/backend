
import asyncio
import logging
import logging.handlers
import os
import time as _time
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Modules located at the repository root
from database import init_db
from cache import cache_sweep
from metrics import record_response
from security import rate_limit_sweep
from chunk_upload import chunk_upload_sweep
from telegram_client import SessionRevokedError
from upload_sessions import session_sweep

# API routers
from routes import auth as auth_router
from routes import files as files_router
from routes import folders as folders_router
from routes import admin as admin_router
from routes import upload as upload_router

load_dotenv()

# Logging
_log_handlers: list[logging.Handler] = [logging.StreamHandler()]

if os.getenv("LOG_TO_FILE"):
    _log_handlers.append(
        logging.handlers.RotatingFileHandler(
            "app.log",
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
        )
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=_log_handlers,
)

logger = logging.getLogger(__name__)

# Static files and optional frontend build
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_STATIC_DIR = os.path.join(_BASE_DIR, "static")
_APP_DIR = os.path.join(_STATIC_DIR, "app")
_SPA_INDEX = os.path.join(_APP_DIR, "index.html")

# CORS
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://localhost:5001",
)
origins = [
    origin.strip()
    for origin in ALLOWED_ORIGINS.split(",")
    if origin.strip()
]


async def _maintenance_loop():
    while True:
        await asyncio.sleep(900)

        try:
            cache_sweep()
            rate_limit_sweep()
            chunk_upload_sweep()
            await session_sweep()
        except Exception:
            logger.exception("Maintenance loop error")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting TeleCloud")

    # Database initialization can fail if the database is unavailable.
    init_db()

    # Local directories are temporary on serverless hosting.
    for directory in ("uploads", "thumbs"):
        os.makedirs(directory, exist_ok=True)

    # A persistent maintenance loop is not reliable on Vercel.
    # Start it only when explicitly enabled.
    maintenance_task = None

    if os.getenv("ENABLE_MAINTENANCE_LOOP", "false").lower() == "true":
        maintenance_task = asyncio.create_task(_maintenance_loop())

    try:
        yield
    finally:
        if maintenance_task is not None:
            maintenance_task.cancel()
            try:
                await maintenance_task
            except asyncio.CancelledError:
                pass

        logger.info("TeleCloud shutting down")


app = FastAPI(
    title="TeleCloud",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "Content-Range",
        "Accept-Ranges",
        "Content-Length",
    ],
)


@app.middleware("http")
async def timing_middleware(request: Request, call_next):
    start = _time.perf_counter()

    try:
        response = await call_next(request)
        elapsed_ms = (_time.perf_counter() - start) * 1000

        content_type = response.headers.get("content-type", "")
        is_stream = (
            response.headers.get("transfer-encoding", "").lower()
            == "chunked"
        )

        if (
            not is_stream
            and (
                "application/json" in content_type
                or not content_type
            )
        ):
            record_response(
                elapsed_ms,
                is_error=response.status_code >= 500,
            )

        return response

    except Exception:
        elapsed_ms = (_time.perf_counter() - start) * 1000

        record_response(elapsed_ms, is_error=True)

        logger.exception(
            "Unhandled error in %s %s",
            request.method,
            request.url.path,
        )

        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error",
            },
        )


@app.exception_handler(SessionRevokedError)
async def session_revoked_handler(
    request: Request,
    exc: SessionRevokedError,
):
    return JSONResponse(
        status_code=401,
        content={
            "status": "error",
            "message": str(exc),
        },
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


# API routes
app.include_router(auth_router.router)
app.include_router(files_router.router)
app.include_router(folders_router.router)
app.include_router(admin_router.router)
app.include_router(upload_router.router)


# Optional static frontend
_assets_dir = os.path.join(_APP_DIR, "assets")

if os.path.isdir(_assets_dir):
    app.mount(
        "/assets",
        StaticFiles(directory=_assets_dir),
        name="assets",
    )

if os.path.isdir(_STATIC_DIR):
    app.mount(
        "/static",
        StaticFiles(directory=_STATIC_DIR),
        name="static",
    )


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    if full_path.startswith(("static/", "assets/")):
        return JSONResponse(
            status_code=404,
            content={"status": "error", "message": "Not found"},
        )

    if os.path.isfile(_SPA_INDEX):
        return FileResponse(_SPA_INDEX)

    return JSONResponse(
        status_code=404,
        content={
            "status": "error",
            "message": "Not found",
        },
    )
