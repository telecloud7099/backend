import time
import logging
from sqlalchemy import text
from sqlmodel import Session

from fastapi import APIRouter, Depends

from backend.auth import get_current_user
from backend.database import engine
from backend.cache import get_cache_stats
from backend.telegram_client import get_active_sessions
from backend.metrics import get_uptime, get_request_stats

router = APIRouter()
logger = logging.getLogger(__name__)


def _get_memory_mb() -> float | None:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024, 1)
    except Exception:
        pass
    return None


def _check_db() -> dict:
    start = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            latency_ms = round((time.perf_counter() - start) * 1000, 1)
            total_files = conn.execute(text("SELECT COUNT(*) FROM files")).scalar() or 0
            total_folders = conn.execute(text("SELECT COUNT(*) FROM folders")).scalar() or 0
        return {
            "status": "ok",
            "latency_ms": latency_ms,
            "total_files": int(total_files),
            "total_folders": int(total_folders),
        }
    except Exception as e:
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        logger.error(f"Admin health DB check failed: {e}")
        return {"status": "error", "latency_ms": latency_ms, "error": str(e)}


def _uptime_human(seconds: float) -> str:
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m {s}s"


@router.get("/admin/health")
async def admin_health(telegram_user_id: int = Depends(get_current_user)):
    uptime = get_uptime()
    return {
        "status": "ok",
        "uptime_seconds": round(uptime),
        "uptime_human": _uptime_human(uptime),
        "db": _check_db(),
        "telegram": get_active_sessions(),
        "cache": get_cache_stats(),
        "memory_mb": _get_memory_mb(),
        "requests": get_request_stats(),
    }
