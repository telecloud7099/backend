"""In-memory per-session progress for the server -> Telegram leg of a chunked upload.

The browser can see its own upload progress (browser -> server) from XHR events, but
once a part is on disk the multi-minute Telegram transfer used to be invisible — the
UI sat at "100%" with no signal. This registry is what GET /uploads/{id} exposes so
the frontend can poll real progress instead of staring at a silent long-lived PUT.

Deliberately NOT durable: progress is cosmetic, and the recovery invariant lives in
confirmed FileChunk rows (see chunk_upload.py). If the process restarts mid-part the
registry is empty, the part is unconfirmed, and the client simply re-sends it. This
also means the registry is only correct for a single-process deployment — the same
assumption the Telethon client pool already makes.
"""
import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional
from uuid import UUID

# Smoothing factor for the exponential moving average of upload speed. Telethon fires
# the progress callback per 512 KiB wire chunk, so instantaneous readings are noisy.
_SPEED_EMA_ALPHA = 0.2


@dataclass
class PartProgress:
    part_number: int
    phase: str  # "receiving" | "uploading_telegram" | "failed"
    bytes_done: int = 0
    bytes_total: int = 0
    speed_bps: float = 0.0
    error: Optional[str] = None
    started_at: float = field(default_factory=time.monotonic)
    _last_update: float = field(default_factory=time.monotonic)
    _last_bytes: int = 0


_progress: dict[UUID, PartProgress] = {}
# The background Telegram-upload task per session, kept both to prevent a duplicate
# upload of the same part and because asyncio only holds weak references to tasks.
_tasks: dict[UUID, asyncio.Task] = {}


def begin(session_id: UUID, part_number: int, phase: str, bytes_total: int) -> None:
    _progress[session_id] = PartProgress(part_number=part_number, phase=phase, bytes_total=bytes_total)


def update(session_id: UUID, bytes_done: int, bytes_total: int) -> None:
    p = _progress.get(session_id)
    if not p:
        return
    now = time.monotonic()
    dt = now - p._last_update
    if dt > 0:
        inst = (bytes_done - p._last_bytes) / dt
        p.speed_bps = inst if p.speed_bps == 0 else (_SPEED_EMA_ALPHA * inst + (1 - _SPEED_EMA_ALPHA) * p.speed_bps)
        p._last_update = now
        p._last_bytes = bytes_done
    p.bytes_done = bytes_done
    p.bytes_total = bytes_total


def mark_failed(session_id: UUID, part_number: int, error: str) -> None:
    _progress[session_id] = PartProgress(part_number=part_number, phase="failed", error=error)


def clear(session_id: UUID) -> None:
    _progress.pop(session_id, None)


def in_flight_part(session_id: UUID) -> Optional[int]:
    """Part number currently being pushed to Telegram by a live background task, or None."""
    task = _tasks.get(session_id)
    if task and not task.done():
        p = _progress.get(session_id)
        return p.part_number if p else None
    return None


def set_task(session_id: UUID, task: asyncio.Task) -> None:
    _tasks[session_id] = task


def clear_task(session_id: UUID) -> None:
    _tasks.pop(session_id, None)


def progress_dict(session_id: UUID) -> Optional[dict]:
    """Wire shape merged into the session status response, or None when idle."""
    p = _progress.get(session_id)
    if not p:
        return None
    eta = None
    if p.phase == "uploading_telegram" and p.speed_bps > 0 and p.bytes_total > p.bytes_done:
        eta = round((p.bytes_total - p.bytes_done) / p.speed_bps)
    return {
        "part_number": p.part_number,
        "phase": p.phase,
        "bytes_done": p.bytes_done,
        "bytes_total": p.bytes_total,
        "speed_bps": round(p.speed_bps),
        "eta_seconds": eta,
        "error": p.error,
    }
