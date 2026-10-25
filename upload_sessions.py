"""Upload session lifecycle: chunk-size detection, session creation, status, and abort.

A session tracks one large-file upload that must be split into multiple Telegram
documents ("parts"). It is durable (stored in Postgres via backend.database) because
a multi-gigabyte upload can span a long time and must survive a backend restart —
see the `FileChunk` / `UploadSession` models for how resume derives entirely from
confirmed chunk rows rather than any separate in-memory state.
"""
import logging
import math
import os
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from backend.database import (
    UploadSession, create_upload_session, get_upload_session, abort_upload_session,
    get_stale_upload_sessions,
)

logger = logging.getLogger(__name__)

# Sized for Cloudflare Tunnel's 100MB request-body limit, not Telegram's own per-document
# cap -- full rationale, options considered, and why 80MB in docs/UPLOAD_CHUNK_ARCHITECTURE.md.
FREE_CHUNK_SIZE = 80 * 1024 * 1024
PREMIUM_CHUNK_SIZE = 80 * 1024 * 1024

# Any file at or above this size gets a durable UploadSession — independent of whether it
# actually needs multiple Telegram documents. Below Telegram's own cap this just means a
# session with a single part/document (same Telegram-side footprint as before), but wrapping
# it in a session is what makes the upload survive a page refresh and retry a failed part
# instead of the whole file. Small/quick files stay on the plain single-shot endpoint, where
# a full-request retry is cheap enough not to need this machinery.
RESUMABLE_THRESHOLD = int(os.getenv("RESUMABLE_UPLOAD_THRESHOLD_MB", "10") or "10") * 1024 * 1024

# Generous window so a legitimately slow/paused upload is never killed prematurely —
# this only reaps sessions truly abandoned by the client.
SESSION_EXPIRE_SECONDS = int(os.getenv("UPLOAD_SESSION_EXPIRE_SECONDS", str(7 * 24 * 3600)))

# Telegram Premium status rarely changes mid-session; cache it per user to avoid a
# get_me() round-trip on every session creation.
_premium_cache: dict[int, bool] = {}


async def get_chunk_size(client, telegram_user_id: int) -> int:
    """Safe per-part size for this account. Falls back to the free-tier size if
    Premium status can't be determined."""
    if telegram_user_id in _premium_cache:
        is_premium = _premium_cache[telegram_user_id]
    else:
        try:
            me = await client.get_me()
            is_premium = bool(getattr(me, "premium", False))
        except Exception as e:
            logger.warning(f"Could not detect Premium status for user {telegram_user_id}, defaulting to free tier: {e}")
            is_premium = False
        _premium_cache[telegram_user_id] = is_premium
    return PREMIUM_CHUNK_SIZE if is_premium else FREE_CHUNK_SIZE


def needs_chunking(total_size: int, chunk_size: int) -> bool:
    return total_size > chunk_size


def needs_session(total_size: int) -> bool:
    """Whether this upload should go through the durable, resumable session flow at all
    (see RESUMABLE_THRESHOLD) — a separate question from needs_chunking, which is only
    about whether it takes more than one Telegram document."""
    return total_size >= RESUMABLE_THRESHOLD


def start_session(
    telegram_user_id: int, filename: str, total_size: int, mime_type: str,
    folder_id: Optional[UUID], chunk_size: int,
) -> UploadSession:
    total_chunks = math.ceil(total_size / chunk_size)
    session = create_upload_session(
        telegram_user_id, filename, total_size, mime_type, folder_id, chunk_size, total_chunks,
    )
    logger.info(
        f"Upload session {session.id} created: user={telegram_user_id} filename={filename!r} "
        f"total_size={total_size} chunk_size={chunk_size} total_chunks={total_chunks}"
    )
    return session


def get_session(session_id: UUID) -> Optional[UploadSession]:
    return get_upload_session(session_id)


def abort_session(session_id: UUID) -> list[int]:
    message_ids = abort_upload_session(session_id)
    logger.info(f"Upload session {session_id} aborted, {len(message_ids)} Telegram part(s) to clean up")
    return message_ids


async def session_sweep() -> int:
    """Expires upload sessions abandoned for SESSION_EXPIRE_SECONDS, cleaning up any
    Telegram parts they already uploaded so they don't dangle forever."""
    from backend.telegram_client import get_user_client

    cutoff = datetime.utcnow() - timedelta(seconds=SESSION_EXPIRE_SECONDS)
    stale = get_stale_upload_sessions(cutoff)
    for session in stale:
        message_ids = abort_session(session.id)
        if message_ids:
            try:
                client = await get_user_client(session.telegram_user_id, require_authorized=True)
                await client.delete_messages("me", message_ids)
            except Exception as e:
                logger.warning(f"Session sweep: failed to clean up Telegram parts for {session.id}: {e}")
    if stale:
        logger.info(f"Session sweep expired {len(stale)} abandoned upload session(s)")
    return len(stale)


def session_status_dict(session: UploadSession) -> dict:
    # "session_status" (not "status") to avoid colliding with the API envelope's
    # top-level status field ("success"/"error") used across the rest of this app.
    return {
        "session_id": str(session.id),
        "session_status": session.status,
        "next_part_number": session.next_part_number,
        "total_chunks": session.total_chunks,
        "chunk_size": session.chunk_size,
        "bytes_uploaded": session.bytes_uploaded,
        "total_size": session.total_size,
        "updated_at": session.updated_at.isoformat(),
    }
