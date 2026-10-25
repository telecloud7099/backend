import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from backend.auth import get_current_user
from backend.database import (
    add_folder, get_confirmed_chunks, finalize_chunked_file, UploadSession,
    get_active_upload_sessions,
)
from backend.telegram_client import get_user_client, SessionRevokedError
from backend.security import rate_limit_check, sanitize_input, log_security_event
from backend.cache import cache_invalidate
from backend.hashing import content_signature
from backend.routes.files import _categorize
import backend.upload_sessions as upload_sessions
import backend.chunk_upload as chunk_upload
import backend.upload_progress as upload_progress

router = APIRouter()
logger = logging.getLogger(__name__)


def _not_found() -> JSONResponse:
    return JSONResponse(status_code=404, content={"status": "error", "message": "Upload session not found"})


def _get_owned_session(session_id: str, telegram_user_id: int) -> Optional[UploadSession]:
    """Looks up a session and returns it only if it belongs to the requesting user —
    an invalid UUID or a session owned by someone else are indistinguishable from
    "not found" to the caller."""
    try:
        session = upload_sessions.get_session(uuid.UUID(session_id))
    except ValueError:
        return None
    if not session or session.telegram_user_id != telegram_user_id:
        return None
    return session


class CreateUploadSessionBody(BaseModel):
    filename: str
    total_size: int
    mime_type: str = "application/octet-stream"
    folder_name: str = ""


@router.post("/uploads")
async def create_upload_session_route(
    request: Request,
    body: CreateUploadSessionBody,
    telegram_user_id: int = Depends(get_current_user),
):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    if body.total_size <= 0:
        return JSONResponse(status_code=400, content={"status": "error", "message": "total_size must be positive"})

    try:
        client = await get_user_client(telegram_user_id, require_authorized=True)
    except SessionRevokedError:
        raise
    except Exception as e:
        logger.error(f"Upload session client error: {e}")
        return JSONResponse(status_code=502, content={"status": "error", "message": "Could not connect to Telegram"})

    chunk_size = await upload_sessions.get_chunk_size(client, telegram_user_id)

    if not upload_sessions.needs_session(body.total_size):
        # Small/quick enough that a durable session isn't worth it — caller should use the
        # existing single-shot /upload endpoint instead. No session is created.
        return {"status": "success", "chunked": False, "chunk_size": chunk_size}

    folder_name = sanitize_input(body.folder_name)
    folder_id = None
    if folder_name:
        folder_id = add_folder(telegram_user_id, folder_name).id

    session = upload_sessions.start_session(
        telegram_user_id, body.filename, body.total_size, body.mime_type, folder_id, chunk_size,
    )
    log_security_event(request, "UPLOAD_SESSION_CREATED",
                        f"session={session.id} filename={body.filename!r} size={body.total_size}",
                        str(telegram_user_id))

    return {
        "status": "success",
        "chunked": True,
        **upload_sessions.session_status_dict(session),
    }


@router.get("/uploads")
async def list_upload_sessions_route(
    telegram_user_id: int = Depends(get_current_user),
):
    """Active (still-uploading) sessions for this user — used to reattach the upload
    widget to an in-progress chunked upload after a page refresh."""
    return {"status": "success", "sessions": get_active_upload_sessions(telegram_user_id)}


@router.get("/uploads/{session_id}")
async def get_upload_session_route(
    session_id: str,
    telegram_user_id: int = Depends(get_current_user),
):
    session = _get_owned_session(session_id, telegram_user_id)
    if not session:
        return _not_found()

    return {
        "status": "success",
        **upload_sessions.session_status_dict(session),
        # Live server->Telegram progress for the part in flight (None when idle) — this
        # is what lets the frontend poll instead of holding a multi-minute PUT open.
        "part_progress": upload_progress.progress_dict(session.id),
    }


@router.put("/uploads/{session_id}/parts/{part_number}")
async def upload_part_route(
    request: Request,
    session_id: str,
    part_number: int,
    telegram_user_id: int = Depends(get_current_user),
):
    session = _get_owned_session(session_id, telegram_user_id)
    if not session:
        return _not_found()
    if session.status != "uploading":
        return JSONResponse(status_code=409, content={
            "status": "error", "message": f"Session is {session.status}, not accepting parts",
        })

    try:
        client = await get_user_client(telegram_user_id, require_authorized=True)
    except SessionRevokedError:
        raise
    except Exception as e:
        logger.error(f"Part upload client error: {e}")
        return JSONResponse(status_code=502, content={"status": "error", "message": "Could not connect to Telegram"})

    try:
        result = await chunk_upload.receive_part(client, session, part_number, request)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"status": "error", "message": str(e)})
    except Exception as e:
        logger.error(f"Part upload error (session={session_id} part={part_number}): {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"status": "error", "message": "Part upload failed"})

    return {"status": "success", **result}


@router.post("/uploads/{session_id}/complete")
async def complete_upload_session_route(
    request: Request,
    session_id: str,
    telegram_user_id: int = Depends(get_current_user),
):
    session = _get_owned_session(session_id, telegram_user_id)
    if not session:
        return _not_found()

    if session.status == "completed" and session.file_id:
        # Idempotent: caller retried after a successful completion whose response was lost.
        return {"status": "success", "file_id": str(session.file_id), "filename": session.filename}

    chunks = get_confirmed_chunks(session.id)
    if len(chunks) != session.total_chunks:
        return JSONResponse(status_code=409, content={
            "status": "error",
            "message": f"{len(chunks)}/{session.total_chunks} parts uploaded — cannot complete yet",
        })

    signature = content_signature([c.sha256 for c in chunks])
    category = _categorize(session.filename, session.mime_type)

    file_row = finalize_chunked_file(
        session.id, session.filename, session.total_size, session.mime_type,
        category, session.folder_id, session.total_chunks, signature,
    )

    cache_invalidate(str(telegram_user_id))
    log_security_event(request, "UPLOAD_SESSION_COMPLETED",
                        f"session={session.id} file={file_row.id} filename={session.filename!r}",
                        str(telegram_user_id))

    logger.info(f"Session {session.id} completed as file {file_row.id} ({session.total_chunks} parts, signature={signature[:12]})")
    return {"status": "success", "file_id": str(file_row.id), "filename": file_row.filename}


@router.delete("/uploads/{session_id}")
async def abort_upload_session_route(
    request: Request,
    session_id: str,
    telegram_user_id: int = Depends(get_current_user),
):
    session = _get_owned_session(session_id, telegram_user_id)
    if not session:
        return _not_found()

    message_ids = upload_sessions.abort_session(session.id)

    if message_ids:
        try:
            client = await get_user_client(telegram_user_id, require_authorized=True)
            await client.delete_messages("me", message_ids)
        except Exception as e:
            logger.error(f"Failed to clean up Telegram parts for aborted session {session.id}: {e}")

    log_security_event(request, "UPLOAD_SESSION_ABORTED", f"session={session.id}", str(telegram_user_id))
    return {"status": "success", "aborted": True}
