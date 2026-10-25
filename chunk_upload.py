"""Streaming receive of a single upload-session part: request body -> bounded temp file,
then a background task pushes it to Telegram and records the FileChunk. The PUT returns
as soon as the part is safely on disk ("accepted"), so the browser never holds a request
open for the multi-minute Telegram transfer — it polls GET /uploads/{id} for that leg's
progress instead (see upload_progress.py).

Recovery invariant: the only durable truth is a confirmed FileChunk row. A temp file and
the in-memory progress registry are both disposable — if the process dies mid-part, the
part is simply unconfirmed and the client re-sends it from byte 0 (a retried PUT opens
the temp file in truncate mode). There is no separate crash-recovery state machine.

Chunk-grouping metadata for scan-based recovery (see routes/files.py's _full_scan) is
carried in the message CAPTION, not the filename — the on-Telegram filename for a chunk
part stays the internal `{session_id}_{part_number}.tmp` disk name and is never meant to
be user-facing (see filename_mangling_test.py, run 2026-07-23 against Telethon 1.32.1 /
MTProto layer 166: 5 filenames including double-extension patterns like `video.part1.mp4`
and `report.v2.final.pdf` all survived send_file() -> get_messages() unchanged, so there's
no current evidence of Telegram rewriting document filenames). An earlier version of this
docstring claimed such rewriting was "verified empirically" without recording what was
actually tested — treat that as an unverified historical observation, not a current fact.
Captions are used regardless, because they're the only channel that reliably survives a
Postgres wipe and lets _full_scan re-derive grouping/order/original-filename from Telegram
alone — a property the document filename would share only if a future change also started
threading the real filename through DocumentAttributeFilename for chunk parts, which is a
deliberate choice not to do (see routes/files.py's single-shot-only use of it).
"""
import asyncio
import logging
import os
import time as _time
from typing import Optional
from uuid import UUID

from fastapi import Request

from backend.database import get_confirmed_chunk, record_file_chunk, UploadSession
from backend.hashing import StreamingHasher
import backend.upload_progress as upload_progress

logger = logging.getLogger(__name__)

PARTS_DIR = os.path.join("uploads", "_parts")
os.makedirs(PARTS_DIR, exist_ok=True)

STALE_TEMP_SECONDS = 3600  # part temp files older than this are assumed orphaned by a crash

CAPTION_PREFIX = "__tc_chunk__"


def build_chunk_caption(group_id: UUID, part_number: int, total_chunks: int, original_filename: str) -> str:
    return f"{CAPTION_PREFIX}:{group_id}:{part_number}:{total_chunks}:{original_filename}"


def parse_chunk_caption(caption: Optional[str]) -> Optional[dict]:
    """Returns the parsed grouping key/part info, or None if this isn't a chunk-part caption."""
    if not caption or not caption.startswith(CAPTION_PREFIX + ":"):
        return None
    try:
        _, group_id, part_number, total_chunks, original_filename = caption.split(":", 4)
        return {
            "group_id": group_id,
            "part_number": int(part_number),
            "total_chunks": int(total_chunks),
            "original_filename": original_filename,
        }
    except ValueError:
        return None


def _expected_part_size(session: UploadSession, part_number: int) -> int:
    if part_number < session.total_chunks:
        return session.chunk_size
    return session.total_size - session.chunk_size * (session.total_chunks - 1)


def _temp_path(session_id: UUID, part_number: int) -> str:
    return os.path.join(PARTS_DIR, f"{session_id}_{part_number}.tmp")


async def receive_part(client, session: UploadSession, part_number: int, request: Request) -> dict:
    """Streams one part's body to disk, verifies its size, and hands it to a background
    task that uploads it to Telegram. Returns as soon as the part is on disk — the caller
    watches the session status endpoint for Telegram progress and confirmation.

    Idempotent: if this part number was already confirmed for this session, or is the part
    currently in flight to Telegram, the client's retry is treated as a no-op rather than a
    duplicate upload. On those no-op paths the incoming body is still read to completion —
    responding while the browser is mid-body-send makes it report a connection error
    instead of delivering our JSON (observed with Chrome + XHR).
    """
    existing = get_confirmed_chunk(session.id, part_number)
    if existing:
        logger.info(f"Session {session.id} part {part_number} already confirmed — skipping re-upload")
        await _drain_body(request)
        return {
            "part_number": part_number, "accepted": True, "confirmed": True, "duplicate": True,
            "telegram_message_id": existing.telegram_message_id, "sha256": existing.sha256,
        }

    if part_number < 1 or part_number > session.total_chunks:
        raise ValueError(f"part_number {part_number} out of range (1..{session.total_chunks})")

    in_flight = upload_progress.in_flight_part(session.id)
    if in_flight == part_number:
        logger.info(f"Session {session.id} part {part_number} retried while already uploading to Telegram — no-op")
        await _drain_body(request)
        return {"part_number": part_number, "accepted": True, "confirmed": False, "duplicate": True}
    if in_flight is not None:
        raise ValueError(f"part {in_flight} is still uploading to Telegram — wait for it before sending part {part_number}")

    expected_size = _expected_part_size(session, part_number)
    temp_path = _temp_path(session.id, part_number)

    upload_progress.begin(session.id, part_number, "receiving", expected_size)
    hasher = StreamingHasher()
    bytes_written = 0
    try:
        with open(temp_path, "wb") as f:
            async for data in request.stream():
                f.write(data)
                hasher.update(data)
                bytes_written += len(data)
                upload_progress.update(session.id, bytes_written, expected_size)
            # Force the write to be physically committed before Telethon re-opens this
            # path — on Windows, a just-closed multi-GB file can still be mid-flush or
            # briefly locked by real-time antivirus scanning, which showed up as Telethon
            # reading a short chunk and raising "read less than N before reaching the end".
            f.flush()
            os.fsync(f.fileno())

        if bytes_written != expected_size:
            raise ValueError(f"part {part_number} size mismatch: received {bytes_written} bytes, expected {expected_size}")
    except Exception:
        upload_progress.clear(session.id)
        await _remove_with_retry(temp_path)
        raise

    logger.info(
        f"Session {session.id} part {part_number}/{session.total_chunks} received "
        f"({bytes_written} bytes) — starting background Telegram upload"
    )
    upload_progress.begin(session.id, part_number, "uploading_telegram", bytes_written)
    task = asyncio.create_task(
        _upload_part_to_telegram(client, session, part_number, temp_path, bytes_written, hasher.hexdigest())
    )
    upload_progress.set_task(session.id, task)

    return {"part_number": part_number, "accepted": True, "confirmed": False, "duplicate": False}


async def _upload_part_to_telegram(
    client, session: UploadSession, part_number: int, temp_path: str, size: int, sha256: str,
) -> None:
    """Background leg of receive_part: temp file -> Telegram document -> FileChunk row.
    Success clears the progress entry (confirmation is visible via next_part_number);
    failure parks a 'failed' entry so the polling client knows to re-send the part."""
    try:
        caption = build_chunk_caption(session.id, part_number, session.total_chunks, session.filename)
        # Pass file_size explicitly rather than letting Telethon re-derive it via
        # os.path.getsize() — we already know the true size from the streaming write, and
        # trusting a second, later filesystem query is exactly what caused the AV-scan race.
        message = await client.send_file(
            "me", temp_path, force_document=True, caption=caption, file_size=size,
            progress_callback=lambda sent, total: upload_progress.update(session.id, sent, total),
        )
        record_file_chunk(session.id, part_number, message.id, size, sha256)
        logger.info(f"Session {session.id} part {part_number} confirmed as Telegram message {message.id}")
        upload_progress.clear(session.id)
    except Exception as e:
        logger.error(f"Telegram upload failed (session={session.id} part={part_number}): {e}", exc_info=True)
        upload_progress.mark_failed(session.id, part_number, "Telegram upload failed — please retry this part")
    finally:
        upload_progress.clear_task(session.id)
        await _remove_with_retry(temp_path)


async def _drain_body(request: Request) -> None:
    """Reads and discards the rest of the request body. Used on no-op PUT paths: an early
    response while the client is still streaming gigabytes of body gets surfaced by the
    browser as a network error, so the body must be consumed before we answer."""
    async for _ in request.stream():
        pass


async def _remove_with_retry(path: str, attempts: int = 5, delay: float = 0.5) -> None:
    """Windows can briefly hold a lock on a just-closed multi-GB file (antivirus scanning
    is the usual cause) — retry the delete a few times rather than let a transient lock
    surface as an unrelated error. Uses asyncio.sleep so this never blocks the event loop."""
    for i in range(attempts):
        if not os.path.exists(path):
            return
        try:
            os.remove(path)
            return
        except OSError as e:
            if i == attempts - 1:
                logger.warning(f"Failed to remove temp part file {path} after {attempts} attempts: {e}")
            else:
                await asyncio.sleep(delay)


def chunk_upload_sweep() -> int:
    """Deletes any part temp file untouched for STALE_TEMP_SECONDS — catches anything left
    behind by a hard crash mid-write. Safe regardless of whether an upload is still active:
    a legitimately in-progress part simply gets overwritten from byte 0 on its next PUT."""
    if not os.path.isdir(PARTS_DIR):
        return 0
    cutoff = _time.time() - STALE_TEMP_SECONDS
    removed = 0
    for name in os.listdir(PARTS_DIR):
        path = os.path.join(PARTS_DIR, name)
        try:
            if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed += 1
        except OSError as e:
            logger.warning(f"Chunk upload sweep: failed to remove {path}: {e}")
    if removed:
        logger.info(f"Chunk upload sweep removed {removed} stale temp part file(s)")
    return removed
