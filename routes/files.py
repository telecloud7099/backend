import os
import uuid
import asyncio
import logging
import time as _time
from datetime import datetime
from typing import AsyncIterator, Optional
from urllib.parse import quote
from fastapi import APIRouter, Request, Depends, UploadFile, File, Form, Query
from fastapi.responses import JSONResponse, StreamingResponse, Response
from pydantic import BaseModel
from telethon.tl.types import DocumentAttributeFilename

from backend.auth import get_current_user, get_media_user
from backend.database import (
    db_get_files, db_upsert_files, db_insert_file, db_delete_files_by_ids,
    db_move_files, get_sync_state, update_sync_state,
    add_folder, get_folder_by_name, folder_exists, get_file_by_id, get_file_chunks_ordered,
    get_user_session_ids, recover_chunked_file,
)
from backend.telegram_client import get_user_client, remove_client, is_client_connected, SessionRevokedError
from backend.cache import cache_get, cache_set, cache_invalidate
from backend.security import rate_limit_check, validate_file_upload, sanitize_input, log_security_event
from backend.chunk_upload import parse_chunk_caption
import backend.chunk_download as chunk_download

router = APIRouter()
logger = logging.getLogger(__name__)

UPLOAD_FOLDER = "uploads"
THUMB_FOLDER = "thumbs"
PAGE_SIZE = 50


def _content_disposition(disposition: str, filename: str) -> str:
    """HTTP headers are latin-1 only, so any filename beyond that (en-dash, emoji,
    non-Latin scripts) must ride in the RFC 5987 filename* parameter; the plain
    filename= stays as an ASCII fallback for old clients."""
    fallback = (
        filename.encode("ascii", "replace").decode()
        .replace('"', '_').replace('\r', '').replace('\n', '')
    )
    return f"{disposition}; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"
MAX_SCAN_MESSAGES = int(os.getenv("MAX_SCAN_MESSAGES", "2000") or "2000")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "500") or "500")
_MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

# Tracks users currently undergoing a background full scan
_syncing_users: set[int] = set()

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(THUMB_FOLDER, exist_ok=True)


def _make_name(raw_name: str | None, mime: str, msg_id: int, date=None) -> str:
    if raw_name:
        return raw_name
    # Generate a readable name from MIME type and date/ID
    ts = ""
    if date:
        try:
            ts = "_" + date.strftime("%Y%m%d_%H%M%S")
        except Exception:
            ts = f"_{msg_id}"
    else:
        ts = f"_{msg_id}"
    if mime.startswith("image/"):
        ext = mime.split("/")[-1].split(";")[0] or "jpg"
        return f"photo{ts}.{ext}"
    if mime.startswith("video/"):
        ext = mime.split("/")[-1].split(";")[0] or "mp4"
        return f"video{ts}.{ext}"
    if mime.startswith("audio/"):
        ext = mime.split("/")[-1].split(";")[0] or "mp3"
        return f"audio{ts}.{ext}"
    return f"file{ts}"


def _categorize(name: str, mime: str) -> str:
    name = (name or "").lower()
    mime = (mime or "").lower()
    if name.endswith(".apk") or mime == "application/vnd.android.package-archive":
        return "APK"
    if mime.startswith("image/"):
        return "Images"
    if mime.startswith("video/"):
        return "Videos"
    if mime.startswith("audio/"):
        return "Audio"
    if any(name.endswith(e) for e in (".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx")) or "pdf" in mime:
        return "Docs"
    if any(name.endswith(e) for e in (".zip", ".rar", ".7z", ".tar", ".gz", ".tgz")):
        return "Archives"
    return "Other"


# ── Sync helpers ──────────────────────────────────────────────────────────────

def _reconcile_chunk_groups(telegram_user_id: int, chunk_groups: dict[str, list]) -> int:
    """Disaster recovery only: reconstructs chunked files whose grouping isn't in Postgres
    (fresh device, DB wipe) from the captions collected during a scan. `chunk_groups` maps
    group_id -> [(parsed_caption, msg), ...] for every chunk-part message seen that wasn't
    already known (see get_user_session_ids). A group missing any of its parts within the
    scanned window is left alone rather than reconstructed partially — it's picked up
    whenever a scan happens to observe all of its parts together."""
    recovered = 0
    for group_id, entries in chunk_groups.items():
        entries.sort(key=lambda e: e[0]["part_number"])
        total_chunks = entries[0][0]["total_chunks"]
        if len(entries) != total_chunks:
            logger.warning(
                f"Incomplete chunk group {group_id} for user {telegram_user_id}: "
                f"{len(entries)}/{total_chunks} parts seen in this scan — skipping"
            )
            continue

        original_filename = entries[0][0]["original_filename"]
        parts = [(p["part_number"], msg.id, msg.file.size or 0) for p, msg in entries]
        total_size = sum(size for _, _, size in parts)
        mime = entries[0][1].file.mime_type or "application/octet-stream"
        category = _categorize(original_filename, mime)

        recover_chunked_file(telegram_user_id, original_filename, total_size, mime, category, parts)
        recovered += 1
        logger.info(
            f"Recovered chunked file {original_filename!r} from scan "
            f"({total_chunks} parts, group {group_id}) for user {telegram_user_id}"
        )
    return recovered


async def _full_scan(telegram_user_id: int) -> list[dict]:
    client = await get_user_client(telegram_user_id, require_authorized=True)
    max_scan = None if MAX_SCAN_MESSAGES == 0 else MAX_SCAN_MESSAGES
    known_session_ids = {str(sid) for sid in get_user_session_ids(telegram_user_id)}
    files = []
    chunk_groups: dict[str, list] = {}
    seen: set[int] = set()
    newest_id = 0
    async for msg in client.iter_messages("me", limit=max_scan):
        if not msg or not msg.file or msg.id in seen:
            continue
        seen.add(msg.id)
        if msg.id > newest_id:
            newest_id = msg.id

        parsed = parse_chunk_caption(msg.text)
        if parsed:
            if parsed["group_id"] not in known_session_ids:
                chunk_groups.setdefault(parsed["group_id"], []).append((parsed, msg))
            continue

        mime = msg.file.mime_type or "application/octet-stream"
        name = _make_name(msg.file.name, mime, msg.id, msg.date)
        files.append({
            "id": msg.id, "name": name,
            "size": msg.file.size or 0, "mime_type": mime,
            "date": msg.date.isoformat() if msg.date else None,
            "category": _categorize(name, mime),
            "caption": (msg.text or "").strip(),
        })
    files.sort(key=lambda x: x.get("date") or "", reverse=True)
    db_upsert_files(telegram_user_id, files)
    _reconcile_chunk_groups(telegram_user_id, chunk_groups)
    update_sync_state(telegram_user_id, last_sync_at=_time.time(), newest_msg_id=newest_id)
    return db_get_files(telegram_user_id)


async def _incremental_sync(telegram_user_id: int, force: bool = False) -> int:
    state = get_sync_state(telegram_user_id)
    if not force and _time.time() - state["last_sync_at"] < 600:
        return 0
    try:
        client = await get_user_client(telegram_user_id, require_authorized=True)
        known_session_ids = {str(sid) for sid in get_user_session_ids(telegram_user_id)}
        min_id = state["newest_msg_id"]
        new_files = []
        chunk_groups: dict[str, list] = {}
        newest_id = min_id
        async for msg in client.iter_messages("me", min_id=min_id, limit=200):
            if not msg or not msg.file:
                continue
            if msg.id > newest_id:
                newest_id = msg.id

            parsed = parse_chunk_caption(msg.text)
            if parsed:
                if parsed["group_id"] not in known_session_ids:
                    chunk_groups.setdefault(parsed["group_id"], []).append((parsed, msg))
                continue

            mime = msg.file.mime_type or "application/octet-stream"
            name = _make_name(msg.file.name, mime, msg.id, msg.date)
            new_files.append({
                "id": msg.id, "name": name,
                "size": msg.file.size or 0, "mime_type": mime,
                "date": msg.date.isoformat() if msg.date else None,
                "category": _categorize(name, mime),
                "caption": (msg.text or "").strip(),
            })
        recovered = _reconcile_chunk_groups(telegram_user_id, chunk_groups)
        if new_files or recovered:
            db_upsert_files(telegram_user_id, new_files)
            all_files = db_get_files(telegram_user_id)
            cache_set(f"{telegram_user_id}:all_files", all_files)
        update_sync_state(telegram_user_id, last_sync_at=_time.time(), newest_msg_id=newest_id)
        return len(new_files) + recovered
    except SessionRevokedError:
        raise
    except Exception as e:
        logger.error(f"Incremental sync error for user {telegram_user_id}: {e}", exc_info=True)
        return 0


async def _warm_client(telegram_user_id: int):
    """Connect Telegram client in background so thumbnails load immediately."""
    if is_client_connected(telegram_user_id):
        return
    try:
        await get_user_client(telegram_user_id, require_authorized=True)
        logger.info(f"Telegram client warmed for user {telegram_user_id}")
    except Exception as e:
        logger.debug(f"Telegram client warm-up failed for user {telegram_user_id}: {e}")


# ── List all files ────────────────────────────────────────────────────────────

@router.get("/files")
async def list_all_files(
    request: Request,
    offset: int = Query(0),
    limit: int = Query(PAGE_SIZE),
    category: str = Query("All"),
    refresh: bool = Query(False),
    telegram_user_id: int = Depends(get_current_user),
):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    cache_key = f"{telegram_user_id}:all_files"
    if refresh:
        cache_invalidate(str(telegram_user_id))

    all_files = cache_get(cache_key)

    if all_files is None:
        db_files = db_get_files(telegram_user_id)
        all_files = db_files or []
        cache_set(cache_key, all_files)
        if not db_files:
            if telegram_user_id not in _syncing_users:
                _syncing_users.add(telegram_user_id)
                async def _bg_scan(uid: int = telegram_user_id):
                    try:
                        await _full_scan(uid)
                        refreshed = db_get_files(uid)
                        cache_set(f"{uid}:all_files", refreshed)
                        logger.info(f"Background full scan complete for user {uid}: {len(refreshed)} files")
                    except Exception as e:
                        logger.error(f"Background full scan error for user {uid}: {e}")
                    finally:
                        _syncing_users.discard(uid)
                asyncio.create_task(_bg_scan())

    syncing = telegram_user_id in _syncing_users

    # Warm up Telegram client in background so thumbnails can load without waiting
    asyncio.create_task(_warm_client(telegram_user_id))

    filtered = [f for f in all_files if f.get("category") == category] if category != "All" else all_files
    page = filtered[offset: offset + limit]

    return {
        "status": "success",
        "files": page,
        "total": len(filtered),
        "has_more": offset + limit < len(filtered),
        "scan_limit": MAX_SCAN_MESSAGES,
        "scanned": len(all_files),
        "syncing": syncing,
    }


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/files/stats")
async def files_stats(telegram_user_id: int = Depends(get_current_user)):
    cache_key = f"{telegram_user_id}:all_files"
    all_files = cache_get(cache_key)
    scanned = len(all_files) if all_files is not None else None
    has_more = (scanned == MAX_SCAN_MESSAGES) if scanned is not None else None
    return {
        "status": "success",
        "scan_limit": MAX_SCAN_MESSAGES,
        "scanned": scanned,
        "has_more": has_more,
        "cache_warm": all_files is not None,
    }


# ── Manual sync ───────────────────────────────────────────────────────────────

@router.post("/files/sync")
async def sync_new_files(
    request: Request,
    telegram_user_id: int = Depends(get_current_user),
):
    new_count = await _incremental_sync(telegram_user_id, force=True)
    return {"status": "success", "new_files": new_count}


# ── Search ────────────────────────────────────────────────────────────────────

@router.get("/files/search")
async def search_files(
    request: Request,
    q: str = Query(""),
    telegram_user_id: int = Depends(get_current_user),
):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    query = q.strip().lower()
    if len(query) < 2:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Query must be at least 2 characters"})

    all_files = cache_get(f"{telegram_user_id}:all_files") or db_get_files(telegram_user_id)
    results = [f for f in all_files if query in (f.get("name") or "").lower()]
    return {"status": "success", "files": results[:200], "total": len(results), "query": query}


# ── Stream file ───────────────────────────────────────────────────────────────

@router.get("/file/{file_id}")
async def get_file(
    file_id: str,
    request: Request,
    download: bool = Query(False),
    telegram_user_id: int = Depends(get_media_user),
):
    try:
        file_row = get_file_by_id(telegram_user_id, uuid.UUID(file_id))
        if not file_row:
            return JSONResponse(status_code=404, content={"status": "error", "message": "File not found"})

        if file_row.is_chunked:
            plan = chunk_download.build_plan(file_row.id)
            if not plan:
                return JSONResponse(status_code=404, content={"status": "error", "message": "File not found"})

            client = await get_user_client(telegram_user_id, require_authorized=True)
            file_size = file_row.file_size
            disposition = "attachment" if download else "inline"
            content_disp = _content_disposition(disposition, file_row.filename)

            range_header = request.headers.get("Range")
            if range_header and file_size:
                try:
                    range_val = range_header.replace("bytes=", "")
                    start_str, end_str = range_val.split("-")
                    start = int(start_str)
                    end = int(end_str) if end_str else file_size - 1
                    end = min(end, file_size - 1)
                    content_length = end - start + 1

                    async def chunked_range_iter() -> AsyncIterator[bytes]:
                        async for data in chunk_download.stream_range(client, plan, start, end):
                            yield data

                    headers = {
                        "Content-Range": f"bytes {start}-{end}/{file_size}",
                        "Accept-Ranges": "bytes",
                        "Content-Length": str(content_length),
                        "Content-Disposition": content_disp,
                    }
                    return StreamingResponse(chunked_range_iter(), status_code=206, media_type=file_row.mime_type, headers=headers)
                except Exception as e:
                    logger.warning(f"Chunked range parse error: {e}")

            async def chunked_full_iter() -> AsyncIterator[bytes]:
                async for data in chunk_download.stream_full(client, plan):
                    yield data

            headers = {
                "Accept-Ranges": "bytes",
                "Content-Disposition": content_disp,
                "Cache-Control": "public, max-age=86400",
                "ETag": f'"{file_row.id}"',
            }
            if file_size:
                headers["Content-Length"] = str(file_size)
            if request.headers.get("If-None-Match") == f'"{file_row.id}"':
                return Response(status_code=304)

            return StreamingResponse(chunked_full_iter(), media_type=file_row.mime_type, headers=headers)

        msg_id = file_row.telegram_message_id

        client = await get_user_client(telegram_user_id, require_authorized=True)
        message = await client.get_messages("me", ids=msg_id)
        if not message or not message.file:
            return JSONResponse(status_code=404, content={"status": "error", "message": "File not found"})

        mime = message.file.mime_type or "application/octet-stream"
        name = message.file.name or f"file_{msg_id}"
        file_size = message.file.size or 0
        disposition = "attachment" if download else "inline"
        content_disp = _content_disposition(disposition, name)

        range_header = request.headers.get("Range")
        if range_header and file_size:
            try:
                range_val = range_header.replace("bytes=", "")
                start_str, end_str = range_val.split("-")
                start = int(start_str)
                end = int(end_str) if end_str else file_size - 1
                end = min(end, file_size - 1)
                chunk_size = end - start + 1

                async def range_iter() -> AsyncIterator[bytes]:
                    # iter_download's `limit` counts requests, not bytes — iter_exact
                    # yields exactly the requested byte window.
                    async for chunk in chunk_download.iter_exact(client, message.media, start, chunk_size):
                        yield chunk

                headers = {
                    "Content-Range": f"bytes {start}-{end}/{file_size}",
                    "Accept-Ranges": "bytes",
                    "Content-Length": str(chunk_size),
                    "Content-Disposition": content_disp,
                }
                return StreamingResponse(range_iter(), status_code=206, media_type=mime, headers=headers)
            except Exception as e:
                logger.warning(f"Range parse error: {e}")

        async def full_iter() -> AsyncIterator[bytes]:
            async for chunk in client.iter_download(message.media, request_size=chunk_download.REQUEST_SIZE):
                yield chunk

        headers = {
            "Accept-Ranges": "bytes",
            "Content-Disposition": content_disp,
            "Cache-Control": "public, max-age=86400",
            "ETag": f'"{msg_id}"',
        }
        if file_size:
            headers["Content-Length"] = str(file_size)

        if request.headers.get("If-None-Match") == f'"{msg_id}"':
            return Response(status_code=304)

        return StreamingResponse(full_iter(), media_type=mime, headers=headers)
    except SessionRevokedError:
        raise
    except Exception as e:
        logger.error(f"GET FILE ERROR: {e}", exc_info=True)
        return JSONResponse(status_code=404, content={"status": "error", "message": "File not found"})


# ── Thumbnail ─────────────────────────────────────────────────────────────────

@router.get("/thumbnail/{file_id}")
async def get_thumbnail(
    file_id: str,
    request: Request,
    telegram_user_id: int = Depends(get_media_user),
):
    try:
        file_row = get_file_by_id(telegram_user_id, uuid.UUID(file_id))
    except ValueError:
        file_row = None
    if not file_row:
        return JSONResponse(status_code=404, content={"status": "error", "message": "Not found"})

    if file_row.is_chunked:
        # Best-effort: part 1 may or may not contain a decodable header depending on the
        # container (e.g. mp4 moov atom placement) — falls through to the generic file
        # icon on the frontend if Telegram has no thumbnail for it.
        chunks = get_file_chunks_ordered(file_row.id)
        if not chunks:
            return JSONResponse(status_code=404, content={"status": "error", "message": "Not found"})
        msg_id = chunks[0].telegram_message_id
    else:
        msg_id = file_row.telegram_message_id

    thumb_file = f"{telegram_user_id}_{msg_id}.jpg"
    thumb_path = os.path.join(os.path.abspath(THUMB_FOLDER), thumb_file)

    if os.path.exists(thumb_path):
        from fastapi.responses import FileResponse
        return FileResponse(thumb_path, media_type="image/jpeg", headers={"Cache-Control": "public, max-age=604800"})

    try:
        client = await get_user_client(telegram_user_id, require_authorized=True)
        message = await client.get_messages("me", ids=msg_id)
        if not message or not message.file:
            return JSONResponse(status_code=404, content={"status": "error", "message": "Not found"})

        thumb_bytes = None

        # Documents (videos, files with poster frames) — use largest available thumb
        if message.document and getattr(message.document, "thumbs", None):
            try:
                thumb_bytes = await message.download_media(bytes, thumb=-1)
            except Exception:
                pass

        # Telegram native photos
        if not thumb_bytes and message.photo:
            try:
                thumb_bytes = await message.download_media(bytes, thumb=-1)
            except Exception:
                pass

        # Small images: download full file as thumb
        if not thumb_bytes:
            mime = message.file.mime_type or ""
            if mime.startswith("image/") and message.file.size and message.file.size < 500_000:
                thumb_bytes = await message.download_media(bytes)

        if not thumb_bytes:
            return JSONResponse(status_code=404, content={"status": "error", "message": "No thumbnail"})

        with open(thumb_path, "wb") as f:
            f.write(thumb_bytes)

        return Response(content=thumb_bytes, media_type="image/jpeg",
                        headers={"Cache-Control": "public, max-age=604800"})
    except SessionRevokedError:
        raise
    except Exception as e:
        logger.error(f"GET THUMBNAIL ERROR: {e}", exc_info=True)
        return JSONResponse(status_code=404, content={"status": "error", "message": "Not found"})


# ── Upload ────────────────────────────────────────────────────────────────────

@router.post("/upload")
async def upload(
    request: Request,
    folderName: str = Form(default=""),
    file: list[UploadFile] = File(...),
    telegram_user_id: int = Depends(get_current_user),
):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    folder_name = sanitize_input(folderName)
    files = file

    if not files:
        return JSONResponse(status_code=400, content={"status": "error", "message": "No files provided"})

    for f in files:
        ok, result = validate_file_upload(f)
        if not ok:
            return JSONResponse(status_code=400, content={"status": "error", "message": result})

    saved: list[tuple[str, str]] = []
    for f in files:
        filename = f"{uuid.uuid4().hex}_{f.filename}"
        path = os.path.join(UPLOAD_FOLDER, filename)
        content = await f.read()
        if len(content) > _MAX_UPLOAD_BYTES:
            logger.warning(
                f"Upload rejected: {f.filename!r} is {len(content) // (1024 * 1024)}MB, "
                f"limit {MAX_UPLOAD_MB}MB (user={telegram_user_id})"
            )
            for _, sp in saved:
                if os.path.exists(sp):
                    os.remove(sp)
            return JSONResponse(
                status_code=413,
                content={"status": "error", "message": f"'{f.filename}' exceeds the {MAX_UPLOAD_MB} MB size limit."},
            )
        with open(path, "wb") as fp:
            fp.write(content)
        saved.append((f.filename, path))

    # Resolve folder_id upfront
    folder_id = None
    if folder_name:
        folder = add_folder(telegram_user_id, folder_name)
        folder_id = folder.id

    uploaded: list[str] = []
    failed: list[str] = []

    try:
        client = await get_user_client(telegram_user_id, require_authorized=True)
        for orig_name, path in saved:
            try:
                msg = await client.send_file(
                    "me", path, force_document=True,
                    attributes=[DocumentAttributeFilename(file_name=orig_name)],
                )
                mime = msg.file.mime_type or "application/octet-stream" if msg.file else "application/octet-stream"
                size = msg.file.size or 0 if msg.file else 0
                db_insert_file(
                    telegram_user_id=telegram_user_id,
                    msg_id=msg.id,
                    filename=orig_name,
                    mime_type=mime,
                    file_size=size,
                    category=_categorize(orig_name, mime),
                    uploaded_at=msg.date if msg.date else datetime.utcnow(),
                    folder_id=folder_id,
                )
                uploaded.append(orig_name)
            except Exception as e:
                logger.error(f"Error uploading {orig_name}: {e}", exc_info=True)
                failed.append(orig_name)
            finally:
                if os.path.exists(path):
                    os.remove(path)
    except SessionRevokedError:
        for _, path in saved:
            if os.path.exists(path):
                os.remove(path)
        raise
    except Exception as e:
        for _, path in saved:
            if os.path.exists(path):
                os.remove(path)
        logger.error(f"UPLOAD ERROR: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": "Upload failed"})

    cache_invalidate(str(telegram_user_id))
    log_security_event(request, "FILES_UPLOADED", f"uploaded={len(uploaded)} failed={len(failed)}", str(telegram_user_id))

    if failed:
        return {"status": "partial", "uploaded": uploaded, "failed": failed,
                "message": f"{len(uploaded)} uploaded, {len(failed)} failed."}
    return {"status": "success", "files": uploaded}


# ── Move files ────────────────────────────────────────────────────────────────

class MoveFilesBody(BaseModel):
    folder: str
    file_ids: list[str]


@router.post("/files/move")
async def move_files(
    request: Request,
    body: MoveFilesBody,
    telegram_user_id: int = Depends(get_current_user),
):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    folder = sanitize_input(body.folder).strip()
    if not folder:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Folder name is required"})
    if not body.file_ids:
        return JSONResponse(status_code=400, content={"status": "error", "message": "file_ids must be a non-empty list"})

    try:
        file_ids = [uuid.UUID(x) for x in body.file_ids]
    except ValueError:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Invalid file id"})

    target_folder = add_folder(telegram_user_id, folder)
    db_move_files(telegram_user_id, file_ids, target_folder.id)
    cache_invalidate(str(telegram_user_id))
    log_security_event(request, "FILES_MOVED", f"moved={len(file_ids)} to={folder}", str(telegram_user_id))
    return {"status": "success", "moved": len(file_ids), "failed": []}


# ── Delete files ──────────────────────────────────────────────────────────────

class DeleteFilesBody(BaseModel):
    file_ids: list[str]


@router.delete("/files")
async def delete_files(
    request: Request,
    body: DeleteFilesBody,
    telegram_user_id: int = Depends(get_current_user),
):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    if not body.file_ids:
        return JSONResponse(status_code=400, content={"status": "error", "message": "file_ids must be a non-empty list"})

    try:
        file_ids = [uuid.UUID(x) for x in body.file_ids]
    except ValueError:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Invalid file id"})

    try:
        client = await get_user_client(telegram_user_id, require_authorized=True)
        message_ids = db_delete_files_by_ids(telegram_user_id, file_ids)
        deleted, failed = 0, []
        for i in range(0, len(message_ids), 100):
            chunk = message_ids[i: i + 100]
            try:
                await client.delete_messages("me", chunk)
                deleted += len(chunk)
            except Exception as e:
                logger.error(f"DELETE chunk error: {e}")
                failed.extend(chunk)

        for mid in message_ids:
            tp = os.path.join(THUMB_FOLDER, f"{telegram_user_id}_{mid}.jpg")
            if os.path.exists(tp):
                os.remove(tp)

        cache_invalidate(str(telegram_user_id))
        log_security_event(request, "FILES_DELETED", f"deleted={deleted}", str(telegram_user_id))
        return {"status": "success", "deleted": deleted, "failed": failed}
    except SessionRevokedError:
        raise
    except Exception as e:
        logger.error(f"DELETE FILES ERROR: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": "Failed to delete files"})
