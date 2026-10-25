import logging
from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from backend.auth import get_current_user
from backend.database import (
    get_folders, folder_exists, add_folder,
    rename_folder_db, delete_folder_db,
    db_get_files_in_folder, db_get_folder_counts,
    get_folder_by_name,
)
from backend.cache import cache_get, cache_set, cache_invalidate
from backend.security import rate_limit_check, sanitize_input, log_security_event

router = APIRouter()
logger = logging.getLogger(__name__)


# ── List folders ──────────────────────────────────────────────────────────────

@router.get("/folders")
async def list_folders(
    request: Request,
    telegram_user_id: int = Depends(get_current_user),
):
    folders = get_folders(telegram_user_id)
    log_security_event(request, "FOLDERS_LISTED", f"count={len(folders)}", str(telegram_user_id))
    return {"status": "success", "folders": [f["name"] for f in folders]}


# ── Folder counts + storage stats ────────────────────────────────────────────

@router.get("/folders/counts")
async def folder_counts(
    request: Request,
    telegram_user_id: int = Depends(get_current_user),
):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    cache_key = f"{telegram_user_id}:folder_counts"
    cached = cache_get(cache_key)
    if cached is not None:
        return {"status": "success", **cached}

    result = db_get_folder_counts(telegram_user_id)
    cache_set(cache_key, result)
    return {"status": "success", **result}


# ── Create folder ─────────────────────────────────────────────────────────────

class CreateFolderBody(BaseModel):
    folder_name: str


@router.post("/folders")
async def create_folder(
    request: Request,
    body: CreateFolderBody,
    telegram_user_id: int = Depends(get_current_user),
):
    name = sanitize_input(body.folder_name).strip()
    if not name:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Folder name is required"})
    if folder_exists(telegram_user_id, name):
        return JSONResponse(status_code=400, content={"status": "error", "message": "Folder already exists"})
    add_folder(telegram_user_id, name)
    cache_invalidate(str(telegram_user_id))
    log_security_event(request, "FOLDER_CREATED", f"name={name}", str(telegram_user_id))
    return {"status": "success", "folder": name}


# ── Rename folder ─────────────────────────────────────────────────────────────

class RenameFolderBody(BaseModel):
    new_name: str


@router.put("/folders/{old_name}")
async def rename_folder(
    old_name: str,
    request: Request,
    body: RenameFolderBody,
    telegram_user_id: int = Depends(get_current_user),
):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    old_name = sanitize_input(old_name).strip()
    new_name = sanitize_input(body.new_name).strip()

    if not old_name or not new_name:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Both names are required"})
    if old_name == new_name:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Names are the same"})
    if not folder_exists(telegram_user_id, old_name):
        return JSONResponse(status_code=404, content={"status": "error", "message": "Folder not found"})
    if folder_exists(telegram_user_id, new_name):
        return JSONResponse(status_code=400, content={"status": "error", "message": "A folder with that name already exists"})

    rename_folder_db(telegram_user_id, old_name, new_name)
    cache_invalidate(str(telegram_user_id))
    log_security_event(request, "FOLDER_RENAMED", f"{old_name}→{new_name}", str(telegram_user_id))
    return {"status": "success"}


# ── Delete folder ─────────────────────────────────────────────────────────────

@router.delete("/folders/{folder_name}")
async def delete_folder(
    folder_name: str,
    request: Request,
    telegram_user_id: int = Depends(get_current_user),
):
    name = sanitize_input(folder_name).strip()
    if not folder_exists(telegram_user_id, name):
        return JSONResponse(status_code=404, content={"status": "error", "message": "Folder not found"})
    delete_folder_db(telegram_user_id, name)
    cache_invalidate(str(telegram_user_id))
    log_security_event(request, "FOLDER_DELETED", f"name={name}", str(telegram_user_id))
    return {"status": "success", "message": "Folder removed. Files are still in Telegram."}


# ── Files in folder ───────────────────────────────────────────────────────────

@router.get("/folders/{folder_name}/files")
async def list_files_in_folder(
    folder_name: str,
    request: Request,
    telegram_user_id: int = Depends(get_current_user),
):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    folder = sanitize_input(folder_name).strip()
    if not folder:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Folder name is required"})

    cache_key = f"{telegram_user_id}:folder:{folder}"
    cached = cache_get(cache_key)
    if cached is not None:
        return {"status": "success", "files": cached, "total": len(cached)}

    folder_record = get_folder_by_name(telegram_user_id, folder)
    if not folder_record:
        return JSONResponse(status_code=404, content={"status": "error", "message": "Folder not found"})

    files = db_get_files_in_folder(telegram_user_id, folder_record.id)
    cache_set(cache_key, files)
    log_security_event(request, "FILES_LISTED", f"folder={folder} count={len(files)}", str(telegram_user_id))
    return {"status": "success", "files": files, "total": len(files)}
