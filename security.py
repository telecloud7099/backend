import re
import time
import logging
from typing import Optional
from collections import defaultdict
from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

rate_limit_storage: dict[str, list] = defaultdict(list)
MAX_REQUESTS_PER_HOUR = 100


async def rate_limit_check(request: Request):
    ip = request.client.host
    now = time.time()
    rate_limit_storage[ip] = [t for t in rate_limit_storage[ip] if now - t < 3600]
    if len(rate_limit_storage[ip]) >= MAX_REQUESTS_PER_HOUR:
        logger.warning(f"Rate limit exceeded for IP: {ip}")
        return JSONResponse(
            status_code=429,
            content={"status": "error", "message": "Rate limit exceeded. Try again later."},
        )
    rate_limit_storage[ip].append(now)
    return None


def validate_phone_number(phone: Optional[str]) -> tuple:
    if not phone:
        return False, "Phone number is required"
    phone = re.sub(r"[\s\-]", "", phone)
    if not re.match(r"^\+[1-9]\d{1,14}$", phone):
        return False, "Invalid phone number format. Use +[country code][number]"
    return True, phone


def validate_file_upload(file) -> tuple[bool, str]:
    if not file:
        return False, "No file provided"

    ALLOWED_EXTENSIONS = {
        "txt", "pdf", "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg",
        "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "zip", "rar", "7z", "tar", "gz", "tgz",
        "mp3", "mp4", "avi", "mov", "wmv", "mkv", "flac", "aac", "ogg",
        "apk", "iso", "dmg",
    }

    filename = file.filename
    if not filename or "." not in filename:
        return False, "Invalid filename"

    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"File type .{ext} not allowed"

    return True, filename


def sanitize_input(text: Optional[str]) -> str:
    if not text:
        return ""
    return re.sub(r"[<>\"']", "", text).strip()


def rate_limit_sweep() -> None:
    """Remove IPs with no activity in the last hour to prevent unbounded growth."""
    cutoff = time.time() - 3600
    stale = [ip for ip, timestamps in rate_limit_storage.items()
             if not timestamps or timestamps[-1] < cutoff]
    for ip in stale:
        del rate_limit_storage[ip]
    if stale:
        logger.debug(f"Rate limit sweep removed {len(stale)} stale IPs")


def log_security_event(request: Request, event_type: str, details: str, phone: Optional[str] = None):
    logger.info(
        "SECURITY EVENT: type=%s ip=%s phone=%s ua=%s details=%s",
        event_type,
        request.client.host,
        phone,
        request.headers.get("User-Agent", ""),
        details,
    )
