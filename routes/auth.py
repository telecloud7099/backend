import logging
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from telethon.errors import SessionPasswordNeededError, AuthRestartError

from backend.auth import get_current_user, create_jwt
from backend.database import (
    get_or_create_user, get_user,
    save_api_credentials, get_api_credentials,
    credentials_exist_for_phone, get_api_credentials_by_phone,
    save_string_session, load_string_session,
    delete_all_user_data,
)
from backend.telegram_client import (
    get_client, get_unauthenticated_client, get_pre_auth_client,
    get_string_session, remove_client, remove_pre_auth_client, promote_pre_auth_client,
)
from backend.security import rate_limit_check, validate_phone_number, sanitize_input, log_security_event
from backend.cache import cache_invalidate

router = APIRouter()
logger = logging.getLogger(__name__)

# phone → phone_code_hash (pre-auth)
_phone_code_hashes: dict[str, str] = {}
# phone → (api_id, api_hash) for new users who haven't authenticated yet
_pending_credentials: dict[str, tuple[int, str]] = {}


# ── Request models ────────────────────────────────────────────────────────────

class CheckPhoneRequest(BaseModel):
    phone: str


class SetupApiRequest(BaseModel):
    phone: str
    api_id: int
    api_hash: str


class SendCodeRequest(BaseModel):
    phone: str


class VerifyCodeRequest(BaseModel):
    phone: str
    code: str


class VerifyPasswordRequest(BaseModel):
    phone: str
    password: str


# ── Check phone ───────────────────────────────────────────────────────────────

@router.post("/check-phone")
async def check_phone(request: Request, body: CheckPhoneRequest):
    rl = await rate_limit_check(request)
    if rl:
        return rl
    ok, result = validate_phone_number(body.phone)
    if not ok:
        return JSONResponse(status_code=400, content={"status": "error", "message": result})
    phone = result
    has_creds = credentials_exist_for_phone(phone)
    return {"status": "ok", "needs_setup": not has_creds}


# ── Setup API credentials (pre-auth, new users only) ─────────────────────────

@router.post("/setup-api")
async def setup_api(request: Request, body: SetupApiRequest):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    ok, result = validate_phone_number(body.phone)
    if not ok:
        return JSONResponse(status_code=400, content={"status": "error", "message": result})
    phone = result

    if body.api_id <= 0:
        return JSONResponse(status_code=400, content={"status": "error", "message": "API ID must be positive"})
    if not body.api_hash or len(body.api_hash.strip()) < 16:
        return JSONResponse(status_code=400, content={"status": "error", "message": "API Hash is too short"})

    _pending_credentials[phone] = (body.api_id, body.api_hash.strip())
    return {"status": "success"}


# ── Send OTP ──────────────────────────────────────────────────────────────────

@router.post("/send_code")
async def send_code(request: Request, body: SendCodeRequest):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    ok, result = validate_phone_number(body.phone)
    if not ok:
        return JSONResponse(status_code=400, content={"status": "error", "message": result})
    phone = result

    # If OTP already sent, don't repeat the Telegram call
    if phone in _phone_code_hashes:
        return {"status": "code_sent", "message": f"Code already sent to {phone}."}

    # Resolve credentials: from DB (returning user) or pending (new user)
    api_id, api_hash = get_api_credentials_by_phone(phone)
    if not api_id:
        pending = _pending_credentials.get(phone)
        if not pending:
            return JSONResponse(status_code=400, content={
                "status": "error",
                "message": "API credentials not configured.",
                "needs_setup": True,
            })
        api_id, api_hash = pending

    async def _send(ph, aid, ahash):
        client = await get_unauthenticated_client(ph, aid, ahash)
        r = await client.send_code_request(ph)
        return r.phone_code_hash

    try:
        pch = await _send(phone, api_id, api_hash)
        _phone_code_hashes[phone] = pch
        log_security_event(request, "OTP_SENT", f"OTP sent to {phone}", phone)
        return {"status": "code_sent", "message": f"OTP sent to {phone}. Check your Telegram app."}
    except AuthRestartError:
        await remove_pre_auth_client(phone)
        try:
            pch = await _send(phone, api_id, api_hash)
            _phone_code_hashes[phone] = pch
            return {"status": "code_sent", "message": f"OTP sent to {phone}. Check your Telegram app."}
        except Exception as e2:
            logger.error(f"SEND CODE RETRY ERROR: {e2}")
            return JSONResponse(status_code=500, content={"status": "error", "message": "Telegram connection error. Please try again."})
    except Exception as e:
        logger.error(f"SEND CODE ERROR: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": "Failed to send OTP. Please try again."})


# ── Verify OTP ────────────────────────────────────────────────────────────────

@router.post("/verify_code")
async def verify_code(request: Request, body: VerifyCodeRequest):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    ok, result = validate_phone_number(body.phone)
    if not ok:
        return JSONResponse(status_code=400, content={"status": "error", "message": result})
    phone = result
    code = sanitize_input(body.code)
    if not code:
        return JSONResponse(status_code=400, content={"status": "error", "message": "OTP code is required"})

    pch = _phone_code_hashes.get(phone)
    if not pch:
        return JSONResponse(status_code=400, content={"status": "error", "message": "No OTP session. Request a new code."})

    api_id, api_hash = get_api_credentials_by_phone(phone)
    if not api_id:
        pending = _pending_credentials.get(phone)
        if not pending:
            return JSONResponse(status_code=400, content={"status": "error", "message": "API credentials missing."})
        api_id, api_hash = pending

    try:
        # Use the pre-auth client that already has the OTP session
        pre_client = await get_unauthenticated_client(phone, api_id, api_hash)
        await pre_client.sign_in(phone=phone, code=code, phone_code_hash=pch)
        return await _finalize_login(request, phone, api_id, api_hash, pre_client)
    except SessionPasswordNeededError:
        log_security_event(request, "2FA_REQUIRED", "2FA required", phone)
        return {"status": "2fa_required"}
    except Exception as e:
        logger.error(f"VERIFY CODE ERROR: {e}")
        log_security_event(request, "LOGIN_FAILED", str(e), phone)
        return JSONResponse(status_code=400, content={"status": "failed", "error": "Invalid OTP or session expired"})


# ── Verify 2FA password ───────────────────────────────────────────────────────

@router.post("/verify_password")
async def verify_password(request: Request, body: VerifyPasswordRequest):
    rl = await rate_limit_check(request)
    if rl:
        return rl

    ok, result = validate_phone_number(body.phone)
    if not ok:
        return JSONResponse(status_code=400, content={"status": "error", "message": result})
    phone = result
    password = sanitize_input(body.password)
    if not password:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Password is required"})

    api_id, api_hash = get_api_credentials_by_phone(phone)
    if not api_id:
        pending = _pending_credentials.get(phone)
        if not pending:
            return JSONResponse(status_code=400, content={"status": "error", "message": "API credentials missing."})
        api_id, api_hash = pending

    try:
        pre_client = get_pre_auth_client(phone) or await get_unauthenticated_client(phone, api_id, api_hash)
        await pre_client.sign_in(password=password)
        return await _finalize_login(request, phone, api_id, api_hash, pre_client)
    except Exception as e:
        logger.error(f"VERIFY PASSWORD ERROR: {e}")
        log_security_event(request, "2FA_FAILED", str(e), phone)
        return JSONResponse(status_code=400, content={"status": "failed", "error": "Invalid password"})


async def _finalize_login(request, phone: str, api_id: int, api_hash: str, pre_client) -> dict:
    """After successful Telegram auth: create user, save credentials, issue JWT."""
    me = await pre_client.get_me()
    telegram_user_id = me.id

    user = get_or_create_user(
        telegram_user_id=telegram_user_id,
        username=getattr(me, "username", None),
        first_name=getattr(me, "first_name", None),
    )

    # Persist credentials if they came from pending (new user)
    db_api_id, _ = get_api_credentials(telegram_user_id)
    if not db_api_id:
        save_api_credentials(telegram_user_id, phone, api_id, api_hash)

    # Save StringSession
    string_session = pre_client.session.save()
    save_string_session(telegram_user_id, string_session)

    # Move pre-auth client → main pool
    promote_pre_auth_client(phone, telegram_user_id)

    # Clean up OTP state
    _phone_code_hashes.pop(phone, None)
    _pending_credentials.pop(phone, None)

    token = create_jwt(telegram_user_id)
    log_security_event(request, "LOGIN_SUCCESS", f"telegram_user_id={telegram_user_id}", phone)
    return {"status": "success", "access_token": token}


# ── Me ────────────────────────────────────────────────────────────────────────

@router.get("/me")
async def me(telegram_user_id: int = Depends(get_current_user)):
    user = get_user(telegram_user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {
        "status": "success",
        "telegram_user_id": user.telegram_user_id,
        "username": user.username,
        "first_name": user.first_name,
    }


# ── Logout ────────────────────────────────────────────────────────────────────

@router.post("/logout")
async def logout(request: Request, telegram_user_id: int = Depends(get_current_user)):
    await remove_client(telegram_user_id)
    cache_invalidate(str(telegram_user_id))
    log_security_event(request, "LOGOUT", "User logged out", str(telegram_user_id))
    return {"status": "success"}


# ── Delete all data ───────────────────────────────────────────────────────────

@router.post("/delete_data")
async def delete_data(request: Request, telegram_user_id: int = Depends(get_current_user)):
    await remove_client(telegram_user_id)
    cache_invalidate(str(telegram_user_id))
    delete_all_user_data(telegram_user_id)

    import os
    thumbs_dir = "thumbs"
    if os.path.isdir(thumbs_dir):
        for f in os.listdir(thumbs_dir):
            if f.startswith(f"{telegram_user_id}_"):
                try:
                    os.remove(os.path.join(thumbs_dir, f))
                except OSError:
                    pass

    log_security_event(request, "DATA_DELETED", "All data deleted", str(telegram_user_id))
    return {"status": "success", "message": "All data deleted"}
