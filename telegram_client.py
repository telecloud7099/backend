import asyncio
import logging
import time as _time
from telethon import TelegramClient
from telethon.errors import AuthKeyDuplicatedError
from telethon.sessions import StringSession

logger = logging.getLogger(__name__)


class SessionRevokedError(Exception):
    """Telegram permanently invalidated the stored StringSession (the same auth key was
    used from two IP addresses at once — e.g. a local and a deployed backend sharing one
    database). Retrying can never succeed; the user must log in again. main.py maps this
    to a 401 so the frontend redirects to the login screen."""

    def __init__(self):
        super().__init__("Your Telegram session was disconnected because it was used from two places at once. Please log in again.")

# telegram_user_id → TelegramClient (in-memory pool; rebuilt from DB on restart)
_clients: dict[int, TelegramClient] = {}
# Per-user lock to prevent concurrent client creation (race condition)
_connect_locks: dict[int, asyncio.Lock] = {}
# Timestamp of last connection failure — drives 30-second backoff
_connect_failed_at: dict[int, float] = {}
# Number of callers currently inside get_client() for a given user — diagnostic only,
# added to investigate a 2026-07-23 incident where reconnect attempts kept timing out
# for 15+ minutes after a backend restart despite Telegram itself being reachable in
# under a second when tested in isolation (see docs/RESILIENCE_TEST_PLAN.md). Lets log
# lines show whether a slow attempt was contending with concurrent callers.
_active_calls: dict[int, int] = {}

CONNECT_BACKOFF = 30  # seconds to wait after a connection failure before retrying


def is_client_connected(telegram_user_id: int) -> bool:
    client = _clients.get(telegram_user_id)
    return client is not None and client.is_connected()


def _get_lock(user_id: int) -> asyncio.Lock:
    if user_id not in _connect_locks:
        _connect_locks[user_id] = asyncio.Lock()
    return _connect_locks[user_id]


async def get_client(
    telegram_user_id: int,
    api_id: int,
    api_hash: str,
    string_session: str = "",
    require_authorized: bool = False,
) -> TelegramClient:
    t_enter = _time.monotonic()
    _active_calls[telegram_user_id] = _active_calls.get(telegram_user_id, 0) + 1
    concurrent_count = _active_calls[telegram_user_id]
    if concurrent_count > 1:
        logger.info(f"get_client user={telegram_user_id}: entering with {concurrent_count} concurrent callers")

    try:
        # Fast path: return connected client without acquiring the lock
        if telegram_user_id in _clients:
            client = _clients[telegram_user_id]
            if client.is_connected():
                if require_authorized and not await client.is_user_authorized():
                    await _drop(telegram_user_id)
                else:
                    _connect_failed_at.pop(telegram_user_id, None)
                    return client

        # Backoff: if we recently failed, reject immediately (don't hold the lock for 12 seconds)
        last_failure = _connect_failed_at.get(telegram_user_id, 0)
        if _time.time() - last_failure < CONNECT_BACKOFF:
            secs = int(CONNECT_BACKOFF - (_time.time() - last_failure))
            logger.info(
                f"get_client user={telegram_user_id}: rejected by backoff, {secs}s remaining "
                f"(concurrent_callers={concurrent_count})"
            )
            raise Exception(f"Telegram connection unavailable, retrying in {secs}s")

        # Slow path: create / reconnect under a per-user lock to avoid concurrent connections
        t_before_lock = _time.monotonic()
        async with _get_lock(telegram_user_id):
            t_lock_acquired = _time.monotonic()
            lock_wait = t_lock_acquired - t_before_lock
            if lock_wait > 0.05:
                logger.info(
                    f"get_client user={telegram_user_id}: waited {lock_wait:.2f}s for lock "
                    f"(concurrent_callers={concurrent_count})"
                )

            # Re-check inside the lock in case another coroutine already created it
            if telegram_user_id in _clients:
                client = _clients[telegram_user_id]
                if client.is_connected():
                    if require_authorized and not await client.is_user_authorized():
                        await _drop(telegram_user_id)
                    else:
                        _connect_failed_at.pop(telegram_user_id, None)
                        return client
                else:
                    t_connect_start = _time.monotonic()
                    try:
                        await asyncio.wait_for(client.connect(), timeout=12)
                        connect_elapsed = _time.monotonic() - t_connect_start
                        logger.info(
                            f"get_client user={telegram_user_id}: reconnect of existing client "
                            f"succeeded in {connect_elapsed:.2f}s (lock_wait={lock_wait:.2f}s, "
                            f"total={_time.monotonic() - t_enter:.2f}s)"
                        )
                        if require_authorized and not await client.is_user_authorized():
                            await _drop(telegram_user_id)
                        else:
                            _connect_failed_at.pop(telegram_user_id, None)
                            return client
                    except Exception as e:
                        connect_elapsed = _time.monotonic() - t_connect_start
                        logger.warning(
                            f"get_client user={telegram_user_id}: reconnect of existing client "
                            f"FAILED after {connect_elapsed:.2f}s ({e}) (lock_wait={lock_wait:.2f}s, "
                            f"total={_time.monotonic() - t_enter:.2f}s)"
                        )
                        await _drop(telegram_user_id)

            session = StringSession(string_session) if string_session else StringSession()
            # connection_retries=1: one attempt — avoids 37-second OS TCP timeout loops
            client = TelegramClient(session, api_id, api_hash, connection_retries=1)
            t_connect_start = _time.monotonic()
            try:
                await asyncio.wait_for(client.connect(), timeout=12)
                connect_elapsed = _time.monotonic() - t_connect_start
                logger.info(
                    f"get_client user={telegram_user_id}: new client connect succeeded in "
                    f"{connect_elapsed:.2f}s (lock_wait={lock_wait:.2f}s, "
                    f"total={_time.monotonic() - t_enter:.2f}s, concurrent_callers={concurrent_count})"
                )
            except AuthKeyDuplicatedError:
                # Permanent: Telegram killed this auth key for concurrent use from two IPs.
                # No backoff/retry — surface it so the caller wipes the stored session.
                logger.error(f"Telegram revoked the session for user {telegram_user_id} (AuthKeyDuplicatedError)")
                try:
                    await asyncio.wait_for(client.disconnect(), timeout=3)
                except Exception:
                    pass
                raise SessionRevokedError()
            except (asyncio.TimeoutError, Exception) as e:
                connect_elapsed = _time.monotonic() - t_connect_start
                total_elapsed = _time.monotonic() - t_enter
                _connect_failed_at[telegram_user_id] = _time.time()
                logger.warning(
                    f"Telegram connect failed for user {telegram_user_id}: {e} "
                    f"(lock_wait={lock_wait:.2f}s, connect_attempt={connect_elapsed:.2f}s, "
                    f"total={total_elapsed:.2f}s, concurrent_callers={concurrent_count})"
                )
                try:
                    await asyncio.wait_for(client.disconnect(), timeout=3)
                except Exception:
                    pass
                raise Exception("Telegram connection timed out. Please try again.")

            if require_authorized and not await client.is_user_authorized():
                await client.disconnect()
                _connect_failed_at[telegram_user_id] = _time.time()
                raise Exception("Telegram session not authorized. Please login again.")

            _connect_failed_at.pop(telegram_user_id, None)
            _clients[telegram_user_id] = client
            return client
    finally:
        _active_calls[telegram_user_id] -= 1


async def get_unauthenticated_client(phone: str, api_id: int, api_hash: str) -> TelegramClient:
    """Fresh client for OTP flow — keyed by phone, not user_id (user_id unknown yet)."""
    key = f"pre:{phone}"
    if key in _clients:  # type: ignore[operator]
        client = _clients[key]  # type: ignore[index]
        if client.is_connected():
            return client
        try:
            await asyncio.wait_for(client.connect(), timeout=12)
            return client
        except Exception:
            del _clients[key]  # type: ignore[arg-type]

    client = TelegramClient(StringSession(), api_id, api_hash, connection_retries=1)
    try:
        await asyncio.wait_for(client.connect(), timeout=12)
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Unauthenticated Telegram connect failed for {phone}: {e}")
        try:
            await asyncio.wait_for(client.disconnect(), timeout=3)
        except Exception:
            pass
        raise Exception("Telegram connection timed out. Please try again.")
    _clients[key] = client  # type: ignore[index]
    return client


def get_string_session(telegram_user_id: int) -> str:
    client = _clients.get(telegram_user_id)
    if client and hasattr(client.session, "save"):
        return client.session.save()
    return ""


async def remove_client(telegram_user_id: int):
    await _drop(telegram_user_id)


def get_pre_auth_client(phone: str):
    """Return the existing pre-auth client for a phone, or None."""
    return _clients.get(f"pre:{phone}")  # type: ignore[arg-type]


def promote_pre_auth_client(phone: str, telegram_user_id: int):
    """Move the pre-auth client (keyed by phone) into the main pool (keyed by user_id)."""
    key = f"pre:{phone}"
    client = _clients.pop(key, None)  # type: ignore[arg-type]
    if client:
        _clients[telegram_user_id] = client


async def remove_pre_auth_client(phone: str):
    key = f"pre:{phone}"
    client = _clients.pop(key, None)  # type: ignore[arg-type]
    if client:
        try:
            await client.disconnect()
        except Exception:
            pass


async def _drop(key):
    client = _clients.pop(key, None)
    if client:
        try:
            await asyncio.wait_for(client.disconnect(), timeout=5)
        except Exception:
            pass


def get_active_sessions() -> dict:
    user_ids = [k for k in _clients if isinstance(k, int) and _clients[k].is_connected()]
    return {"count": len(user_ids), "user_ids": user_ids}


async def get_user_client(telegram_user_id: int, require_authorized: bool = False) -> TelegramClient:
    """Shared entry point for routes that need a connected, authenticated client for a user —
    loads credentials/StringSession from the DB and persists the session if Telethon rotated it."""
    from backend.database import get_api_credentials, load_string_session, save_string_session

    api_id, api_hash = get_api_credentials(telegram_user_id)
    if not api_id:
        raise Exception("API credentials not found")
    string_session = load_string_session(telegram_user_id) or ""
    try:
        client = await get_client(telegram_user_id, api_id, api_hash, string_session, require_authorized)
    except SessionRevokedError:
        # The stored session can never work again — wipe it so nothing keeps retrying it,
        # and so the next login starts clean.
        save_string_session(telegram_user_id, "")
        raise
    saved = get_string_session(telegram_user_id)
    if saved and saved != string_session:
        save_string_session(telegram_user_id, saved)
    return client
