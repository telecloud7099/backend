import time

CACHE_TTL = 3600  # 1 hour

_cache: dict[str, tuple] = {}  # key → (data, timestamp)
_hits: int = 0
_misses: int = 0


def cache_get(key: str):
    global _hits, _misses
    if key in _cache:
        data, ts = _cache[key]
        if time.time() - ts < CACHE_TTL:
            _hits += 1
            return data
        del _cache[key]
    _misses += 1
    return None


def cache_set(key: str, data) -> None:
    _cache[key] = (data, time.time())


def cache_invalidate(prefix: str) -> None:
    keys = [k for k in _cache if k.startswith(f"{prefix}:")]
    for k in keys:
        del _cache[k]


def cache_sweep() -> None:
    now = time.time()
    expired = [k for k, (_, ts) in _cache.items() if now - ts >= CACHE_TTL]
    for k in expired:
        del _cache[k]


def get_cache_stats() -> dict:
    total = _hits + _misses
    return {
        "hits": _hits,
        "misses": _misses,
        "hit_rate_pct": round(100 * _hits / total, 1) if total > 0 else 0.0,
        "entries": len(_cache),
    }
