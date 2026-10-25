import time
from collections import deque

_app_start: float = time.time()
_response_times: deque[float] = deque(maxlen=200)
_request_count: int = 0
_error_count: int = 0


def record_response(elapsed_ms: float, is_error: bool = False) -> None:
    global _request_count, _error_count
    _response_times.append(elapsed_ms)
    _request_count += 1
    if is_error:
        _error_count += 1


def get_uptime() -> float:
    return time.time() - _app_start


def get_request_stats() -> dict:
    avg = round(sum(_response_times) / len(_response_times), 1) if _response_times else None
    return {
        "total": _request_count,
        "errors": _error_count,
        "avg_response_ms": avg,
    }
