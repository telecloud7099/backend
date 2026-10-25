"""Streaming SHA-256 helpers — hash data as it's read/written rather than in a second pass
over the whole file."""
import hashlib


class StreamingHasher:
    def __init__(self):
        self._hasher = hashlib.sha256()

    def update(self, data: bytes) -> None:
        self._hasher.update(data)

    def hexdigest(self) -> str:
        return self._hasher.hexdigest()


def content_signature(chunk_hashes: list[str]) -> str:
    """Whole-file integrity signature: sha256 of the concatenation of per-chunk sha256
    hex digests. Cheap to verify (no need to rehash gigabytes of reassembled data) while
    still detecting a missing, reordered, or corrupted chunk."""
    h = hashlib.sha256()
    for digest in chunk_hashes:
        h.update(digest.encode())
    return h.hexdigest()
