"""Streaming download for chunked files: chains each Telegram document's bytes in part
order, with HTTP Range support that maps a byte window across chunk boundaries. No merge
to a temp file — bytes flow straight from Telegram to the HTTP response, same as the
existing single-message download path.
"""
import logging
import time
from typing import AsyncIterator, Optional
from uuid import UUID

from backend.database import get_file_chunks_ordered, FileChunk

logger = logging.getLogger(__name__)

# Telegram's per-request ceiling. Every request is a full round trip to the DC, so on a
# high-latency link (e.g. a deployed backend far from the account's home DC) request size
# directly sets the streaming throughput ceiling — 1 MiB halves the round trips vs
# Telethon's 512 KiB default.
REQUEST_SIZE = 1024 * 1024

# message_id -> (expires_at, media). A playing video issues many Range requests, and each
# used to cost a get_messages round trip before the first byte could flow. File references
# inside media expire server-side (~1h), so entries are kept well under that.
_media_cache: dict[int, tuple[float, object]] = {}
_MEDIA_TTL_SECONDS = 300


class ChunkPlan:
    """A file's ordered chunks with each one's starting byte offset in the logical file."""

    def __init__(self, chunks: list[FileChunk]):
        self.chunks = chunks
        self.offsets: list[int] = []
        total = 0
        for c in chunks:
            self.offsets.append(total)
            total += c.size
        self.total_size = total


def build_plan(file_id: UUID) -> Optional[ChunkPlan]:
    chunks = get_file_chunks_ordered(file_id)
    if not chunks:
        return None
    return ChunkPlan(chunks)


async def _get_media(client, chunk: FileChunk):
    cached = _media_cache.get(chunk.telegram_message_id)
    if cached and cached[0] > time.monotonic():
        return cached[1]

    message = await client.get_messages("me", ids=chunk.telegram_message_id)
    if not message or not message.file:
        raise Exception(f"Chunk part {chunk.part_number} (message {chunk.telegram_message_id}) is unavailable")
    _media_cache[chunk.telegram_message_id] = (time.monotonic() + _MEDIA_TTL_SECONDS, message.media)
    return message.media


async def iter_exact(client, media, offset: int, length: int) -> AsyncIterator[bytes]:
    """Yields exactly `length` bytes starting at `offset` within `media`.

    Telethon's `iter_download` is lazy — it only makes a network request when asked for
    the next chunk, so simply stopping once enough bytes are collected (rather than trying
    to pass a byte count via its `limit`, which actually counts *chunks*, not bytes) is both
    correct and avoids any wasted fetching.
    """
    if length <= 0:
        return
    remaining = length
    async for data in client.iter_download(media, offset=offset, request_size=REQUEST_SIZE):
        if len(data) >= remaining:
            yield data[:remaining]
            return
        yield data
        remaining -= len(data)


async def stream_full(client, plan: ChunkPlan) -> AsyncIterator[bytes]:
    """Streams every chunk in order, start to finish."""
    for chunk in plan.chunks:
        media = await _get_media(client, chunk)
        async for data in client.iter_download(media, request_size=REQUEST_SIZE):
            yield data


async def stream_range(client, plan: ChunkPlan, start: int, end: int) -> AsyncIterator[bytes]:
    """Streams bytes [start, end] (inclusive) of the logical file, spanning chunk boundaries."""
    for i, chunk in enumerate(plan.chunks):
        chunk_start = plan.offsets[i]
        chunk_end = chunk_start + chunk.size - 1
        if chunk_end < start or chunk_start > end:
            continue  # entirely outside the requested window

        local_start = max(0, start - chunk_start)
        local_end = min(chunk.size - 1, end - chunk_start)
        local_length = local_end - local_start + 1

        media = await _get_media(client, chunk)
        async for data in iter_exact(client, media, local_start, local_length):
            yield data
