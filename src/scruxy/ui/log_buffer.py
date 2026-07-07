"""In-memory ring-buffer logging handler for the UI logs tab."""
from __future__ import annotations

import logging
import threading
from collections import deque


class BufferHandler(logging.Handler):
    """Logging handler that stores the last *capacity* formatted log records.

    Thread-safe.  Used by the UI logs API endpoint to serve recent
    application logs without requiring file access.
    """

    def __init__(self, capacity: int = 500) -> None:
        super().__init__()
        self._buffer: deque[dict] = deque(maxlen=capacity)
        # A dedicated buffer for WARNING+ records.  The main buffer is
        # shared across all levels and, under the INFO-level firehose a
        # busy proxy emits (per-stage pipeline timings, per-request
        # forward logs, ...), warnings/errors are evicted within seconds
        # -- so they often vanish from the UI Logs tab before anyone
        # looks.  Retaining them separately guarantees they survive the
        # flood and remain visible regardless of INFO volume.
        self._warn_buffer: deque[dict] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._seq = 0

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = {
                "id": self._seq,
                "ts": record.created,
                "level": record.levelname,
                "logger": record.name,
                "message": self.format(record),
            }
            with self._lock:
                self._seq += 1
                entry["id"] = self._seq
                self._buffer.append(entry)
                if record.levelno >= logging.WARNING:
                    self._warn_buffer.append(entry)
        except Exception:
            self.handleError(record)

    def get_entries(self, after_id: int = 0, limit: int = 200) -> list[dict]:
        """Return log entries with id > *after_id*, newest last.

        Merges the all-levels buffer with the dedicated WARNING+ buffer
        (deduplicated by id) so warnings/errors remain visible even after
        they have been evicted from the INFO-flooded main buffer.  When the
        result exceeds *limit*, WARNING+ records are retained preferentially
        so a flood of newer INFO records can never truncate them away.
        """
        with self._lock:
            main = list(self._buffer)
            warns = list(self._warn_buffer)
        if after_id > 0:
            main = [e for e in main if e["id"] > after_id]
            warns = [e for e in warns if e["id"] > after_id]
        merged: dict[int, dict] = {e["id"]: e for e in main}
        for e in warns:
            merged[e["id"]] = e
        entries = sorted(merged.values(), key=lambda e: e["id"])
        if len(entries) <= limit:
            return entries
        # Truncation needed: keep WARNING+ entries (newest ``limit`` at most)
        # and fill the remaining budget with the newest other records, so
        # warnings survive the INFO firehose this buffer exists to surface.
        warn_ids = {e["id"] for e in warns}
        warn_entries = [e for e in entries if e["id"] in warn_ids]
        other_entries = [e for e in entries if e["id"] not in warn_ids]
        if len(warn_entries) >= limit:
            kept = warn_entries[-limit:]
        else:
            budget = limit - len(warn_entries)
            kept = warn_entries + other_entries[-budget:]
        return sorted(kept, key=lambda e: e["id"])

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
            self._warn_buffer.clear()


def get_buffer_handler() -> BufferHandler | None:
    """Find the BufferHandler attached to the root logger (if any)."""
    for handler in logging.getLogger().handlers:
        if isinstance(handler, BufferHandler):
            return handler
    return None
