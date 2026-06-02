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
        except Exception:
            self.handleError(record)

    def get_entries(self, after_id: int = 0, limit: int = 200) -> list[dict]:
        """Return log entries with id > *after_id*, newest last."""
        with self._lock:
            if after_id <= 0:
                return list(self._buffer)[-limit:]
            return [e for e in self._buffer if e["id"] > after_id][-limit:]

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()


def get_buffer_handler() -> BufferHandler | None:
    """Find the BufferHandler attached to the root logger (if any)."""
    for handler in logging.getLogger().handlers:
        if isinstance(handler, BufferHandler):
            return handler
    return None
