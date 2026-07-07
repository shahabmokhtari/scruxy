"""Tests for the UI log ring-buffer handler (WARNING+ retention)."""
from __future__ import annotations

import logging

from scruxy.ui.log_buffer import BufferHandler


def _record(level: int, msg: str, name: str = "test") -> logging.LogRecord:
    return logging.LogRecord(
        name=name, level=level, pathname=__file__, lineno=1,
        msg=msg, args=(), exc_info=None,
    )


def test_warnings_survive_info_flood() -> None:
    """A WARNING must remain retrievable even after the all-levels buffer
    has been fully cycled by a flood of INFO records."""
    handler = BufferHandler(capacity=10)
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_record(logging.WARNING, "blocked SSRF to 127.0.0.1"))
    # Flood well beyond capacity with INFO records.
    for i in range(100):
        handler.emit(_record(logging.INFO, f"pipeline {i}"))

    messages = [e["message"] for e in handler.get_entries(limit=500)]
    assert "blocked SSRF to 127.0.0.1" in messages
    # The main buffer (capacity 10) should have dropped early INFO records.
    assert "pipeline 0" not in messages


def test_warnings_survive_small_limit_truncation() -> None:
    """WARNING+ records must survive even when the returned page is capped
    by a small ``limit`` and a flood of newer INFO records exists."""
    handler = BufferHandler(capacity=500)
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_record(logging.WARNING, "early-warning"))
    for i in range(400):
        handler.emit(_record(logging.INFO, f"info {i}"))

    # Small limit; the warning is an OLD entry buried under newer INFO.
    messages = [e["message"] for e in handler.get_entries(limit=50)]
    assert "early-warning" in messages
    assert len(messages) <= 50


def test_get_entries_no_duplicates_for_warning() -> None:
    """A warning present in both buffers must appear only once."""
    handler = BufferHandler(capacity=50)
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_record(logging.WARNING, "warn-1"))
    handler.emit(_record(logging.INFO, "info-1"))

    entries = handler.get_entries(limit=500)
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids))  # no dup ids
    assert [e["message"] for e in entries] == ["warn-1", "info-1"]


def test_get_entries_incremental_after_id() -> None:
    """``after_id`` returns only newer entries, preserving ascending order."""
    handler = BufferHandler(capacity=50)
    handler.setFormatter(logging.Formatter("%(message)s"))

    for i in range(5):
        handler.emit(_record(logging.INFO, f"m{i}"))
    all_entries = handler.get_entries(limit=500)
    third_id = all_entries[2]["id"]

    newer = handler.get_entries(after_id=third_id, limit=500)
    assert [e["message"] for e in newer] == ["m3", "m4"]


def test_clear_empties_both_buffers() -> None:
    handler = BufferHandler(capacity=50)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.emit(_record(logging.WARNING, "warn"))
    handler.emit(_record(logging.INFO, "info"))
    handler.clear()
    assert handler.get_entries(limit=500) == []
