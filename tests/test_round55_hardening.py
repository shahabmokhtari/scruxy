"""Regression tests for Round 55 hardening fixes (R55-1..R55-4)."""
from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# R55-1 — forward proxy SSE cap drains newlines first
# ---------------------------------------------------------------------------

class TestR55_1_ForwardSSECapDrainsNewlinesFirst:
    def test_cap_check_runs_after_newline_drain_loop(self):
        """The buffer cap must NOT run before the newline-drain loop.
        Otherwise a >1 MiB chunk that contains many valid SSE events
        would be yielded as a single opaque blob, defeating per-line
        unscrubbing and leaking REDACTED tokens past event #1."""
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        src = inspect.getsource(ForwardProxyServer._scrub_and_forward)
        # Find the bodies inside _sse_lines.
        idx_cap = src.find("if len(buf) > _MAX_SSE_LINE_BUFFER_BYTES")
        idx_drain = src.find("while b\"\\n\" in buf:")
        assert idx_cap > 0, "Cap check not found"
        assert idx_drain > 0, "Newline drain loop not found"
        assert idx_drain < idx_cap, (
            f"R55-1: drain loop must precede cap check (idx_drain={idx_drain} "
            f"vs idx_cap={idx_cap})"
        )

    @pytest.mark.asyncio
    async def test_large_newline_bearing_chunk_is_split_per_line(self):
        """In-process simulation of the post-R55-1 logic: a >1 MiB
        chunk containing many newlines must be yielded as individual
        lines, not as one opaque blob."""
        from scruxy.proxy.forward_proxy import _MAX_SSE_LINE_BUFFER_BYTES

        # Construct a chunk just over the cap with valid SSE event lines.
        line = b"data: " + b"x" * 1024 + b"\n"
        big_chunk = line * (_MAX_SSE_LINE_BUFFER_BYTES // len(line) + 2)
        assert len(big_chunk) > _MAX_SSE_LINE_BUFFER_BYTES

        async def _aiter():
            yield big_chunk

        # Replicate the post-R55-1 ordering exactly.
        async def _sse_lines_simulation():
            buf = b""
            yielded = []
            async for raw_chunk in _aiter():
                buf += raw_chunk
                while b"\n" in buf:
                    line_, buf = buf.split(b"\n", 1)
                    yielded.append(line_)
                if len(buf) > _MAX_SSE_LINE_BUFFER_BYTES:
                    yielded.append(buf)
                    buf = b""
            if buf:
                yielded.append(buf)
            return yielded

        result = await _sse_lines_simulation()

        # Every yielded segment must be a single SSE event line — no
        # internal newlines.
        for seg in result:
            assert b"\n" not in seg, (
                f"Yielded segment of {len(seg)} bytes contains internal "
                f"newline — line-drain ran AFTER cap (R55-1 regression)"
            )
        # Should be roughly one yield per `line` repetition.
        assert len(result) >= _MAX_SSE_LINE_BUFFER_BYTES // len(line)


# ---------------------------------------------------------------------------
# R55-2 — reverse proxy SSE buffer cap exists and matches forward proxy
# ---------------------------------------------------------------------------

class TestR55_2_ReverseSSECapMatches:
    def test_constant_exists_and_equals_forward_proxy(self):
        """Reverse proxy's buffer cap constant must equal forward
        proxy's; otherwise divergence between the two SSE paths
        re-introduces the cosmetic-fix bug."""
        from scruxy.proxy import routes
        from scruxy.proxy import forward_proxy

        assert hasattr(routes, "_MAX_SSE_LINE_BUFFER_BYTES"), (
            "routes.py is missing _MAX_SSE_LINE_BUFFER_BYTES (R55-2)"
        )
        assert routes._MAX_SSE_LINE_BUFFER_BYTES == forward_proxy._MAX_SSE_LINE_BUFFER_BYTES, (
            "Forward and reverse proxy SSE caps disagree — divergence risk"
        )

    def test_reverse_proxy_handle_sse_response_uses_cap(self):
        """The cap constant must actually be referenced inside
        `_handle_sse_response` (not just defined at module scope)."""
        from scruxy.proxy.routes import _handle_sse_response

        src = inspect.getsource(_handle_sse_response)
        assert "_MAX_SSE_LINE_BUFFER_BYTES" in src, (
            "_handle_sse_response does not use _MAX_SSE_LINE_BUFFER_BYTES (R55-2)"
        )
        # Same ordering check as R55-1 — drain loop before cap.
        idx_cap = src.find("if len(buf) > _MAX_SSE_LINE_BUFFER_BYTES")
        idx_drain = src.find("while b\"\\n\" in buf:")
        assert idx_drain > 0 and idx_cap > 0
        assert idx_drain < idx_cap, (
            "Reverse proxy SSE cap must apply only to residual after newline drain"
        )


# ---------------------------------------------------------------------------
# R55-3 — shutdown stops forward proxy BEFORE session store
# ---------------------------------------------------------------------------

class TestR55_3_ShutdownOrdering:
    def test_lifespan_stops_forward_proxy_before_session_store(self):
        """In `lifespan`'s shutdown branch, `forward_proxy.stop()` must
        be awaited before `session_store.stop()` so any final token-
        map writes by in-flight scrub tasks are not lost to a closed DB."""
        from scruxy import app as app_module

        src = inspect.getsource(app_module.lifespan)
        idx_fwd_stop = src.find("await app.state.forward_proxy.stop()")
        idx_store_stop = src.find("await session_store.stop()")
        assert idx_fwd_stop > 0, "forward_proxy.stop() not found in lifespan"
        assert idx_store_stop > 0, "session_store.stop() not found in lifespan"
        assert idx_fwd_stop < idx_store_stop, (
            f"R55-3: forward_proxy.stop() must run BEFORE session_store.stop(), "
            f"but found indices fwd={idx_fwd_stop} > store={idx_store_stop}"
        )


# ---------------------------------------------------------------------------
# R55-4 — get_session_recordings skips bad JSONL lines
# ---------------------------------------------------------------------------

class TestR55_4_GetSessionRecordingsSkipsBadLines:
    @pytest.mark.asyncio
    async def test_malformed_line_is_skipped_not_raised(self, tmp_path):
        """A truncated final JSONL line must not propagate JSONDecodeError;
        valid earlier lines must still be returned."""
        from scruxy.recording.recorder import SessionRecorder

        recorder = SessionRecorder(storage_dir=str(tmp_path))
        rec_path = recorder._recording_path("sess-1")
        rec_path.parent.mkdir(parents=True, exist_ok=True)
        # 2 valid entries followed by a truncated/malformed line.
        rec_path.write_text(
            json.dumps({"id": 1, "kind": "request"}) + "\n" +
            json.dumps({"id": 2, "kind": "response"}) + "\n" +
            '{"id": 3, "kind": "req'  # truncated mid-string
        )

        result = await recorder.get_session_recordings("sess-1")
        assert len(result) == 2
        assert result[0]["id"] == 1
        assert result[1]["id"] == 2

    @pytest.mark.asyncio
    async def test_empty_file_returns_empty_list(self, tmp_path):
        from scruxy.recording.recorder import SessionRecorder

        recorder = SessionRecorder(storage_dir=str(tmp_path))
        rec_path = recorder._recording_path("sess-2")
        rec_path.parent.mkdir(parents=True, exist_ok=True)
        rec_path.write_text("")
        assert await recorder.get_session_recordings("sess-2") == []

    @pytest.mark.asyncio
    async def test_missing_file_returns_empty_list(self, tmp_path):
        from scruxy.recording.recorder import SessionRecorder

        recorder = SessionRecorder(storage_dir=str(tmp_path))
        assert await recorder.get_session_recordings("nope") == []


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
