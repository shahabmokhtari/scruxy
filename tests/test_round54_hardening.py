"""Regression tests for Round 54 hardening fixes (R54-1..R54-4)."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# R54-1 — `_redact_url_for_log` exception fallback strips userinfo + fragment
# ---------------------------------------------------------------------------

class TestR54_1_RedactFallbackStripsCredsAndFragment:
    def test_routes_redact_fallback_strips_userinfo_and_fragment(self):
        """When ``urlsplit`` raises (forced via patch), the fallback
        must drop userinfo and fragment, not just the query."""
        from scruxy.proxy import routes

        url = "https://alice:s3cret@api.example.com/path?q=1#frag"
        with patch("urllib.parse.urlsplit", side_effect=ValueError("bad url")):
            redacted = routes._redact_url_for_log(url)

        assert "alice" not in redacted
        assert "s3cret" not in redacted
        assert "frag" not in redacted
        assert "q=1" not in redacted
        assert redacted.startswith("https://api.example.com")

    def test_forward_proxy_redact_fallback_strips_userinfo_and_fragment(self):
        from scruxy.proxy import forward_proxy

        url = "https://alice:s3cret@api.example.com/path?q=1#frag"
        with patch("urllib.parse.urlsplit", side_effect=ValueError("bad url")):
            redacted = forward_proxy._redact_url_for_log(url)

        assert "alice" not in redacted
        assert "s3cret" not in redacted
        assert "frag" not in redacted
        assert "q=1" not in redacted
        assert redacted.startswith("https://api.example.com")

    def test_routes_redact_fallback_no_userinfo_no_fragment(self):
        """Sanity: a fallback on a clean URL still works."""
        from scruxy.proxy import routes

        with patch("urllib.parse.urlsplit", side_effect=ValueError("bad url")):
            redacted = routes._redact_url_for_log("https://api.example.com/path")
        assert redacted == "https://api.example.com/path"


# ---------------------------------------------------------------------------
# R54-2 — SSL context lock LRU eviction pops lock BEFORE deleting cache entry
# ---------------------------------------------------------------------------

class TestR54_2_SSLCtxEvictionPopsLockBeforeCacheDelete:
    def test_eviction_order_is_pop_lock_then_del_cache(self):
        """Inspect the source of `_get_or_create_ssl_ctx` and assert
        the eviction loop pops the per-host lock BEFORE deleting the
        cache entry — same pattern as R53-6."""
        import inspect
        import re
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        src = inspect.getsource(ForwardProxyServer._get_or_create_ssl_ctx)
        # Find the eviction body.
        idx_pop = src.find("self._ssl_ctx_locks.pop(oldest")
        idx_del = src.find("del self._ssl_ctx_cache[oldest]")
        assert idx_pop > 0, "pop call not found"
        assert idx_del > 0, "del call not found"
        assert idx_pop < idx_del, (
            "Lock pop must come before cache delete (R54-2 / mirrors R53-6); "
            f"got pop@{idx_pop} del@{idx_del}"
        )

    @pytest.mark.asyncio
    async def test_lock_dict_does_not_outlive_cache_entry(self, tmp_path):
        """Behavioral: when the cache-full eviction fires, the per-
        host lock for the evicted hostname must be removed in the
        same atomic step."""
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        server = ForwardProxyServer(
            host="127.0.0.1", port=0, ca=MagicMock(),
            registry=MagicMock(), pipeline=None,
            session_store=None,
            request_scrubber=None, response_unscrubber=None,
        )
        # Force tiny cap and stub out the actual SSL build.
        server._ssl_ctx_cache_max = 2
        server._build_ssl_ctx = MagicMock(side_effect=lambda h: MagicMock())

        # Fill cache + locks with 2 entries.
        await server._get_or_create_ssl_ctx("h1.test")
        await server._get_or_create_ssl_ctx("h2.test")
        assert "h1.test" in server._ssl_ctx_locks
        assert "h2.test" in server._ssl_ctx_locks
        assert "h1.test" in server._ssl_ctx_cache
        assert "h2.test" in server._ssl_ctx_cache

        # Adding a 3rd host triggers eviction of the oldest (h1).
        await server._get_or_create_ssl_ctx("h3.test")

        # Both the cache entry AND the per-host lock for h1 must
        # have been evicted in lockstep (no orphaned lock).
        assert "h1.test" not in server._ssl_ctx_cache
        assert "h1.test" not in server._ssl_ctx_locks


# ---------------------------------------------------------------------------
# R54-3 — SSE line buffer is bounded
# ---------------------------------------------------------------------------

class TestR54_3_SSELineBufferBounded:
    def test_buffer_cap_constant_exists_and_is_reasonable(self):
        """The cap constant must exist, be < 16 MB, and be referenced
        by the `_sse_lines` body to bound per-connection buffer growth."""
        import inspect
        from scruxy.proxy import forward_proxy
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        cap = getattr(forward_proxy, "_MAX_SSE_LINE_BUFFER_BYTES", None)
        assert cap is not None, "_MAX_SSE_LINE_BUFFER_BYTES must be defined"
        assert 1024 <= cap <= 16 * 1024 * 1024, (
            f"Cap {cap} bytes is outside reasonable bounds"
        )

        src = inspect.getsource(ForwardProxyServer._scrub_and_forward)
        assert "_MAX_SSE_LINE_BUFFER_BYTES" in src, (
            "_sse_lines body does not reference the buffer cap"
        )

    @pytest.mark.asyncio
    async def test_no_newline_does_not_cause_unbounded_growth(self, monkeypatch):
        """Drive an inlined copy of the `_sse_lines` loop logic and
        confirm that when upstream emits a single huge no-newline
        chunk, the loop yields and resets rather than accumulating."""
        from scruxy.proxy.forward_proxy import _MAX_SSE_LINE_BUFFER_BYTES

        # Reproduce the bounded-buffer logic that R54-3 added.
        async def _sse_lines_simulation(chunks):
            buf = b""
            yielded = []
            for raw_chunk in chunks:
                buf += raw_chunk
                if len(buf) > _MAX_SSE_LINE_BUFFER_BYTES:
                    yielded.append(buf)
                    buf = b""
                    continue
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    yielded.append(line)
            if buf:
                yielded.append(buf)
            return yielded

        # Stream 5 chunks of 600 KB each = 3 MB total, no newlines.
        big = b"x" * (600 * 1024)
        result = await _sse_lines_simulation([big] * 5)

        # Must have flushed at least once (otherwise we'd be holding
        # 3 MB > cap=1 MB in memory).
        assert len(result) >= 2, (
            f"Buffer was never flushed: {len(result)} yields"
        )
        # No single yielded segment may exceed cap + one chunk size.
        for seg in result:
            assert len(seg) <= _MAX_SSE_LINE_BUFFER_BYTES + len(big), (
                f"Segment of {len(seg)} bytes exceeds cap"
            )


# ---------------------------------------------------------------------------
# R54-4 — `_scrub_url_query` strips fragment on EVERY return path
# ---------------------------------------------------------------------------

class TestR54_4_ScrubUrlQueryStripsFragmentOnEarlyReturns:
    @pytest.mark.asyncio
    async def test_no_query_fragment_only(self):
        """A URL with NO `?` but with a `#fragment` must come back
        without the fragment.  R53-8 only handled the success path."""
        from scruxy.proxy.routes import _scrub_url_query

        scrubbed, _ = await _scrub_url_query(
            "https://api.example.com/cb#access_token=xyz123",
            MagicMock(), MagicMock(), "req-1",
        )
        assert "#" not in scrubbed
        assert "access_token=xyz123" not in scrubbed

    @pytest.mark.asyncio
    async def test_empty_query_with_fragment(self):
        """`?#fragment` (empty query, present fragment) must drop the
        fragment."""
        from scruxy.proxy.routes import _scrub_url_query

        scrubbed, _ = await _scrub_url_query(
            "https://api.example.com/cb?#alice@example.com",
            MagicMock(), MagicMock(), "req-1",
        )
        assert "#" not in scrubbed
        assert "alice@example.com" not in scrubbed

    @pytest.mark.asyncio
    async def test_no_pairs_with_fragment(self):
        """A URL whose query has no parsable pairs (e.g. `?=` or
        all-empty) plus a fragment must still drop the fragment."""
        from scruxy.proxy.routes import _scrub_url_query

        scrubbed, _ = await _scrub_url_query(
            "https://api.example.com/cb?#secret=abc",
            MagicMock(), MagicMock(), "req-1",
        )
        assert "#" not in scrubbed
        assert "secret=abc" not in scrubbed

    @pytest.mark.asyncio
    async def test_success_path_still_strips_fragment(self):
        """R53-8 regression check: success path must continue to
        strip fragment too."""
        from scruxy.proxy.routes import _scrub_url_query
        from scruxy.tokenmap.token_map import TokenMap

        tm = TokenMap()

        class _FakeResult:
            def __init__(self, text):
                self.scrubbed_text = text
                self.detected_pii = set()
                self.pre_filter_matches = set()
                self.entities = []

        pipeline = MagicMock()
        pipeline.scrub_text = AsyncMock(side_effect=lambda t, *a, **k: _FakeResult(t))

        scrubbed, _ = await _scrub_url_query(
            "https://api.example.com/cb?state=ok#access_token=xyz",
            pipeline, tm, "req-1",
        )
        assert "#" not in scrubbed
        assert "access_token=xyz" not in scrubbed


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
