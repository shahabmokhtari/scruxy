"""Regression tests for Round 49 hardening fixes (C1-C8).

Per the user's three guardrails:
1. Don't add new code paths in fixes when possible.
2. Tests MUST exercise the production code path, not just helpers.
3. Treat each fix as itself reviewable code.

Tests intentionally drive the integration paths (`SessionTokenMapView`,
the actual API endpoints, the actual deanonymize flow) rather than the
isolated helpers — round 48 had a test that passed against the helper
but missed the production wrapper, exactly the cosmetic-fix pattern
this round was filed for.
"""
from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest


# ---------------------------------------------------------------------------
# C1 — Strict decompress bomb cap reachable
# ---------------------------------------------------------------------------

class TestC1_BombCapReachable:
    """Round 48's B6 rewrite removed `max_length` from `decompress()`,
    making `_DECOMPRESS_LIMIT` unreachable.  This test asserts that
    a real compression bomb actually trips the cap."""

    def test_gzip_bomb_does_not_oom(self):
        from scruxy.proxy.routes import (
            _decompress_body_strict, DecompressFailed, _DECOMPRESS_LIMIT,
        )
        # Build a 1 KB gzip body that decompresses to LIMIT + 64 MiB.
        # Without the C1 fix this would allocate the full output before
        # the cap fires.  With the fix the cap is checked per-chunk.
        bomb = gzip.compress(b"A" * (_DECOMPRESS_LIMIT + 64 * 1024 * 1024))
        # The compressed form should be tiny relative to the expansion.
        assert len(bomb) < 1024 * 1024, f"test bomb too large: {len(bomb)}"
        with pytest.raises(DecompressFailed):
            _decompress_body_strict(bomb, "gzip")

    def test_decompress_eof_required(self):
        """Truncated gzip footer must NOT be silently accepted (C8 in routes)."""
        from scruxy.proxy.routes import _decompress_body_strict, DecompressFailed
        original = gzip.compress(b'{"x":"alice@example.com"}')
        # Strip last 5 bytes (CRC + size in gzip footer).
        truncated = original[:-5]
        with pytest.raises(DecompressFailed):
            _decompress_body_strict(truncated, "gzip")

    def test_forward_proxy_bomb_cap(self):
        """The forward-proxy decompress helper must also enforce the cap."""
        from scruxy.proxy.forward_proxy import _decompress_body, DecompressLimitExceeded
        bomb = gzip.compress(b"A" * (50 * 1024 * 1024 + 64 * 1024))  # > _MAX_BODY_SIZE
        with pytest.raises(DecompressLimitExceeded):
            _decompress_body(bomb, "gzip", strict=True)


# ---------------------------------------------------------------------------
# C2 — SessionTokenMapView exposes sub-token aliases (production path)
# ---------------------------------------------------------------------------

class TestC2_SessionViewSubtokenAliases:
    """The B3 fix added per-sub-token aliases to TokenMap._unscrub but
    the production response path uses SessionTokenMapView, which
    rebuilds unscrub_map from _session_pii × _scrub and dropped the
    aliases.  This test drives the PRODUCTION path."""

    @pytest.mark.asyncio
    async def test_session_view_includes_sub_token_aliases(self, tmp_path):
        from scruxy.tokenmap.service import ConcurrentSessionStore

        class _PerWordStrategy:
            def generate(self, entity_type, pii, count):
                words = pii.split()
                if len(words) <= 1:
                    return f"REDACTED_{entity_type}_{count}"
                return " ".join(
                    f"REDACTED_{entity_type}_{count}{chr(ord('A') + i)}"
                    for i in range(len(words))
                )

        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            replacements={"PERSON": _PerWordStrategy()},
            persistent=False,
        )
        await store.start()
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("Alice Smith", "PERSON")
            store.tag_session_pii("s1", {"Alice Smith"})

            view = store.get_session_token_map("s1")
            unscrub = view.unscrub_map
            # Joint mapping must be visible.
            assert unscrub.get("REDACTED_PERSON_1A REDACTED_PERSON_1B") == "Alice Smith"
            # And the aliases (this is the C2 fix).
            assert unscrub.get("REDACTED_PERSON_1A") == "Alice"
            assert unscrub.get("REDACTED_PERSON_1B") == "Smith"
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_deanonymize_through_session_view(self, tmp_path):
        """End-to-end: the deanonymize_text helper called with a
        session-scoped view must restore single sub-tokens."""
        from scruxy.tokenmap.service import ConcurrentSessionStore
        from scruxy.scrubber.response_unscrubber import deanonymize_text

        class _PerWordStrategy:
            def generate(self, entity_type, pii, count):
                words = pii.split()
                if len(words) <= 1:
                    return f"REDACTED_{entity_type}_{count}"
                return " ".join(
                    f"REDACTED_{entity_type}_{count}{chr(ord('A') + i)}"
                    for i in range(len(words))
                )

        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            replacements={"PERSON": _PerWordStrategy()},
            persistent=False,
        )
        await store.start()
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("Alice Smith", "PERSON")
            store.tag_session_pii("s1", {"Alice Smith"})

            view = store.get_session_token_map("s1")
            # Production response unscrub uses this view + deanonymize_text.
            out = deanonymize_text("Hi REDACTED_PERSON_1A, are you Smith?", view)
            assert "Alice" in out, (
                f"Sub-token must restore via session view (C2 fix); got {out!r}"
            )
            assert "REDACTED_PERSON_1A" not in out
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_session_view_get_pii_allows_subtoken(self, tmp_path):
        from scruxy.tokenmap.service import ConcurrentSessionStore

        class _PerWordStrategy:
            def generate(self, entity_type, pii, count):
                words = pii.split()
                if len(words) <= 1:
                    return f"REDACTED_{entity_type}_{count}"
                return " ".join(
                    f"REDACTED_{entity_type}_{count}{chr(ord('A') + i)}"
                    for i in range(len(words))
                )

        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            replacements={"PERSON": _PerWordStrategy()},
            persistent=False,
        )
        await store.start()
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("Alice Smith", "PERSON")
            store.tag_session_pii("s1", {"Alice Smith"})

            view = store.get_session_token_map("s1")
            # get_pii() should now allow sub-tokens whose joint token
            # belongs to a session-tagged PII.
            assert view.get_pii("REDACTED_PERSON_1A REDACTED_PERSON_1B") == "Alice Smith"
            assert view.get_pii("REDACTED_PERSON_1A") == "Alice"
            assert view.get_pii("REDACTED_PERSON_1B") == "Smith"
            # A sub-token that doesn't align with the session's tagged
            # PII must still be rejected.
            assert view.get_pii("REDACTED_PERSON_99A") is None
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# C3 — Presidio cache key includes post-filter rules fingerprint
# ---------------------------------------------------------------------------

class TestC3_PostFilterFingerprintInCacheKey:
    def test_changing_rules_invalidates_cache(self):
        """A reconfigure that changes only the post-filter rules
        content (without flipping the enabled toggle) must invalidate
        the cache so stale results don't slip through."""
        from scruxy.plugin.presidio import PresidioPlugin
        plugin = PresidioPlugin()
        plugin.setup({
            "enabled": True, "language": "en",
            "entities": ["EMAIL_ADDRESS"], "score_threshold": 0.6,
            "post_filter": True,
            "post_filter_rules": "EMAIL_ADDRESS:\n  reject_substring:\n    - 'noreply@'",
        })
        text = "contact alice@example.com about it"
        _ = plugin.detect(text)
        misses_before = plugin._cache_misses

        # Same text again → cache hit.
        _ = plugin.detect(text)
        assert plugin._cache_misses == misses_before, "should hit cache"

        # Reconfigure the rules CONTENT only.  Cache key must invalidate.
        plugin._post_filter_rules_fingerprint = hashlib.md5(
            b"EMAIL_ADDRESS:\n  reject_substring:\n    - 'different@'"
        ).hexdigest()[:16]

        _ = plugin.detect(text)
        assert plugin._cache_misses > misses_before, (
            "Changing post-filter rules content must invalidate cache (C3)"
        )


# ---------------------------------------------------------------------------
# C4 — `_read_chunked_body` returns leftover for pipelining
# ---------------------------------------------------------------------------

class TestC4_ChunkedBodyReturnsLeftover:
    @pytest.mark.asyncio
    async def test_returns_tuple_with_leftover(self):
        """The helper must return (body, leftover) so the MITM keep-alive
        loop can carry pipelined-request bytes forward."""
        from scruxy.proxy.forward_proxy import _read_chunked_body

        # Build a chunked body followed by the start of a NEXT request.
        # Format: "5\r\nhello\r\n0\r\n\r\n" then "GET /next ..."
        chunked = b"5\r\nhello\r\n0\r\n\r\n"
        next_req = b"GET /next HTTP/1.1\r\nHost: x\r\n\r\n"
        wire = chunked + next_req

        reader = asyncio.StreamReader()
        reader.feed_data(wire)
        reader.feed_eof()

        body, leftover = await _read_chunked_body(reader, b"")
        assert body == b"hello"
        assert leftover == next_req, (
            f"leftover must contain the next pipelined request (C4); got {leftover!r}"
        )

    @pytest.mark.asyncio
    async def test_returns_empty_leftover_when_clean(self):
        from scruxy.proxy.forward_proxy import _read_chunked_body
        wire = b"5\r\nhello\r\n0\r\n\r\n"
        reader = asyncio.StreamReader()
        reader.feed_data(wire)
        reader.feed_eof()
        body, leftover = await _read_chunked_body(reader, b"")
        assert body == b"hello"
        assert leftover == b""


# ---------------------------------------------------------------------------
# C5 — Presidio _setup_lock initialized at __init__
# ---------------------------------------------------------------------------

class TestC5_SetupLockEager:
    def test_lock_exists_at_construction(self):
        """The lock must exist BEFORE any thread can call setup() —
        the lazy `if not hasattr` pattern was itself non-atomic."""
        from scruxy.plugin.presidio import PresidioPlugin
        plugin = PresidioPlugin()
        # Lock must be present and reentrant.
        assert hasattr(plugin, "_setup_lock")
        with plugin._setup_lock:
            with plugin._setup_lock:
                pass

    def test_concurrent_first_setup_uses_same_lock(self):
        """Two threads racing on the very first setup() must share
        the same lock object, never see lock identity flip."""
        from scruxy.plugin.presidio import PresidioPlugin
        plugin = PresidioPlugin()
        lock_id = id(plugin._setup_lock)

        seen_ids: list[int] = []

        def _setup_call():
            seen_ids.append(id(plugin._setup_lock))

        threads = [threading.Thread(target=_setup_call) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert all(i == lock_id for i in seen_ids), (
            f"Lock identity drifted: {set(seen_ids)} != {lock_id}"
        )


# ---------------------------------------------------------------------------
# C6 — Cert gen-lock eviction skips held locks
# ---------------------------------------------------------------------------

class TestC6_GenLockEvictionSkipsHeld:
    def test_held_lock_is_not_evicted(self, tmp_path):
        """A gen-lock currently held by another thread must NOT be
        evicted — evicting it would let a subsequent thread create a
        DIFFERENT lock for the same hostname, defeating the dedup."""
        from scruxy.cert.ca import CertificateAuthority
        ca = CertificateAuthority(tmp_path)
        ca._host_cache_max = 2

        # Manually pre-populate gen_locks with a held lock for "held.example.com".
        held_lock = threading.Lock()
        held_lock.acquire()
        ca._host_gen_locks["held.example.com"] = held_lock

        try:
            # Now flood with unique hostnames to trigger eviction.
            for i in range(40):
                ca.get_host_cert(f"flood{i}.example.com")

            # The held lock MUST still be in the dict (it wasn't evictable).
            assert ca._host_gen_locks.get("held.example.com") is held_lock, (
                "Held lock was evicted (C6 regression)"
            )
        finally:
            held_lock.release()


# ---------------------------------------------------------------------------
# C7 — UI SSE counter bound to generator lifecycle
# ---------------------------------------------------------------------------

class TestC7_SseCounterBoundToGenerator:
    @pytest.mark.asyncio
    async def test_increment_inside_generator(self):
        """The counter increment must happen INSIDE the generator's
        try/finally so any exception between the route return and
        the first __anext__ doesn't leak a count."""
        from scruxy.ui import routes as ui_routes
        baseline = ui_routes._ui_sse_active_count

        class _FakeReq:
            class app:
                class state:
                    _listen_host = "127.0.0.1"
            class url:
                path = "/ui/api/events"
            client = None
            method = "GET"
            headers = {"host": "testserver"}
            async def is_disconnected(self):
                return True

        # Get the response (this used to increment under the OLD code).
        resp = await ui_routes.api_events(_FakeReq())  # type: ignore[arg-type]
        # Counter MUST still be at baseline — increment moved INTO the
        # generator (C7).
        assert ui_routes._ui_sse_active_count == baseline, (
            f"Counter incremented outside generator (C7 regression). "
            f"baseline={baseline}, now={ui_routes._ui_sse_active_count}"
        )
        # Now drain the generator and confirm increment + decrement balance.
        try:
            async for _ in resp.body_iterator:
                pass
        except Exception:
            pass
        assert ui_routes._ui_sse_active_count == baseline


# ---------------------------------------------------------------------------
# C8 — Multi-member gzip + EOF check in BOTH proxy paths
# ---------------------------------------------------------------------------

class TestC8_ForwardProxyGzipParity:
    def test_forward_proxy_handles_multi_member_gzip(self):
        from scruxy.proxy.forward_proxy import _decompress_body
        out = _decompress_body(
            gzip.compress(b"hello ") + gzip.compress(b"world"),
            "gzip",
            strict=True,
        )
        assert out == b"hello world", (
            f"Multi-member gzip not supported in forward proxy (C8); got {out!r}"
        )

    def test_forward_proxy_rejects_truncated_gzip_in_strict(self):
        from scruxy.proxy.forward_proxy import _decompress_body, DecompressLimitExceeded
        original = gzip.compress(b'{"x":"alice@example.com"}')
        truncated = original[:-5]  # strip CRC + size from gzip footer
        with pytest.raises(DecompressLimitExceeded):
            _decompress_body(truncated, "gzip", strict=True)

    def test_forward_proxy_lenient_truncated_gzip_returns_raw(self):
        """Lenient mode: truncated gzip must NOT silently produce
        partial plaintext (GPT-5.5 forward-proxy residual).  Returning
        the raw bytes lets the caller's `decompressed is body` check
        flag `_decompress_failed=True`, so matched providers fail
        closed even though we read the body in lenient mode."""
        from scruxy.proxy.forward_proxy import _decompress_body
        original = gzip.compress(b'{"x":"alice@example.com"}')
        truncated = original[:-5]
        out = _decompress_body(truncated, "gzip", strict=False)
        # MUST equal raw bytes, NOT the partial decoded plaintext.
        assert out == truncated, (
            "Lenient mode must return raw bytes for truncated gzip so the "
            "caller's `_decompress_failed` plumbing fires the matched-provider 413"
        )

    @pytest.mark.asyncio
    async def test_handle_http_truncated_gzip_returns_413(self):
        """End-to-end: drive `_handle_http` with a matched provider +
        truncated gzip and assert the proxy returns 413 + does NOT
        forward upstream.  This is the production path GPT-5.5 said
        the unit test bypassed."""
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        provider = MagicMock()
        provider.name = "anthropic"
        provider.upstream_url = "https://api.example.com"
        provider.extract_session_id = MagicMock(return_value="s1")

        registry = MagicMock()
        registry.match = MagicMock(return_value=provider)
        registry.match_disabled = MagicMock(return_value=None)

        token_map = MagicMock()
        session_store = MagicMock()
        session_store.get_or_create_session = AsyncMock(return_value=token_map)

        server = ForwardProxyServer(
            host="127.0.0.1", port=0, ca=MagicMock(),
            registry=registry, pipeline=MagicMock(),
            session_store=session_store,
            request_scrubber=MagicMock(), response_unscrubber=MagicMock(),
        )
        # Sentinel: must NOT be called.
        forward_calls: list = []
        async def _no_forward(*a, **kw):
            forward_calls.append((a, kw))
            return (502, {}, b"unexpected")
        server._plain_forward = _no_forward  # type: ignore[assignment]

        body = gzip.compress(b'{"messages":[]}')[:-5]  # truncated footer
        reader = asyncio.StreamReader(limit=1024 * 1024)
        reader.feed_eof()

        written: bytearray = bytearray()
        class _FakeWriter:
            def write(self, data):
                written.extend(data)
            async def drain(self):
                pass
            def close(self):
                pass
            async def wait_closed(self):
                pass
            def is_closing(self):
                return False
            def get_extra_info(self, *a, **kw):
                return None

        await asyncio.wait_for(
            server._handle_http(
                method="POST",
                target="https://api.example.com/v1/messages",
                headers={
                    "host": "api.example.com",
                    "content-length": str(len(body)),
                    "content-encoding": "gzip",
                    "content-type": "application/json",
                    "connection": "close",
                },
                reader=reader,
                writer=_FakeWriter(),  # type: ignore[arg-type]
                leftover=body,
            ),
            timeout=5.0,
        )
        wire = bytes(written)
        assert b"413" in wire, f"Expected 413; got {wire[:200]!r}"
        assert forward_calls == [], (
            "Truncated gzip must NOT reach upstream forwarder "
            f"(C8 forward-proxy residual): {len(forward_calls)} call(s)"
        )
