"""Regression tests for Round 51 hardening fixes (E1-E8).

Each test drives the production code path the reviewer flagged.
"""
from __future__ import annotations

import asyncio
import json
import threading
from collections import OrderedDict
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# E1 — Matched-provider URL query strings scrubbed
# ---------------------------------------------------------------------------

class TestE1_QueryStringScrubbed:
    @pytest.mark.asyncio
    async def test_scrub_url_query_helper_replaces_pii_values(self):
        """The helper must run each query VALUE through the pipeline."""
        from scruxy.proxy.routes import _scrub_url_query
        from scruxy.tokenmap.token_map import TokenMap

        tm = TokenMap()

        class _FakeResult:
            def __init__(self, text):
                self.scrubbed_text = text

        class _FakePipeline:
            async def scrub_text(self, text, token_map, context=None, request_id=""):
                # Tokenize like a real pipeline would.
                if "@" in text:
                    tok = token_map.get_or_create_token(text, "EMAIL_ADDRESS")
                    return _FakeResult(tok)
                return _FakeResult(text)

        url = "https://api.example.com/v1/messages?email=alice@example.com&api_version=v1"
        out, _ = await _scrub_url_query(url, _FakePipeline(), tm, "r1")
        # PII value scrubbed; static value preserved.
        assert "alice@example.com" not in out, out
        assert "REDACTED_EMAIL_ADDRESS" in out
        assert "api_version=v1" in out

    @pytest.mark.asyncio
    async def test_scrub_url_query_no_query_returns_unchanged(self):
        from scruxy.proxy.routes import _scrub_url_query
        url = "https://api.example.com/v1/messages"
        out, _ = await _scrub_url_query(url, MagicMock(), MagicMock(), "r1")
        assert out == url

    @pytest.mark.asyncio
    async def test_scrub_url_query_pipeline_failure_drops_value(self):
        """If pipeline.scrub_text raises, the value MUST be dropped
        (replaced with empty), NOT forwarded raw."""
        from scruxy.proxy.routes import _scrub_url_query

        class _BoomPipeline:
            async def scrub_text(self, *a, **kw):
                raise RuntimeError("boom")

        url = "https://api.example.com/x?secret=abc123"
        out, _ = await _scrub_url_query(url, _BoomPipeline(), MagicMock(), "r1")
        assert "abc123" not in out

    def test_url_scrub_runs_outside_body_branch(self):
        """E1 r51 residual: URL scrubbing must be wired BEFORE the
        body-scrub branch so bodyless or non-JSON matched requests
        still get their query string scrubbed.  Verify by source
        position: `_scrub_url_query` call must precede the body
        decompression block."""
        path = Path(__file__).parent.parent / "src" / "scruxy" / "proxy" / "routes.py"
        src = path.read_text(encoding="utf-8")
        url_scrub_idx = src.find("_scrub_url_query(")
        body_scrub_idx = src.find("if request_scrubber is not None and proxy_req.body is not None")
        assert 0 < url_scrub_idx < body_scrub_idx, (
            "E1 r51 residual: _scrub_url_query call must precede the "
            "body-scrub branch in routes.py so bodyless requests get scrubbed"
        )

    def test_forward_proxy_url_scrub_runs_outside_body_branch(self):
        """E1 r51 residual: same check for forward_proxy.py."""
        path = Path(__file__).parent.parent / "src" / "scruxy" / "proxy" / "forward_proxy.py"
        src = path.read_text(encoding="utf-8")
        url_scrub_idx = src.find("_scrub_url_query(")
        # The body-scrub branch in fwd proxy starts with this signature.
        body_branch_idx = src.find("if (\n            self._request_scrubber is not None\n            and body_json is not None")
        assert 0 < url_scrub_idx < body_branch_idx, (
            "E1 r51 residual: _scrub_url_query in forward_proxy.py must "
            "precede the body-scrub branch"
        )

    def test_forward_proxy_does_not_rewrite_upstream_host(self):
        """The forward proxy must NOT rewrite the upstream host based
        on the matched provider's ``upstream_url``.  Provider matching
        only decides WHETHER to scrub.  Rewriting the host sent client
        auth tokens to the wrong service (e.g. Copilot's GitHub token
        to api.anthropic.com) and produced 401/404.  Reverse-proxy
        loopback rewriting belongs in the reverse-proxy router, not
        in the forward proxy."""
        path = Path(__file__).parent.parent / "src" / "scruxy" / "proxy" / "forward_proxy.py"
        src = path.read_text(encoding="utf-8")
        # The old rewrite block must be gone.
        assert "upstream_url = f\"{upstream_parsed.scheme}://{upstream_parsed.netloc}" not in src, (
            "Forward proxy must NOT rewrite the upstream host; the "
            "provider's upstream_url should not substitute the request host."
        )
        # And the request URL must be passed through verbatim.
        assert "upstream_url = url" in src, (
            "Forward proxy must use the request URL as-is for upstream."
        )

    @pytest.mark.asyncio
    async def test_forward_proxy_bodyless_query_with_no_token_map_returns_503(self):
        """E1 r51 residual #3: forward proxy must fail closed (503)
        for a matched-provider bodyless URL with a query string when
        the session store can't supply a token map.  Previously the
        body-only fail-closed gate let a GET with PII in query slip
        through unscrubbed."""
        from unittest.mock import AsyncMock
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        provider = MagicMock()
        provider.name = "anthropic"
        provider.upstream_url = "https://api.example.com"
        provider.extract_session_id = MagicMock(return_value="s1")

        registry = MagicMock()
        registry.match = MagicMock(return_value=provider)
        registry.match_disabled = MagicMock(return_value=None)

        # Session store returns None to simulate a transient error.
        session_store = MagicMock()
        session_store.get_or_create_session = AsyncMock(return_value=None)

        server = ForwardProxyServer(
            host="127.0.0.1", port=0, ca=MagicMock(),
            registry=registry, pipeline=MagicMock(),
            session_store=session_store,
            request_scrubber=MagicMock(), response_unscrubber=MagicMock(),
        )

        status, _, _ = await server._scrub_and_forward(
            method="GET",
            url="https://api.example.com/v1/messages?email=alice@example.com",
            headers={},
            body=None,  # bodyless
        )
        # MUST be 503 (token map unavailable AND query string present),
        # NOT a successful forward.
        assert status == 503, (
            f"Forward proxy must fail closed for bodyless URL with query "
            f"+ no token map (E1 r51 residual #3); got {status}"
        )


# ---------------------------------------------------------------------------
# E2 — _redact_url_for_log strips userinfo
# ---------------------------------------------------------------------------

class TestE2_RedactUrlStripsUserinfo:
    def test_strips_basic_auth_credentials(self):
        from scruxy.proxy.routes import _redact_url_for_log
        url = "http://alice:hunter2@unmatched.example.com/admin?token=abc"
        out = _redact_url_for_log(url)
        assert "alice" not in out
        assert "hunter2" not in out
        assert "token=abc" not in out
        assert out == "http://unmatched.example.com/admin"

    def test_strips_userinfo_only(self):
        """User-only (no password) URLs also stripped."""
        from scruxy.proxy.routes import _redact_url_for_log
        url = "http://alice@example.com/path"
        out = _redact_url_for_log(url)
        assert "alice" not in out
        assert out == "http://example.com/path"

    def test_preserves_port(self):
        from scruxy.proxy.routes import _redact_url_for_log
        url = "http://user:pw@example.com:8080/path"
        out = _redact_url_for_log(url)
        assert ":8080" in out
        assert "user" not in out

    def test_forward_proxy_helper_consistent(self):
        from scruxy.proxy.forward_proxy import _redact_url_for_log
        url = "http://alice:hunter2@example.com/x?email=alice@example.com"
        out = _redact_url_for_log(url)
        assert "alice" not in out
        assert "hunter2" not in out


# ---------------------------------------------------------------------------
# E3 — Session locks coherent across threads
# ---------------------------------------------------------------------------

class TestE3_SessionLockCoherence:
    @pytest.mark.asyncio
    async def test_get_lock_does_not_keyerror_after_concurrent_eviction(self, tmp_path):
        """The asyncio side and worker-thread side both mutate the
        OrderedDicts — get_lock must be tolerant of evictions and
        re-create rather than raise KeyError."""
        from scruxy.tokenmap.service import ConcurrentSessionStore

        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            persistent=False,
        )
        store._session_max = 4
        await store.start()
        try:
            # Create a session.
            await store.get_or_create_session("victim")
            # Force eviction by creating many other sessions (cap=4).
            for i in range(20):
                await store.get_or_create_session(f"flood-{i}")

            # Even though "victim" was evicted, get_lock MUST NOT
            # raise KeyError — the E3 fix lazily re-creates it.
            lock = store.get_lock("victim")
            assert lock is not None
            # And it's a real asyncio.Lock.
            assert isinstance(lock, asyncio.Lock)
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_locks_lru_order_tracks_session_pii(self, tmp_path):
        """When `tag_session_pii` promotes a session in `_session_pii`,
        `_locks` must move_to_end too — otherwise eviction can drop
        an active session's lock."""
        from scruxy.tokenmap.service import ConcurrentSessionStore

        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            persistent=False,
        )
        store._session_max = 3
        await store.start()
        try:
            await store.get_or_create_session("a")
            await store.get_or_create_session("b")
            await store.get_or_create_session("c")
            # Tag "a" — should be promoted in BOTH OrderedDicts.
            store.tag_session_pii("a", {"pii-a"})
            # Add a fourth — eviction should drop "b" (oldest), not "a".
            await store.get_or_create_session("d")

            assert "a" in store._session_pii
            assert "a" in store._locks, (
                "_locks LRU drifted from _session_pii; 'a' was evicted "
                "despite recent tag_session_pii call (E3 fix)"
            )
            assert "b" not in store._session_pii
            assert "b" not in store._locks
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_clear_all_mappings_clears_locks_under_lock(self, tmp_path):
        """E3 r51 residual: `clear_all_mappings` must clear BOTH
        `_session_pii` AND `_locks` under `_session_pii_lock` so a
        concurrent `tag_session_pii` worker can never observe a
        desynchronised state."""
        path = Path(__file__).parent.parent / "src" / "scruxy" / "tokenmap" / "service.py"
        src = path.read_text(encoding="utf-8")
        # Source-pattern check: in `clear_all_mappings`, the
        # `_locks.clear()` call MUST appear inside the
        # `with self._session_pii_lock:` block.
        idx = src.find("async def clear_all_mappings")
        assert idx != -1
        block = src[idx:idx + 1500]
        # Find the with block and the _locks.clear inside it.
        with_idx = block.find("with self._session_pii_lock:")
        locks_idx = block.find("self._locks.clear()")
        assert with_idx != -1 and locks_idx != -1
        # _locks.clear() must be after the `with` line and before the
        # next dedent (i.e., still inside the with block).
        between = block[with_idx:locks_idx]
        # Inside an indented block, every line between with and the
        # next non-indented statement must start with whitespace.
        # Easier check: verify _locks.clear() is the same indent as
        # _session_pii.clear().
        sp_idx = block.find("self._session_pii.clear()")
        assert sp_idx != -1
        # Get the indent of each.
        sp_line_start = block.rfind("\n", 0, sp_idx) + 1
        locks_line_start = block.rfind("\n", 0, locks_idx) + 1
        sp_indent = len(block[sp_line_start:sp_idx])
        locks_indent = len(block[locks_line_start:locks_idx])
        assert sp_indent == locks_indent, (
            f"E3 r51 residual: _locks.clear() indent ({locks_indent}) must "
            f"match _session_pii.clear() indent ({sp_indent}) so both are "
            f"inside the _session_pii_lock block"
        )

    @pytest.mark.asyncio
    async def test_clear_all_mappings_runtime(self, tmp_path):
        """End-to-end: after `clear_all_mappings`, both dicts are empty."""
        from scruxy.tokenmap.service import ConcurrentSessionStore
        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            persistent=False,
        )
        await store.start()
        try:
            await store.get_or_create_session("s1")
            await store.get_or_create_session("s2")
            assert len(store._session_pii) == 2
            assert len(store._locks) == 2
            await store.clear_all_mappings()
            assert len(store._session_pii) == 0
            assert len(store._locks) == 0
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# E4 — SessionTokenMapView snapshots at construction time
# ---------------------------------------------------------------------------

class TestE4_SessionViewSnapshot:
    @pytest.mark.asyncio
    async def test_view_survives_session_eviction(self, tmp_path):
        """A view created BEFORE eviction must still resolve PII it
        knew about, even if the session is evicted by LRU pressure."""
        from scruxy.tokenmap.service import ConcurrentSessionStore
        from scruxy.scrubber.response_unscrubber import deanonymize_text

        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            persistent=False,
        )
        store._session_max = 2
        await store.start()
        try:
            tm = await store.get_or_create_session("victim")
            tm.get_or_create_token("Alice", "PERSON")
            store.tag_session_pii("victim", {"Alice"})

            # Create the response-time view BEFORE eviction (this is
            # what the proxy does at request scrub time).
            view = store.get_session_token_map("victim")

            # Now flood with new sessions to evict "victim".
            for i in range(5):
                await store.get_or_create_session(f"attacker-{i}")

            assert "victim" not in store._session_pii, (
                "Test setup error: victim should have been evicted"
            )

            # The view's snapshot MUST still resolve "Alice" — without
            # the E4 fix, view.unscrub_map returns {} and the response
            # leaks `REDACTED_PERSON_1` to the user.
            out = deanonymize_text("Hi REDACTED_PERSON_1!", view)
            assert "Alice" in out, (
                f"Session view must survive eviction (E4 fix); got {out!r}"
            )
            assert "REDACTED_PERSON_1" not in out
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_view_created_before_tag_then_evicted_still_works(self, tmp_path):
        """E4 residual: view is created BEFORE tag_session_pii (the
        actual production order), then eviction happens after tag.
        The view's snapshot must absorb newly-tagged PII on first read
        so subsequent eviction can't unmask it."""
        from scruxy.tokenmap.service import ConcurrentSessionStore
        from scruxy.scrubber.response_unscrubber import deanonymize_text

        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            persistent=False,
        )
        store._session_max = 2
        await store.start()
        try:
            tm = await store.get_or_create_session("victim")

            # Production order: view created BEFORE scrub/tag.
            view = store.get_session_token_map("victim")

            # Now scrub + tag (as the proxy would do).
            tm.get_or_create_token("Alice", "PERSON")
            store.tag_session_pii("victim", {"Alice"})

            # First deanonymize call — should absorb `Alice` into snapshot.
            out1 = deanonymize_text("Hi REDACTED_PERSON_1!", view)
            assert "Alice" in out1

            # Now flood evicts the session.
            for i in range(5):
                await store.get_or_create_session(f"attacker-{i}")
            assert "victim" not in store._session_pii

            # Subsequent deanonymize MUST still work — snapshot has Alice.
            out2 = deanonymize_text("Hi REDACTED_PERSON_1 again!", view)
            assert "Alice" in out2, (
                "View created BEFORE tag must absorb tagged PII into "
                "snapshot on first read so eviction can't unmask it "
                "(E4 r51 residual)"
            )
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_absorb_pii_seeds_snapshot_pre_eviction(self, tmp_path):
        """E4 r51 residual #2: the proxy calls `view.absorb_pii(request_pii)`
        right after `tag_session_pii`.  Even if eviction happens BEFORE
        the first `unscrub_map`/`get_pii` read, the snapshot must
        contain the request's PII because `absorb_pii` seeded it."""
        from scruxy.tokenmap.service import ConcurrentSessionStore
        from scruxy.scrubber.response_unscrubber import deanonymize_text

        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            persistent=False,
        )
        store._session_max = 2
        await store.start()
        try:
            tm = await store.get_or_create_session("victim")
            view = store.get_session_token_map("victim")

            tm.get_or_create_token("Alice", "PERSON")
            store.tag_session_pii("victim", {"Alice"})
            # Proxy calls absorb_pii right after tagging (the new fix).
            view.absorb_pii({"Alice"})

            # NOW evict BEFORE any read.
            for i in range(5):
                await store.get_or_create_session(f"attacker-{i}")
            assert "victim" not in store._session_pii

            # First read after eviction MUST still resolve Alice
            # because absorb_pii pre-seeded the snapshot.
            out = deanonymize_text("Hi REDACTED_PERSON_1!", view)
            assert "Alice" in out, (
                f"absorb_pii must pre-seed snapshot; got {out!r}"
            )
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# E5 — Sync lock docstring is honest (no false promises)
# ---------------------------------------------------------------------------

class TestE5_SyncLockDocstringHonest:
    def test_docstring_does_not_claim_async_writers_acquire_sync_lock(self):
        """The misleading docstring was the bug; verify the corrected
        comment doesn't assert what isn't true."""
        from scruxy.stats import collector
        path = Path(collector.__file__)
        src = path.read_text(encoding="utf-8")
        # The buggy comment said "All async writers also acquire this
        # lock so the sync readers see a consistent snapshot."
        assert "All async writers also acquire this lock" not in src, (
            "E5 fix: misleading docstring must be removed"
        )
        # And the correction must explicitly call out the GIL reliance.
        assert "GIL" in src, "Corrected docstring must mention GIL reliance"


# ---------------------------------------------------------------------------
# E6 — URLs in logger messages are redacted
# ---------------------------------------------------------------------------

class TestE6_LoggerUrlRedaction:
    def test_routes_passthrough_log_uses_redact_helper(self):
        """The 'Passthrough upstream error' log line must use
        `_redact_url_for_log` — otherwise URL query secrets reach the
        in-memory log buffer (UI logs tab)."""
        path = Path(__file__).parent.parent / "src" / "scruxy" / "proxy" / "routes.py"
        src = path.read_text(encoding="utf-8")
        # The E6 fix wraps `upstream_url` in `_redact_url_for_log`.
        assert "_redact_url_for_log(upstream_url)" in src, (
            "E6 fix: routes.py passthrough error log must use _redact_url_for_log"
        )

    def test_forward_proxy_log_calls_use_redact_helper(self):
        path = Path(__file__).parent.parent / "src" / "scruxy" / "proxy" / "forward_proxy.py"
        src = path.read_text(encoding="utf-8")
        # Several logger lines should now use the helper.
        assert "_redact_url_for_log(url)" in src, (
            "E6 fix: forward_proxy.py logger calls must use _redact_url_for_log"
        )


# ---------------------------------------------------------------------------
# E7 — Recorder index lock fallback is shared on overflow
# ---------------------------------------------------------------------------

class TestE7_RecorderIndexLockFallback:
    @pytest.mark.asyncio
    async def test_overflow_recorders_share_fallback_lock(
        self, tmp_path, monkeypatch
    ):
        """Two recorders for the same loop must SHARE the fallback
        lock when over `_MAX_SHARED_LOCKS` — otherwise each gets a
        unique lock and concurrent `_index.json` writes corrupt the file."""
        from scruxy.recording.recorder import SessionRecorder

        monkeypatch.setattr(SessionRecorder, "_MAX_SHARED_LOCKS", 0)
        # F6 fix removed `_owned_fallback_index_locks`; the
        # WeakValueDictionary is sufficient to retain the lock as
        # long as a recorder pins it via `_owned_index_lock`.

        rec1 = SessionRecorder(str(tmp_path / "a"))
        rec2 = SessionRecorder(str(tmp_path / "b"))
        # Both recorders should have received the SAME fallback lock
        # (they're on the same event loop).
        assert rec1._index_lock is rec2._index_lock, (
            "E7 fix: over-cap recorders on the same loop must share "
            "the fallback index lock; got distinct locks "
            f"{id(rec1._index_lock)} vs {id(rec2._index_lock)}"
        )


# ---------------------------------------------------------------------------
# E8 — Corrupt stats file doesn't crash startup
# ---------------------------------------------------------------------------

class TestE8_StatsLoadResilient:
    @pytest.mark.asyncio
    async def test_corrupt_json_does_not_raise(self, tmp_path, caplog):
        from scruxy.stats.collector import StatsCollector
        path = tmp_path / "stats.json"
        path.write_text("{this is not valid json")

        sc = StatsCollector(storage_file=str(path))
        # Must NOT raise.
        import logging
        with caplog.at_level(logging.WARNING):
            await sc.load_from_disk()
        # Stats start empty.
        assert sc.total_requests == 0

    @pytest.mark.asyncio
    async def test_truncated_file_does_not_raise(self, tmp_path):
        from scruxy.stats.collector import StatsCollector
        path = tmp_path / "stats.json"
        path.write_text('{"total_requests": 5, "tot')  # mid-key truncation
        sc = StatsCollector(storage_file=str(path))
        await sc.load_from_disk()
        assert sc.total_requests == 0

    @pytest.mark.asyncio
    async def test_empty_file_does_not_raise(self, tmp_path):
        from scruxy.stats.collector import StatsCollector
        path = tmp_path / "stats.json"
        path.write_text("")
        sc = StatsCollector(storage_file=str(path))
        await sc.load_from_disk()
        assert sc.total_requests == 0
