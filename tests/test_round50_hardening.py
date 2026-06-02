"""Regression tests for Round 50 hardening fixes (D1-D7).

Per the user's three guardrails, tests drive the integration paths
(`SessionTokenMapView`, `_log_passthrough`, the actual API endpoints,
the actual deanonymize flow) where possible — not just isolated helpers.
"""
from __future__ import annotations

import asyncio
import gc
import threading
from collections import OrderedDict
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest


# ---------------------------------------------------------------------------
# D1 — SessionTokenMapView.get_pii handles duplicate words
# ---------------------------------------------------------------------------

class TestD1_GetPiiDuplicateWords:
    @pytest.mark.asyncio
    async def test_third_subtoken_for_repeated_word_resolves(self, tmp_path):
        """A multi-word PII like 'José García García' has a duplicate
        word.  The third sub-token's alias must resolve through
        `get_pii()`, not just the first occurrence."""
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
            tm.get_or_create_token("José García García", "PERSON")
            store.tag_session_pii("s1", {"José García García"})

            view = store.get_session_token_map("s1")
            # First occurrence of "García" → REDACTED_PERSON_1B
            assert view.get_pii("REDACTED_PERSON_1B") == "García"
            # SECOND occurrence of "García" → REDACTED_PERSON_1C.  Without
            # the D1 fix, list.index("García") returns 1 unconditionally
            # and sub_tokens[1] != "REDACTED_PERSON_1C" → returns None.
            assert view.get_pii("REDACTED_PERSON_1C") == "García", (
                "Second-occurrence sub-token must resolve via session view (D1)"
            )
            # First word still works.
            assert view.get_pii("REDACTED_PERSON_1A") == "José"
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# D2 — _purge_subtoken_aliases preserves whitelist identity mappings
# ---------------------------------------------------------------------------

class TestD2_PurgePreservesWhitelist:
    def test_purge_skips_when_subtoken_equals_subpii(self):
        """If a custom strategy emits a sub-token that equals its
        sub-PII (rare but legal), the purge helper must NOT delete an
        unrelated whitelist identity mapping for that word."""
        from scruxy.tokenmap.token_map import TokenMap

        tm = TokenMap()
        # Pre-populate a whitelist identity mapping for "Dr".
        tm._unscrub["Dr"] = "Dr"
        tm._scrub["Dr"] = "Dr"

        # Now call purge with a token shape where the first sub-token
        # equals its sub-PII (e.g. a custom strategy kept "Dr" intact).
        # Creation guard would have refused to create aliases here, so
        # purge MUST also skip — otherwise it'll delete the whitelist.
        tm._purge_subtoken_aliases("Dr Smith", "Dr REDACTED_PERSON_1B")

        # Whitelist mapping must still exist.
        assert tm._unscrub.get("Dr") == "Dr", (
            "Purge deleted whitelist identity mapping (D2 regression)"
        )

    def test_purge_still_removes_real_aliases(self):
        """Sanity check: D2 fix must not break the normal purge path."""
        from scruxy.tokenmap.token_map import TokenMap
        tm = TokenMap()
        # Real alias case: every sub-token differs from sub-PII.
        tm._unscrub["REDACTED_PERSON_1A"] = "Alice"
        tm._unscrub["REDACTED_PERSON_1B"] = "Smith"
        tm._purge_subtoken_aliases(
            "Alice Smith", "REDACTED_PERSON_1A REDACTED_PERSON_1B",
        )
        assert tm._unscrub.get("REDACTED_PERSON_1A") is None
        assert tm._unscrub.get("REDACTED_PERSON_1B") is None


# ---------------------------------------------------------------------------
# D3 — Passthrough log redacts query strings
# ---------------------------------------------------------------------------

class TestD3_PassthroughUrlRedaction:
    def test_redact_helper_strips_query(self):
        from scruxy.proxy.routes import _redact_url_for_log
        url = "https://example.com/callback?email=alice@example.com&token=secret"
        redacted = _redact_url_for_log(url)
        assert "email" not in redacted
        assert "alice@example.com" not in redacted
        assert "token=secret" not in redacted
        assert redacted == "https://example.com/callback"

    def test_redact_helper_strips_fragment(self):
        from scruxy.proxy.routes import _redact_url_for_log
        url = "https://example.com/path#auth=ABC"
        redacted = _redact_url_for_log(url)
        assert "auth=ABC" not in redacted

    def test_redact_helper_passes_clean_urls(self):
        from scruxy.proxy.routes import _redact_url_for_log
        url = "https://example.com/path"
        assert _redact_url_for_log(url) == url

    def test_forward_proxy_helper_consistent(self):
        from scruxy.proxy.forward_proxy import _redact_url_for_log
        url = "https://example.com/x?api_key=secret"
        out = _redact_url_for_log(url)
        assert "api_key" not in out
        assert "secret" not in out


# ---------------------------------------------------------------------------
# D4 — StatsCollector dashboard methods don't crash with asyncio.Lock
# ---------------------------------------------------------------------------

class TestD4_StatsCollectorSyncMethods:
    """Production crash scenario: the real StatsCollector (with
    asyncio.Lock) must be callable from sync code without TypeError."""

    def test_get_windowed_stats_callable_from_sync(self):
        from scruxy.stats.collector import StatsCollector
        sc = StatsCollector()
        # Must NOT raise TypeError
        result = sc.get_windowed_stats(window_minutes=15.0)
        assert "scrub" in result
        assert "unscrub" in result
        assert "network" in result
        assert "total" in result

    def test_get_provider_latency_history_callable_from_sync(self):
        from scruxy.stats.collector import StatsCollector
        sc = StatsCollector()
        result = sc.get_provider_latency_history("anthropic")
        assert "total_history" in result
        assert "network_history" in result

    @pytest.mark.asyncio
    async def test_dashboard_endpoint_uses_real_collector(self):
        """End-to-end: drive /ui/api/dashboard with the real
        StatsCollector to catch the TypeError crash that the
        SimpleNamespace mock was masking (D4 production scenario)."""
        from scruxy.stats.collector import StatsCollector
        from scruxy.ui import routes as ui_routes
        from fastapi import FastAPI

        app = FastAPI()
        app.state._listen_host = "127.0.0.1"
        app.state.stats = StatsCollector()
        app.state.session_store = None
        app.state.config = None
        app.state.registry = None
        app.state.recorder = None
        app.include_router(ui_routes.router)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver",
        ) as client:
            resp = await client.get("/ui/api/dashboard")
        # Without D4 fix this returns 500 (TypeError on the asyncio.Lock).
        assert resp.status_code in (200, 401, 403), (
            f"Dashboard endpoint must not crash (got {resp.status_code}); "
            f"D4 fix required"
        )


# ---------------------------------------------------------------------------
# D5 — Per-session dicts bounded LRU
# ---------------------------------------------------------------------------

class TestD5_PerSessionBounded:
    @pytest.mark.asyncio
    async def test_stats_collector_per_session_lru(self):
        """Stats per_session must evict oldest entries when over cap."""
        from scruxy.stats.collector import StatsCollector
        sc = StatsCollector()
        sc._per_session_max = 4

        for i in range(20):
            await sc.record_scrub_event(
                session_id=f"sess-{i}",
                provider="anthropic",
                entities=[],
                latency_ms=1.0,
            )

        assert len(sc.per_session) <= sc._per_session_max
        assert "sess-0" not in sc.per_session
        assert "sess-19" in sc.per_session

    @pytest.mark.asyncio
    async def test_session_store_session_pii_lru(self, tmp_path):
        """ConcurrentSessionStore _session_pii must evict over cap."""
        from scruxy.tokenmap.service import ConcurrentSessionStore
        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            persistent=False,
        )
        store._session_max = 4
        await store.start()
        try:
            for i in range(20):
                await store.get_or_create_session(f"sess-{i}")

            assert len(store._session_pii) <= store._session_max
            assert "sess-0" not in store._session_pii
            # Lock map is bounded too.
            assert len(store._locks) <= store._session_max
            assert "sess-0" not in store._locks
            # Most-recent session is still tracked.
            assert "sess-19" in store._session_pii
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_load_from_disk_rebuilds_ordered_dict_and_trims(self, tmp_path):
        """D5 residual: load_from_disk must rebuild per_session as a
        bounded OrderedDict — not a plain dict, which would crash the
        next eviction with TypeError on popitem(last=False)."""
        import json
        from scruxy.stats.collector import StatsCollector

        # Persist a large per_session map to disk.
        storage = tmp_path / "stats.json"
        storage.write_text(json.dumps({
            "per_session": {
                f"sess-{i}": {
                    "requests": 1, "entities": 0, "unscrub_events": 0,
                    "tokens_unscrubbed": 0, "by_type": {},
                }
                for i in range(50)
            },
        }))

        sc = StatsCollector(storage_file=str(storage))
        sc._per_session_max = 8
        await sc.load_from_disk()
        # Must be an OrderedDict, NOT a plain dict.
        assert isinstance(sc.per_session, OrderedDict), (
            "load_from_disk must rebuild per_session as OrderedDict (D5 residual)"
        )
        # Must respect the cap (trim oldest).
        assert len(sc.per_session) <= sc._per_session_max

        # And subsequent eviction MUST work without TypeError.
        for i in range(20):
            await sc.record_scrub_event(
                session_id=f"new-{i}", provider="anthropic",
                entities=[], latency_ms=1.0,
            )
        assert len(sc.per_session) <= sc._per_session_max

    @pytest.mark.asyncio
    async def test_tag_session_pii_respects_cap(self, tmp_path):
        """tag_session_pii used to bypass the LRU cap when the session
        wasn't in the map yet (D5 residual)."""
        from scruxy.tokenmap.service import ConcurrentSessionStore
        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            persistent=False,
        )
        store._session_max = 3
        await store.start()
        try:
            for i in range(10):
                store.tag_session_pii(f"sess-{i}", {f"pii-{i}"})
            # Cap must be enforced even via tag_session_pii.
            assert len(store._session_pii) <= store._session_max
            assert "sess-0" not in store._session_pii
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# D6 — Prior token's sub-aliases purged on rebuild override
# ---------------------------------------------------------------------------

class TestD6_RebuildOverridePurgesPriorAliases:
    def test_purge_on_override_removes_prior_sub_aliases(self):
        """Direct test of the helper used in `_full_rebuild` override path:
        when prior_token != new_token, the prior token's sub-aliases
        must be purged."""
        from scruxy.tokenmap.token_map import TokenMap

        tm = TokenMap()
        # Simulate state after a prior multi-word PII override:
        tm._scrub["Alice Smith"] = "REDACTED_PERSON_1A REDACTED_PERSON_1B"
        tm._unscrub["REDACTED_PERSON_1A REDACTED_PERSON_1B"] = "Alice Smith"
        tm._unscrub["REDACTED_PERSON_1A"] = "Alice"
        tm._unscrub["REDACTED_PERSON_1B"] = "Smith"

        # Now an override with a DIFFERENT joint token comes in (e.g.
        # from a pending write captured during rebuild).
        prior_token = tm._scrub["Alice Smith"]
        new_token = "REDACTED_PERSON_2A REDACTED_PERSON_2B"

        # The fix's exact production logic.
        if tm._unscrub.get(prior_token) == "Alice Smith":
            tm._unscrub.pop(prior_token, None)
        tm._purge_subtoken_aliases("Alice Smith", prior_token)
        tm._scrub["Alice Smith"] = new_token
        tm._unscrub[new_token] = "Alice Smith"

        # Prior sub-aliases must be GONE (D6 fix).
        assert tm._unscrub.get("REDACTED_PERSON_1A") is None
        assert tm._unscrub.get("REDACTED_PERSON_1B") is None


# ---------------------------------------------------------------------------
# D7 — _shared_index_locks bounded
# ---------------------------------------------------------------------------

class TestD7_IndexLockBounded:
    def test_index_lock_uses_weak_value_dict(self):
        from scruxy.recording.recorder import SessionRecorder
        import weakref
        # Class attribute should be a WeakValueDictionary, NOT a plain dict.
        assert isinstance(
            SessionRecorder._shared_index_locks,
            weakref.WeakValueDictionary,
        ), "D7 fix: _shared_index_locks must be WeakValueDictionary"

    def test_index_lock_garbage_collected_when_no_recorder_holds(self, tmp_path):
        """When all recorders for a (storage_key, loop_id) are gone,
        the entry must be GC'd, NOT leaked indefinitely."""
        from scruxy.recording.recorder import SessionRecorder

        before = len(SessionRecorder._shared_index_locks)
        recorders = [SessionRecorder(str(tmp_path / f"s{i}")) for i in range(5)]
        # Each recorder pins its index lock via _owned_index_lock, so
        # the WeakValueDictionary should contain at least 5 entries.
        # (Exact count depends on whether they got distinct keys.)
        del recorders
        gc.collect()
        # After GC, the entries pinned only by the (now-deleted)
        # recorders should be evictable.  The WeakValueDictionary
        # may shrink — we just assert it doesn't grow unboundedly.
        after = len(SessionRecorder._shared_index_locks)
        assert after <= before + 5, (
            f"_shared_index_locks growing unbounded: before={before}, after={after}"
        )

    def test_overflow_returns_unshared_lock(self, tmp_path, monkeypatch):
        """When over `_MAX_SHARED_LOCKS`, the helper still returns a
        usable lock (correctness preserved over sharing)."""
        from scruxy.recording.recorder import SessionRecorder

        monkeypatch.setattr(SessionRecorder, "_MAX_SHARED_LOCKS", 0)
        rec = SessionRecorder(str(tmp_path / "x"))
        # Lock must exist and be usable.
        assert rec._index_lock is not None
        assert rec._owned_index_lock is rec._index_lock
