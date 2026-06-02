"""Tests for shared TokenMap, pre-filter, session tagging, expiration, and tester changes."""
from __future__ import annotations

import asyncio
from contextlib import suppress
import threading
import time
from pathlib import Path

import pytest

from scruxy.scrubber.response_unscrubber import deanonymize_text

from scruxy.tokenmap.token_map import TokenMap
from scruxy.tokenmap.service import ConcurrentSessionStore
from scruxy.pipeline.engine import PipelineEngine, PreFilterMatch, _extract_entity_type, _PlaceholderEntry
from scruxy.plugin.base import PiiEntity


# ---------------------------------------------------------------------------
# Helper: create a store with DB lifecycle
# ---------------------------------------------------------------------------


async def _make_store(tmp_path: Path, **kwargs) -> ConcurrentSessionStore:
    """Create a ConcurrentSessionStore, open the DB, and return it."""
    store = ConcurrentSessionStore(tmp_path / "sessions", **kwargs)
    await store.start()
    return store


# ---------------------------------------------------------------------------
# TokenMap: timestamps, remove_entry, prune_expired
# ---------------------------------------------------------------------------


class TestTokenMapTimestamps:
    """Entry timestamps and expiration pruning."""

    def test_new_entry_gets_timestamp(self) -> None:
        tm = TokenMap()
        before = time.time()
        tm.get_or_create_token("a@b.com", "EMAIL")
        after = time.time()
        ts = tm._entry_timestamps.get("a@b.com")
        assert ts is not None
        assert before <= ts <= after

    def test_existing_entry_keeps_original_timestamp(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("a@b.com", "EMAIL")
        original_ts = tm._entry_timestamps["a@b.com"]
        # Request same PII again — timestamp should not change
        tm.get_or_create_token("a@b.com", "EMAIL")
        assert tm._entry_timestamps["a@b.com"] == original_ts

    def test_remove_entry(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("a@b.com", "EMAIL")
        assert tm.size == 1
        assert tm.remove_entry("a@b.com") is True
        assert tm.size == 0
        assert tm.get_token("a@b.com") is None
        assert tm.get_pii("REDACTED_EMAIL_1") is None
        assert "a@b.com" not in tm._entry_timestamps

    def test_remove_entry_nonexistent(self) -> None:
        tm = TokenMap()
        assert tm.remove_entry("nonexistent") is False

    def test_timestamps_in_serialization(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("a@b.com", "EMAIL")
        data = tm.to_dict()
        assert "entry_timestamps" in data
        assert "a@b.com" in data["entry_timestamps"]

        restored = TokenMap.from_dict(data)
        assert "a@b.com" in restored._entry_timestamps


# ---------------------------------------------------------------------------
# Shared TokenMap: same PII -> same token across sessions
# ---------------------------------------------------------------------------


class TestSharedTokenMap:
    """All sessions share the same token map."""

    async def test_same_pii_same_token_across_sessions(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            tm1 = await store.get_or_create_session("s1")
            tm2 = await store.get_or_create_session("s2")

            # Both return the same TokenMap instance
            assert tm1 is tm2

            # Same PII -> same token
            token1 = tm1.get_or_create_token("john@test.com", "EMAIL")
            token2 = tm2.get_or_create_token("john@test.com", "EMAIL")
            assert token1 == token2
        finally:
            await store.stop()

    async def test_shared_map_property(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("s1")
            assert store.shared_map is tm
        finally:
            await store.stop()

    async def test_get_token_map_returns_shared(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            await store.get_or_create_session("s1")
            assert store.get_token_map("s1") is store.shared_map
        finally:
            await store.stop()

    async def test_get_token_map_unknown_returns_shared(self, tmp_path: Path) -> None:
        """get_token_map always returns the shared map (backward compat)."""
        store = await _make_store(tmp_path)
        try:
            assert store.get_token_map("nonexistent") is store.shared_map
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# Session PII tagging and exclusive-entry deletion
# ---------------------------------------------------------------------------


class TestSessionPiiTagging:

    async def test_tag_session_pii(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            await store.get_or_create_session("s1")
            store.tag_session_pii("s1", ["a@b.com", "John Doe"])
            assert store.get_session_pii_count("s1") == 2
        finally:
            await store.stop()

    async def test_tag_merges_with_existing(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            await store.get_or_create_session("s1")
            store.tag_session_pii("s1", ["a@b.com"])
            store.tag_session_pii("s1", ["b@c.com", "a@b.com"])
            assert store.get_session_pii_count("s1") == 2  # deduplicated
        finally:
            await store.stop()

    async def test_delete_exclusive_entries(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("s1")
            await store.get_or_create_session("s2")

            tm.get_or_create_token("shared@test.com", "EMAIL")
            tm.get_or_create_token("exclusive@test.com", "EMAIL")

            store.tag_session_pii("s1", ["shared@test.com", "exclusive@test.com"])
            store.tag_session_pii("s2", ["shared@test.com"])

            removed = await store.delete_session_mappings("s1")
            assert removed == 1  # only exclusive@test.com removed
            assert tm.get_token("shared@test.com") is not None
            assert tm.get_token("exclusive@test.com") is None
        finally:
            await store.stop()

    async def test_delete_then_recreate_reuses_counter(self, tmp_path: Path) -> None:
        """After clearing a session, re-adding the same PII should get the same token number."""
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("s1")

            # Create 3 tokens
            t1 = tm.get_or_create_token("alice@test.com", "EMAIL")
            t2 = tm.get_or_create_token("bob@test.com", "EMAIL")
            t3 = tm.get_or_create_token("carol@test.com", "EMAIL")
            assert t1 == "REDACTED_EMAIL_1"
            assert t2 == "REDACTED_EMAIL_2"
            assert t3 == "REDACTED_EMAIL_3"

            store.tag_session_pii("s1", ["alice@test.com", "bob@test.com", "carol@test.com"])

            # Delete session tokens
            await store.delete_session_mappings("s1")
            assert tm.size == 0

            # Re-add same PII -- should start from _1 again, not _4
            t1b = tm.get_or_create_token("alice@test.com", "EMAIL")
            assert t1b == "REDACTED_EMAIL_1"
        finally:
            await store.stop()

    async def test_delete_clears_session_pii_set(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("a@b.com", "EMAIL")
            store.tag_session_pii("s1", ["a@b.com"])

            await store.delete_session_mappings("s1")
            assert store.get_session_pii_count("s1") == 0
        finally:
            await store.stop()

    async def test_delete_session_cleans_up_persistent_lock_entry(self, tmp_path: Path) -> None:
        """Persistent session deletion should not leave a stale per-session lock behind."""
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("a@b.com", "EMAIL")
            store.tag_session_pii("s1", ["a@b.com"])

            await store.delete_session_mappings("s1")

            assert not store.has_session("s1")
            assert "s1" not in store._locks
        finally:
            await store.stop()

    async def test_clear_all_mappings(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("a@b.com", "EMAIL")
            store.tag_session_pii("s1", ["a@b.com"])

            await store.clear_all_mappings()
            assert store.shared_map.size == 0
            assert store.get_session_pii_count("s1") == 0
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# Persistence: shared token map to DB
# ---------------------------------------------------------------------------


class TestSharedPersistence:

    async def test_shared_map_persists_to_db(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("a@b.com", "EMAIL")

            # DB file should exist at parent of sessions dir
            db_path = tmp_path / "scruxy.db"
            assert db_path.exists()
        finally:
            await store.stop()

    async def test_shared_map_loads_from_db(self, tmp_path: Path) -> None:
        # First store: create and persist
        store1 = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store1.get_or_create_session("s1")
            tm.get_or_create_token("a@b.com", "EMAIL")
        finally:
            await store1.stop()

        # Second store: load from DB
        store2 = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            assert store2.shared_map.size == 1
            assert store2.shared_map.get_token("a@b.com") == "REDACTED_EMAIL_1"
        finally:
            await store2.stop()

    async def test_session_pii_persists(self, tmp_path: Path) -> None:
        store1 = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store1.get_or_create_session("s1")
            tm.get_or_create_token("a@b.com", "EMAIL")
            store1.tag_session_pii("s1", ["a@b.com"])
        finally:
            await store1.stop()

        store2 = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            assert store2.get_session_pii_count("s1") == 1
        finally:
            await store2.stop()

    async def test_load_from_db_does_not_drop_live_mappings(self, tmp_path: Path) -> None:
        """Reloading from DB should not wipe a mapping created during live traffic."""
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("seed@test.com", "EMAIL")
            store._drain_pending_writes()

            db = store._db
            assert db is not None

            gate = threading.Event()
            release = threading.Event()
            original_get_all_tokens = db.get_all_tokens

            def slow_get_all_tokens():
                gate.set()
                release.wait(timeout=2)
                return original_get_all_tokens()

            db.get_all_tokens = slow_get_all_tokens  # type: ignore[assignment]

            load_task = asyncio.create_task(store._load_from_db())
            assert await asyncio.to_thread(gate.wait, 1)

            create_task = asyncio.create_task(
                asyncio.to_thread(
                    tm.get_or_create_token,
                    "race@test.com",
                    "EMAIL",
                )
            )
            await asyncio.sleep(0.05)
            release.set()

            await load_task
            await create_task

            assert tm.get_token("race@test.com") == "REDACTED_EMAIL_2"
        finally:
            await store.stop()

    async def test_load_from_db_does_not_hold_shared_map_lock_during_db_io(
        self,
        tmp_path: Path,
    ) -> None:
        """DB reads should not monopolize the shared token-map lock."""
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("seed@test.com", "EMAIL")
            store._drain_pending_writes()

            db = store._db
            assert db is not None

            original_get_all_tokens = db.get_all_tokens
            lock_state: list[bool] = []

            def checked_get_all_tokens():
                is_owned = getattr(store._shared_map._lock, "_is_owned", None)
                lock_state.append(bool(is_owned()) if callable(is_owned) else False)
                return original_get_all_tokens()

            db.get_all_tokens = checked_get_all_tokens  # type: ignore[assignment]

            await store._load_from_db()

            assert lock_state == [False]
        finally:
            await store.stop()

    async def test_session_scoped_unscrub_view_blocks_cross_session_leaks(
        self,
        tmp_path: Path,
    ) -> None:
        """Responses should only deanonymize tokens that belong to the current session."""
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm1 = await store.get_or_create_session("s1")
            await store.get_or_create_session("s2")

            token = tm1.get_or_create_token("alice@example.com", "EMAIL")
            assert token is not None
            store.tag_session_pii("s1", ["alice@example.com"])

            s1_view = store.get_session_token_map("s1")
            s2_view = store.get_session_token_map("s2")

            assert deanonymize_text(f"hello {token}", s1_view) == "hello alice@example.com"
            assert deanonymize_text(f"hello {token}", s2_view) == f"hello {token}"
        finally:
            await store.stop()

    async def test_session_view_blocks_private_attr_access(self, tmp_path: Path) -> None:
        """SessionTokenMapView must not proxy private attributes to the shared map."""
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("alice@example.com", "EMAIL")
            store.tag_session_pii("s1", ["alice@example.com"])

            view = store.get_session_token_map("s1")

            with pytest.raises(AttributeError):
                _ = view._unscrub
            with pytest.raises(AttributeError):
                _ = view._scrub
        finally:
            await store.stop()

    async def test_drain_requeues_touches_and_deletes_on_clear_failure(
        self,
        tmp_path: Path,
    ) -> None:
        """If clear_all() fails, pending touches and deletes must be re-queued."""
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("a@b.com", "EMAIL")
            store._drain_pending_writes()

            # Queue a touch and a delete, then request a clear
            with store._shared_map._lock:
                store._shared_map._pending_touches.add("a@b.com")
                store._shared_map._pending_deletes.add("a@b.com")
                store._shared_map._pending_clear = True

            db = store._db
            assert db is not None
            original_clear = db.clear_all
            db.clear_all = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[assignment]

            with pytest.raises(RuntimeError, match="boom"):
                store._drain_pending_writes()

            # Verify touches and deletes were re-queued
            with store._shared_map._lock:
                assert "a@b.com" in store._shared_map._pending_touches
                assert "a@b.com" in store._shared_map._pending_deletes
                assert store._shared_map._pending_clear is True

            db.clear_all = original_clear  # type: ignore[assignment]
        finally:
            await store.stop()

    async def test_session_view_exposes_token_version(self, tmp_path: Path) -> None:
        """SessionTokenMapView must proxy _token_version for SSE trie rebuilds."""
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            await store.get_or_create_session("s1")
            view = store.get_session_token_map("s1")
            v = view._token_version
            assert isinstance(v, int) and v >= 0
        finally:
            await store.stop()

    async def test_clear_all_preserves_memory_on_db_failure(self, tmp_path: Path) -> None:
        """If DB clear fails, in-memory tokens must survive."""
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("keep@test.com", "EMAIL")
            store._drain_pending_writes()

            db = store._db
            assert db is not None
            original_clear = db.clear_all
            db.clear_all = lambda: (_ for _ in ()).throw(RuntimeError("db boom"))  # type: ignore[assignment]

            with pytest.raises(RuntimeError, match="db boom"):
                await store.clear_all_mappings()

            # Token must still be in memory
            assert tm.get_token("keep@test.com") == "REDACTED_EMAIL_1"

            db.clear_all = original_clear  # type: ignore[assignment]
        finally:
            await store.stop()

    async def test_periodic_drain_pending_check_runs_off_event_loop(self, tmp_path: Path) -> None:
        """A blocked pending-check should not stall unrelated event-loop work."""
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            if store._drain_task is not None:
                store._drain_task.cancel()
                with suppress(asyncio.CancelledError):
                    await store._drain_task
                store._drain_task = None

            started = threading.Event()
            release = threading.Event()
            original_check = store._has_pending_db_work

            def blocking_check() -> bool:
                started.set()
                release.wait(timeout=1)
                return original_check()

            store._has_pending_db_work = blocking_check  # type: ignore[method-assign]

            task = asyncio.create_task(store._periodic_drain())
            assert await asyncio.to_thread(started.wait, 1)

            # The event loop should remain responsive while the pending check
            # is blocked in a worker thread.
            await asyncio.wait_for(asyncio.sleep(0.01), timeout=0.1)

            release.set()
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# Expiration pruning via DB
# ---------------------------------------------------------------------------


class TestExpirationPruning:

    async def test_expired_entries_pruned_during_periodic_task(self, tmp_path: Path) -> None:
        store = await _make_store(
            tmp_path, flush_interval_seconds=0.05, expiration_hours=1,
        )
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("old@test.com", "EMAIL")

            # Drain pending writes before backdating
            store._drain_pending_writes()

            # Backdate in DB directly
            from scruxy.tokenmap.db import TokenDB
            db = TokenDB(tmp_path / "scruxy.db")
            db.open()
            db._c.execute(
                "UPDATE tokens SET last_access = ? WHERE original = ?",
                (time.time() - 7200, "old@test.com"),
            )
            db._c.commit()
            db.close()

            tm.get_or_create_token("new@test.com", "EMAIL")
            store._drain_pending_writes()

            # Wait for periodic expiration to fire
            await asyncio.sleep(0.2)

            # old entry should be purged, new should remain
            assert tm.get_token("old@test.com") is None
            assert tm.get_token("new@test.com") is not None
        finally:
            await store.stop()

    async def test_zero_expiration_no_pruning(self, tmp_path: Path) -> None:
        store = await _make_store(
            tmp_path, flush_interval_seconds=0.05, expiration_hours=0,
        )
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("old@test.com", "EMAIL")
            # Even with old timestamps, zero expiration means no pruning
            await asyncio.sleep(0.15)
            assert tm.get_token("old@test.com") is not None  # not pruned
        finally:
            await store.stop()

    async def test_zero_expiration_preserves_entries_on_restart(self, tmp_path: Path) -> None:
        store1 = await _make_store(
            tmp_path, flush_interval_seconds=999, expiration_hours=0,
        )
        try:
            tm = await store1.get_or_create_session("s1")
            tm.get_or_create_token("old@test.com", "EMAIL")
            store1._drain_pending_writes()

            db = store1._db
            assert db is not None
            db._c.execute(
                "UPDATE tokens SET last_access = ? WHERE original = ?",
                (time.time() - 3 * 24 * 3600, "old@test.com"),
            )
            db._c.commit()
        finally:
            await store1.stop()

        store2 = await _make_store(
            tmp_path, flush_interval_seconds=999, expiration_hours=0,
        )
        try:
            assert store2.shared_map.get_token("old@test.com") == "REDACTED_EMAIL_1"
        finally:
            await store2.stop()

    async def test_existing_token_reuse_refreshes_db_last_access(self, tmp_path: Path) -> None:
        store = await _make_store(
            tmp_path, flush_interval_seconds=999, expiration_hours=1,
        )
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("active@test.com", "EMAIL")
            store._drain_pending_writes()

            db = store._db
            assert db is not None
            stale_ts = time.time() - 3600
            db._c.execute(
                "UPDATE tokens SET last_access = ? WHERE original = ?",
                (stale_ts, "active@test.com"),
            )
            db._c.commit()

            tm.get_or_create_token("active@test.com", "EMAIL")
            store._drain_pending_writes()

            refreshed = db._c.execute(
                "SELECT last_access FROM tokens WHERE original = ?",
                ("active@test.com",),
            ).fetchone()[0]
            assert refreshed > stale_ts
        finally:
            await store.stop()

    async def test_invalidate_entity_types_wins_over_pending_db_write(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("alice@example.com", "EMAIL")
            tm.invalidate_entity_types({"EMAIL"})

            store._drain_pending_writes()

            db = store._db
            assert db is not None
            assert db.get_by_original("alice@example.com") is None
            assert tm.get_token("alice@example.com") is None
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# Pre-filter optimization
# ---------------------------------------------------------------------------


class TestPreFilter:

    def test_pre_filter_replaces_known_pii(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("John Doe", "PERSON")
        tm.get_or_create_token("john@test.com", "EMAIL")

        text = "Hello John Doe, email john@test.com please."
        ph_entries: list[_PlaceholderEntry] = []
        filtered, matches, _ = PipelineEngine._pre_filter_to_placeholders(text, tm, 0, ph_entries)

        assert "John Doe" not in filtered
        assert "john@test.com" not in filtered
        # Placeholders used instead of actual tokens
        assert "\u00a7\u00a7\u00a7SCRX" in filtered
        assert len(matches) == 2
        assert all(isinstance(m, PreFilterMatch) for m in matches)

    def test_pre_filter_empty_map(self) -> None:
        tm = TokenMap()
        text = "No known PII here."
        ph_entries: list[_PlaceholderEntry] = []
        filtered, matches, _ = PipelineEngine._pre_filter_to_placeholders(text, tm, 0, ph_entries)
        assert filtered == text
        assert matches == []

    def test_pre_filter_longest_first(self) -> None:
        """Longer PII strings should be replaced first to avoid partial matches."""
        tm = TokenMap()
        tm.get_or_create_token("John", "PERSON")
        tm.get_or_create_token("John Doe", "PERSON")

        text = "Hello John Doe!"
        ph_entries: list[_PlaceholderEntry] = []
        filtered, matches, _ = PipelineEngine._pre_filter_to_placeholders(text, tm, 0, ph_entries)

        # "John Doe" should be replaced as a whole, not "John" partially
        assert "John" not in filtered
        assert "\u00a7\u00a7\u00a7SCRX" in filtered

    def test_pre_filter_matches_have_correct_fields(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("a@b.com", "EMAIL")
        text = "Email: a@b.com"
        ph_entries: list[_PlaceholderEntry] = []
        _, matches, _ = PipelineEngine._pre_filter_to_placeholders(text, tm, 0, ph_entries)
        assert len(matches) == 1
        assert matches[0].pii_text == "a@b.com"
        assert matches[0].token == "REDACTED_EMAIL_1"
        assert matches[0].entity_type == "EMAIL"
        # Placeholder entry also created
        assert len(ph_entries) == 1
        assert ph_entries[0].pii_text == "a@b.com"

    def test_pre_filter_multiple_occurrences(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("John", "PERSON")
        text = "John called John again."
        ph_entries: list[_PlaceholderEntry] = []
        filtered, matches, _ = PipelineEngine._pre_filter_to_placeholders(text, tm, 0, ph_entries)
        # Two placeholders for two occurrences
        assert filtered.count("\u00a7\u00a7\u00a7SCRX") == 2
        assert len(ph_entries) == 2
        # One match record (the PII string "John")
        assert len(matches) == 1
        assert matches[0].pii_text == "John"


# ---------------------------------------------------------------------------
# _extract_entity_type helper
# ---------------------------------------------------------------------------


class TestExtractEntityType:

    def test_standard_token(self) -> None:
        assert _extract_entity_type("REDACTED_PERSON_1") == "PERSON"

    def test_multi_word_type(self) -> None:
        assert _extract_entity_type("REDACTED_EMAIL_ADDRESS_1") == "EMAIL_ADDRESS"

    def test_unknown_format(self) -> None:
        assert _extract_entity_type("some-random-token") == "UNKNOWN"

    def test_redacted_no_counter(self) -> None:
        assert _extract_entity_type("REDACTED_X") == "UNKNOWN"


# ---------------------------------------------------------------------------
# Config: expiration_hours
# ---------------------------------------------------------------------------


class TestExpirationConfig:

    def test_default_expiration(self) -> None:
        from scruxy.config.models import TokenConfig
        tc = TokenConfig()
        assert tc.expiration_hours == 168

    def test_custom_expiration(self) -> None:
        from scruxy.config.models import TokenConfig
        tc = TokenConfig(expiration_hours=0)
        assert tc.expiration_hours == 0

class TestLoadFromDbRace:
    """Round-44 M1: ``_load_from_db`` must not drop tokens added concurrently
    between the snapshot and the rebuild lock reacquisition."""

    @pytest.mark.asyncio
    async def test_concurrent_writes_during_rebuild_are_preserved(
        self, tmp_path: Path,
    ) -> None:
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("s1")
            # Pre-seed one token so the DB has something to load.
            tm.get_or_create_token("first@test.com", "EMAIL")
            await asyncio.to_thread(store._drain_pending_writes)

            # Patch _full_rebuild to pause between snapshot and the
            # main rebuild, simulating the race window. During the window,
            # we inject a new token from a pipeline-like thread; it must
            # not be wiped by _load_from_db.
            import scruxy.tokenmap.service as _svc
            orig_to_thread = asyncio.to_thread

            race_tm = tm
            race_done = threading.Event()

            async def _racing_to_thread(func, *args, **kwargs):
                result = await orig_to_thread(func, *args, **kwargs)
                # After the snapshot returns and before the apply lock is
                # acquired, insert a brand-new token directly on the shared
                # map (simulating a concurrent pipeline write).
                if getattr(func, "__name__", "") == "_full_rebuild":
                    race_tm.get_or_create_token("racy@test.com", "EMAIL")
                    race_done.set()
                return result

            _svc.asyncio.to_thread = _racing_to_thread
            try:
                await store._load_from_db()
            finally:
                _svc.asyncio.to_thread = orig_to_thread

            assert race_done.is_set()
            # The racy token must still be present after the rebuild.
            assert tm.get_token("racy@test.com") is not None, (
                "_load_from_db race wiped a token queued during the snapshot window"
            )
            # And the originally-persisted token must still be present too.
            assert tm.get_token("first@test.com") is not None
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_concurrent_deletes_during_rebuild_are_honoured(
        self, tmp_path: Path,
    ) -> None:
        """Round-44 follow-up: symmetric to the write race — a delete that
        lands between ``_full_rebuild`` and the apply lock must also
        be honoured; otherwise the rebuild resurrects the deleted token.
        """
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("doomed@test.com", "EMAIL")
            await asyncio.to_thread(store._drain_pending_writes)

            import scruxy.tokenmap.service as _svc
            orig_to_thread = asyncio.to_thread
            race_done = threading.Event()
            race_tm = tm

            async def _racing_to_thread(func, *args, **kwargs):
                result = await orig_to_thread(func, *args, **kwargs)
                if getattr(func, "__name__", "") == "_full_rebuild":
                    # Queue a delete AFTER the snapshot so pending_deletes_snap
                    # won't contain it.  The fix must union current
                    # _pending_deletes with the snapshot under the apply lock.
                    race_tm.remove_entry("doomed@test.com")
                    race_done.set()
                return result

            _svc.asyncio.to_thread = _racing_to_thread
            try:
                await store._load_from_db()
            finally:
                _svc.asyncio.to_thread = orig_to_thread

            assert race_done.is_set()
            assert tm.get_token("doomed@test.com") is None, (
                "_load_from_db race resurrected a concurrently-deleted token"
            )
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_delete_then_readd_during_rebuild_preserves_readd(
        self, tmp_path: Path,
    ) -> None:
        """Round-45 GPT-5.4: after a delete lands in the snapshot, a re-add
        of the SAME pii between snapshot and apply must win — the delete
        tombstone in ``pending_deletes_snap`` must not erase the re-created
        token.
        """
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("victim@test.com", "EMAIL")
            await asyncio.to_thread(store._drain_pending_writes)

            # Queue a delete so it's in the snapshot.
            tm.remove_entry("victim@test.com")

            import scruxy.tokenmap.service as _svc
            orig_to_thread = asyncio.to_thread
            race_done = threading.Event()
            race_tm = tm

            async def _racing_to_thread(func, *args, **kwargs):
                result = await orig_to_thread(func, *args, **kwargs)
                if getattr(func, "__name__", "") == "_full_rebuild":
                    # Re-add the same pii AFTER snapshot.  A stale delete
                    # tombstone in pending_deletes_snap must not wipe it.
                    race_tm.get_or_create_token("victim@test.com", "EMAIL")
                    race_done.set()
                return result

            _svc.asyncio.to_thread = _racing_to_thread
            try:
                await store._load_from_db()
            finally:
                _svc.asyncio.to_thread = orig_to_thread

            assert race_done.is_set()
            assert tm.get_token("victim@test.com") is not None, (
                "_load_from_db tombstone erased a concurrently re-added token"
            )
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_periodic_drain_during_snapshot_window_preserves_writes(
        self, tmp_path: Path,
    ) -> None:
        """Round-45 Goldeneye: if ``_periodic_drain`` runs between the
        snapshot's drain (which wrote to DB but also took a snapshot list)
        and the apply-lock acquisition, current ``_pending_writes`` has
        been cleared — so only the snapshot knows what was queued at
        snapshot time.  The fix unions snapshot + current writes.
        """
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("first@test.com", "EMAIL")
            await asyncio.to_thread(store._drain_pending_writes)

            import scruxy.tokenmap.service as _svc
            orig_to_thread = asyncio.to_thread
            race_done = threading.Event()
            race_tm = tm
            inner_store = store

            async def _racing_to_thread(func, *args, **kwargs):
                result = await orig_to_thread(func, *args, **kwargs)
                if getattr(func, "__name__", "") == "_full_rebuild":
                    # Queue a new token so it lands in the current
                    # _pending_writes.  The snapshot does not have it.
                    race_tm.get_or_create_token("drained@test.com", "EMAIL")
                    # Simulate _periodic_drain firing: flush to DB and
                    # clear _pending_writes.  After this, the token is
                    # in DB but the rebuild's `rows` snapshot predates
                    # the write so it isn't in `rows` either.
                    await orig_to_thread(inner_store._drain_pending_writes)
                    race_done.set()
                return result

            _svc.asyncio.to_thread = _racing_to_thread
            try:
                await store._load_from_db()
            finally:
                _svc.asyncio.to_thread = orig_to_thread

            assert race_done.is_set()
            # Without the current+snapshot union fix, the token would be
            # lost: rows (pre-drain) doesn't have it, snapshot doesn't
            # have it, and current _pending_writes was cleared mid-race.
            # The in-memory map still holds it via _scrub, which the
            # apply block must preserve via pending_overrides.
            assert tm.get_token("drained@test.com") is not None, (
                "_load_from_db lost a token drained mid-race"
            )
            assert tm.get_token("first@test.com") is not None
        finally:
            await store.stop()



# ---------------------------------------------------------------------------
# Round 46: _full_rebuild must drop stale reverse mapping when an override
# replaces a token that already existed in the DB snapshot.
# ---------------------------------------------------------------------------


class TestFullRebuildStaleUnscrub:
    """Goldeneye round-46: invalidate+recreate during rebuild races must
    not leave a stale token→pii reverse entry in ``_unscrub``."""

    async def test_override_replaces_stale_unscrub(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("alice@test.com", "EMAIL")
            store._drain_pending_writes()  # DB has T1; pending empty

            shared = store._shared_map
            with shared._lock:
                old_token = shared._scrub["alice@test.com"]

            # `_full_rebuild` calls `_drain_pending_writes()` internally
            # before it captures `pending_overrides`. To exercise the race
            # where an in-flight invalidate+recreate lands AFTER the inner
            # drain but BEFORE the apply lock, we monkey-patch the drain
            # so that injecting the override happens at exactly that point.
            new_token = "REDACTED_EMAIL_999"
            original_drain = store._drain_pending_writes

            def _drain_then_inject() -> None:
                original_drain()
                with shared._lock:
                    shared._scrub["alice@test.com"] = new_token
                    shared._unscrub[new_token] = "alice@test.com"
                    shared._pending_writes.append((
                        "alice@test.com", new_token, "EMAIL", "test",
                        1, "req-test", False, False, False,
                    ))
                store._drain_pending_writes = original_drain  # one-shot

            store._drain_pending_writes = _drain_then_inject  # type: ignore[assignment]

            await store._load_from_db()

            # The pre-existing DB token (T1) MUST NOT still deanonymize.
            assert shared._unscrub.get(old_token) != "alice@test.com"
            assert shared._unscrub.get(new_token) == "alice@test.com"
            assert shared._scrub.get("alice@test.com") == new_token
        finally:
            await store.stop()
