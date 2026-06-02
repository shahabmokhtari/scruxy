"""Tests for ConcurrentSessionStore with multiple sessions and per-session locking."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from scruxy.tokenmap.service import ConcurrentSessionStore
from scruxy.tokenmap.token_map import TokenMap


# ---------------------------------------------------------------------------
# Helper: create a store with DB lifecycle
# ---------------------------------------------------------------------------


async def _make_store(tmp_path: Path, **kwargs) -> ConcurrentSessionStore:
    """Create a ConcurrentSessionStore, open the DB, and return it."""
    store = ConcurrentSessionStore(tmp_path / "sessions", **kwargs)
    await store.start()
    return store


# ---------------------------------------------------------------------------
# Session creation
# ---------------------------------------------------------------------------


class TestSessionCreation:
    """get_or_create_session creates and caches sessions correctly."""

    async def test_create_new_session(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("session-1")
            assert isinstance(tm, TokenMap)
            assert store.has_session("session-1")
        finally:
            await store.stop()

    async def test_get_existing_session(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            tm1 = await store.get_or_create_session("session-1")
            tm2 = await store.get_or_create_session("session-1")
            assert tm1 is tm2  # exact same instance
        finally:
            await store.stop()

    async def test_multiple_sessions_share_map(self, tmp_path: Path) -> None:
        """All sessions now share the same TokenMap (global determinism)."""
        store = await _make_store(tmp_path)
        try:
            tm1 = await store.get_or_create_session("s1")
            tm2 = await store.get_or_create_session("s2")
            assert tm1 is tm2  # shared map
            tm1.get_or_create_token("a@b.com", "EMAIL")
            assert tm2.size == 1  # shared, so s2 sees it too
        finally:
            await store.stop()

    async def test_session_ids_property(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            await store.get_or_create_session("alpha")
            await store.get_or_create_session("beta")
            ids = store.session_ids
            assert set(ids) == {"alpha", "beta"}
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# Per-session locking
# ---------------------------------------------------------------------------


class TestSessionLocking:
    """Per-session locks ensure session-level isolation without global contention."""

    async def test_lock_per_session(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            await store.get_or_create_session("s1")
            await store.get_or_create_session("s2")
            lock1 = store.get_lock("s1")
            lock2 = store.get_lock("s2")
            assert lock1 is not lock2
        finally:
            await store.stop()

    async def test_same_session_same_lock(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            await store.get_or_create_session("s1")
            assert store.get_lock("s1") is store.get_lock("s1")
        finally:
            await store.stop()

    async def test_concurrent_access_different_sessions(self, tmp_path: Path) -> None:
        """Concurrent writes from different sessions share the same map."""
        store = await _make_store(tmp_path)
        try:
            tm1 = await store.get_or_create_session("s1")
            tm2 = await store.get_or_create_session("s2")
            results: list[str] = []

            async def writer(session_id: str, tm: TokenMap, label: str) -> None:
                async with store.get_lock(session_id):
                    for i in range(10):
                        tm.get_or_create_token(f"{label}-{i}@test.com", "EMAIL")
                    results.append(label)

            await asyncio.gather(
                writer("s1", tm1, "A"),
                writer("s2", tm2, "B"),
            )

            # Shared map: both writers contribute to the same map
            assert tm1.size == 20  # 10 from A + 10 from B
            assert set(results) == {"A", "B"}
        finally:
            await store.stop()

    async def test_same_session_serialised(self, tmp_path: Path) -> None:
        """Concurrent tasks on the *same* session serialize through the lock."""
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("s1")
            order: list[int] = []

            async def worker(seq: int) -> None:
                async with store.get_lock("s1"):
                    order.append(seq)
                    await asyncio.sleep(0.01)
                    tm.get_or_create_token(f"user-{seq}@test.com", "EMAIL")

            await asyncio.gather(worker(1), worker(2), worker(3))
            assert tm.size == 3
            # All three completed (order may vary, but all must be present).
            assert set(order) == {1, 2, 3}
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# Mark dirty (now a no-op, kept for backward compat)
# ---------------------------------------------------------------------------


class TestDirtyTracking:
    """mark_dirty / flush interaction (now no-ops with DB write-through)."""

    async def test_mark_dirty_and_flush(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("secret@corp.com", "EMAIL")
            store.tag_session_pii("s1", ["secret@corp.com"])
            store.mark_dirty("s1")
            await store.flush_all()

            # DB file should exist at parent level.
            assert (tmp_path / "scruxy.db").exists()
        finally:
            await store.stop()

    async def test_flush_all_is_noop(self, tmp_path: Path) -> None:
        """flush_all is a no-op — DB write-through handles persistence."""
        store = await _make_store(tmp_path)
        try:
            await store.get_or_create_session("s1")
            tm = await store.get_or_create_session("s2")
            tm.get_or_create_token("x@y.com", "EMAIL")
            store.tag_session_pii("s2", ["x@y.com"])
            store.mark_dirty("s2")

            await store.flush_all()

            # DB should exist
            assert (tmp_path / "scruxy.db").exists()
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# Background flush lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    """start() and stop() manage the DB lifecycle."""

    async def test_start_stop(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path, flush_interval_seconds=0.05)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("a@b.com", "EMAIL")
            store.tag_session_pii("s1", ["a@b.com"])
            store.mark_dirty("s1")

            # Data is written through immediately — DB file should exist
            assert (tmp_path / "scruxy.db").exists()
        finally:
            await store.stop()

    async def test_stop_closes_db(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path, flush_interval_seconds=999)
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("a@b.com", "EMAIL")
            store.mark_dirty("s1")

            # DB file should exist immediately (write-through)
            assert (tmp_path / "scruxy.db").exists()
        finally:
            await store.stop()

        # After stop, DB is still on disk
        assert (tmp_path / "scruxy.db").exists()


# ---------------------------------------------------------------------------
# New properties: sessions, get_token_map
# ---------------------------------------------------------------------------


class TestSessionsProperty:

    async def test_sessions_returns_dict_copy(self, tmp_path):
        store = await _make_store(tmp_path, flush_interval_seconds=9999)
        try:
            tm = await store.get_or_create_session("s1")
            sessions = store.sessions
            assert "s1" in sessions
            assert sessions["s1"] is tm
            # It's a copy — mutating it doesn't affect the store
            sessions.pop("s1")
            assert store.has_session("s1")
        finally:
            await store.stop()

    async def test_sessions_includes_all(self, tmp_path):
        store = await _make_store(tmp_path, flush_interval_seconds=9999)
        try:
            await store.get_or_create_session("a")
            await store.get_or_create_session("b")
            assert set(store.sessions.keys()) == {"a", "b"}
        finally:
            await store.stop()


class TestGetTokenMap:

    async def test_returns_token_map_for_known_session(self, tmp_path):
        store = await _make_store(tmp_path, flush_interval_seconds=9999)
        try:
            tm = await store.get_or_create_session("s1")
            assert store.get_token_map("s1") is tm
        finally:
            await store.stop()

    async def test_returns_shared_map_for_unknown_session(self, tmp_path):
        """get_token_map always returns the shared map (backward compat)."""
        store = await _make_store(tmp_path, flush_interval_seconds=9999)
        try:
            assert store.get_token_map("nonexistent") is store.shared_map
        finally:
            await store.stop()
