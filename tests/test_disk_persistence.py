"""Tests for token map disk persistence: save, load, and flush behaviour (SQLite-backed)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scruxy.tokenmap.db import TokenDB
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
# Basic save / load
# ---------------------------------------------------------------------------


class TestSaveAndLoad:
    """Write-through to DB and verify the DB content."""

    async def test_flush_creates_db_file(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("sess-1")
            tm.get_or_create_token("alice@corp.com", "EMAIL", source="presidio")
            store.tag_session_pii("sess-1", ["alice@corp.com"])

            # DB file should exist at parent level
            assert (tmp_path / "scruxy.db").exists()
        finally:
            await store.stop()

    async def test_write_through_data_matches(self, tmp_path: Path) -> None:
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("sess-1")
            tm.get_or_create_token("alice@corp.com", "EMAIL", source="presidio")
            tm.get_or_create_token("Bob Smith", "PERSON", source="regex")

            # Drain pending writes so DB has the data
            store._drain_pending_writes()

            # Verify DB content directly
            db = TokenDB(tmp_path / "scruxy.db")
            db.open()
            try:
                tokens = db.get_all_tokens()
                assert len(tokens) == 2
                originals = {t["original"] for t in tokens}
                assert originals == {"alice@corp.com", "Bob Smith"}
                # Check scrubbed values
                email_row = db.get_by_original("alice@corp.com")
                assert email_row["scrubbed"] == "REDACTED_EMAIL_1"
                person_row = db.get_by_original("Bob Smith")
                assert person_row["scrubbed"] == "REDACTED_PERSON_1"
                # Check counters
                assert db.get_counter("EMAIL") == 1
                assert db.get_counter("PERSON") == 1
            finally:
                db.close()
        finally:
            await store.stop()

    async def test_flush_session_not_found(self, tmp_path: Path) -> None:
        """Flushing a non-existent session is a no-op."""
        store = await _make_store(tmp_path)
        try:
            await store.flush_session("no-such-session")  # should not raise
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# Load from DB on startup
# ---------------------------------------------------------------------------


class TestLoadFromDisk:
    """ConcurrentSessionStore.start() loads data from the SQLite DB."""

    async def test_load_existing_session(self, tmp_path: Path) -> None:
        db_path = tmp_path / "scruxy.db"
        sessions_dir = tmp_path / "sessions"
        sessions_dir.mkdir(parents=True)

        # Pre-populate DB
        db = TokenDB(db_path)
        db.open()
        db.upsert_token("alice@corp.com", "REDACTED_EMAIL_1", "EMAIL")
        db.set_counter("EMAIL", 1)
        db.tag_session_pii("restored-session", ["alice@corp.com"])
        db.close()

        store = ConcurrentSessionStore(sessions_dir)
        await store.start()

        assert store.has_session("restored-session")
        tm = await store.get_or_create_session("restored-session")
        assert tm.get_pii("REDACTED_EMAIL_1") == "alice@corp.com"
        assert tm.size == 1

        await store.stop()

    async def test_load_multiple_sessions(self, tmp_path: Path) -> None:
        db_path = tmp_path / "scruxy.db"
        sessions_dir = tmp_path / "sessions"
        sessions_dir.mkdir(parents=True)

        # Pre-populate DB
        db = TokenDB(db_path)
        db.open()
        db.upsert_token("s1@test.com", "REDACTED_EMAIL_1", "EMAIL")
        db.upsert_token("s2@test.com", "REDACTED_EMAIL_2", "EMAIL")
        db.upsert_token("s3@test.com", "REDACTED_EMAIL_3", "EMAIL")
        db.set_counter("EMAIL", 3)
        db.tag_session_pii("s1", ["s1@test.com"])
        db.tag_session_pii("s2", ["s2@test.com"])
        db.tag_session_pii("s3", ["s3@test.com"])
        db.close()

        store = ConcurrentSessionStore(sessions_dir)
        await store.start()

        assert set(store.session_ids) == {"s1", "s2", "s3"}
        tm = store.shared_map
        assert tm.get_pii("REDACTED_EMAIL_1") == "s1@test.com"
        assert tm.get_pii("REDACTED_EMAIL_2") == "s2@test.com"
        assert tm.get_pii("REDACTED_EMAIL_3") == "s3@test.com"

        await store.stop()

    async def test_load_creates_storage_dir_if_missing(self, tmp_path: Path) -> None:
        storage = tmp_path / "brand_new" / "sessions"
        assert not storage.exists()

        store = ConcurrentSessionStore(storage)
        await store.start()

        assert storage.exists()
        await store.stop()


# ---------------------------------------------------------------------------
# Flush round-trip: save then load
# ---------------------------------------------------------------------------


class TestFlushRoundTrip:
    """Save data via write-through, create a new store, and verify restoration."""

    async def test_save_and_restore(self, tmp_path: Path) -> None:
        # -- Phase 1: create and populate --
        store1 = await _make_store(tmp_path)
        try:
            tm = await store1.get_or_create_session("round-trip")
            tm.get_or_create_token("alice@corp.com", "EMAIL", source="presidio")
            tm.get_or_create_token("Bob Smith", "PERSON", source="regex")
            tm.get_or_create_token("555-1234", "PHONE", source="regex")
            store1.tag_session_pii("round-trip", ["alice@corp.com", "Bob Smith", "555-1234"])
        finally:
            await store1.stop()

        # -- Phase 2: new store loads from DB --
        store2 = await _make_store(tmp_path)
        try:
            assert store2.has_session("round-trip")
            restored = await store2.get_or_create_session("round-trip")
            assert restored.size == 3
            assert restored.get_pii("REDACTED_EMAIL_1") == "alice@corp.com"
            assert restored.get_pii("REDACTED_PERSON_1") == "Bob Smith"
            assert restored.get_pii("REDACTED_PHONE_1") == "555-1234"
            assert restored.get_token("alice@corp.com") == "REDACTED_EMAIL_1"
        finally:
            await store2.stop()

    async def test_continued_use_after_restore(self, tmp_path: Path) -> None:
        """After restoring, new tokens should use correct counter values."""
        store1 = await _make_store(tmp_path)
        try:
            tm = await store1.get_or_create_session("cont")
            tm.get_or_create_token("a@b.com", "EMAIL")
            tm.get_or_create_token("c@d.com", "EMAIL")
        finally:
            await store1.stop()

        store2 = await _make_store(tmp_path)
        try:
            tm2 = await store2.get_or_create_session("cont")
            new_token = tm2.get_or_create_token("e@f.com", "EMAIL")
            assert new_token == "REDACTED_EMAIL_3"
        finally:
            await store2.stop()

    async def test_multiple_writes_persist(self, tmp_path: Path) -> None:
        """Multiple writes accumulate in the DB."""
        store = await _make_store(tmp_path)
        try:
            tm = await store.get_or_create_session("overwrite")

            tm.get_or_create_token("a@b.com", "EMAIL")
            tm.get_or_create_token("c@d.com", "EMAIL")

            # Drain pending writes
            store._drain_pending_writes()

            # Verify DB has both
            db = TokenDB(tmp_path / "scruxy.db")
            db.open()
            try:
                tokens = db.get_all_tokens()
                assert len(tokens) == 2
                assert db.get_counter("EMAIL") == 2
            finally:
                db.close()
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# In-memory mode (persistent=False)
# ---------------------------------------------------------------------------


class TestInMemoryMode:
    """When persistent=False, tokens work but no SQLite DB is created."""

    async def test_no_db_file_created(self, tmp_path: Path) -> None:
        store = ConcurrentSessionStore(
            tmp_path / "sessions", persistent=False
        )
        await store.start()
        try:
            tm = await store.get_or_create_session("mem-test")
            tm.get_or_create_token("alice@corp.com", "EMAIL", source="test")
            assert tm.size == 1
            assert tm.get_token("alice@corp.com") == "REDACTED_EMAIL_1"
        finally:
            await store.stop()

        # No scruxy.db should exist
        assert not (tmp_path / "scruxy.db").exists()

    async def test_tokens_work_in_memory(self, tmp_path: Path) -> None:
        store = ConcurrentSessionStore(
            tmp_path / "sessions", persistent=False
        )
        await store.start()
        try:
            tm = await store.get_or_create_session("s1")
            t1 = tm.get_or_create_token("John Doe", "PERSON")
            t2 = tm.get_or_create_token("jane@co.com", "EMAIL")
            assert t1 == "REDACTED_PERSON_1"
            assert t2 == "REDACTED_EMAIL_1"
            assert tm.get_pii("REDACTED_PERSON_1") == "John Doe"
        finally:
            await store.stop()

    async def test_session_pii_tagging_in_memory(self, tmp_path: Path) -> None:
        store = ConcurrentSessionStore(
            tmp_path / "sessions", persistent=False
        )
        await store.start()
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("alice@test.com", "EMAIL")
            store.tag_session_pii("s1", ["alice@test.com"])
            assert store.get_session_pii_count("s1") == 1
        finally:
            await store.stop()

    async def test_clear_all_in_memory(self, tmp_path: Path) -> None:
        store = ConcurrentSessionStore(
            tmp_path / "sessions", persistent=False
        )
        await store.start()
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("test@test.com", "EMAIL")
            await store.clear_all_mappings()
            assert tm.size == 0
        finally:
            await store.stop()

    async def test_data_lost_on_restart(self, tmp_path: Path) -> None:
        """In-memory mode: data does not survive restart."""
        store1 = ConcurrentSessionStore(
            tmp_path / "sessions", persistent=False
        )
        await store1.start()
        try:
            tm = await store1.get_or_create_session("s1")
            tm.get_or_create_token("secret@test.com", "EMAIL")
        finally:
            await store1.stop()

        store2 = ConcurrentSessionStore(
            tmp_path / "sessions", persistent=False
        )
        await store2.start()
        try:
            tm2 = await store2.get_or_create_session("s1")
            assert tm2.size == 0
        finally:
            await store2.stop()
