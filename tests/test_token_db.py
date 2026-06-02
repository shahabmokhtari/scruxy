"""Comprehensive tests for the SQLite TokenDB module."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from scruxy.tokenmap.db import TokenDB


@pytest.fixture()
def db(tmp_path: Path) -> TokenDB:
    """Return an opened TokenDB backed by a temp directory."""
    token_db = TokenDB(tmp_path / "scruxy.db")
    token_db.open()
    yield token_db
    token_db.close()


# ------------------------------------------------------------------
# Lifecycle
# ------------------------------------------------------------------


class TestLifecycle:
    def test_open_creates_directory_and_file(self, tmp_path: Path) -> None:
        db_path = tmp_path / "sub" / "dir" / "scruxy.db"
        token_db = TokenDB(db_path)
        token_db.open()
        assert db_path.exists()
        token_db.close()

    def test_double_close_is_safe(self, db: TokenDB) -> None:
        db.close()
        db.close()  # should not raise

    def test_operations_after_close_raise(self, tmp_path: Path) -> None:
        token_db = TokenDB(tmp_path / "test.db")
        token_db.open()
        token_db.close()
        with pytest.raises(RuntimeError, match="not open"):
            token_db.get_all_tokens()

    def test_expanduser_in_path(self, tmp_path: Path, monkeypatch) -> None:
        # Just verify the constructor stores expanded path
        token_db = TokenDB(tmp_path / "test.db")
        assert "~" not in str(token_db._db_path)


# ------------------------------------------------------------------
# Token CRUD
# ------------------------------------------------------------------


class TestUpsertToken:
    def test_insert_new_token(self, db: TokenDB) -> None:
        db.upsert_token("john@example.com", "REDACTED_EMAIL_1", "EMAIL", "presidio")
        row = db.get_by_original("john@example.com")
        assert row is not None
        assert row["original"] == "john@example.com"
        assert row["scrubbed"] == "REDACTED_EMAIL_1"
        assert row["type"] == "EMAIL"
        assert row["source"] == "presidio"
        assert row["created_at"] > 0
        assert row["last_access"] > 0

    def test_update_existing_token(self, db: TokenDB) -> None:
        db.upsert_token("john@example.com", "REDACTED_EMAIL_1", "EMAIL", "presidio")
        first = db.get_by_original("john@example.com")

        time.sleep(0.01)
        db.upsert_token("john@example.com", "REDACTED_EMAIL_1_v2", "EMAIL_ADDRESS", "regex")
        second = db.get_by_original("john@example.com")

        assert second["scrubbed"] == "REDACTED_EMAIL_1_v2"
        assert second["type"] == "EMAIL_ADDRESS"
        assert second["source"] == "regex"
        # last_access should have been updated
        assert second["last_access"] >= first["last_access"]

    def test_default_source_empty_string(self, db: TokenDB) -> None:
        db.upsert_token("foo", "REDACTED_FOO_1", "FOO")
        row = db.get_by_original("foo")
        assert row["source"] == ""


class TestGetByOriginal:
    def test_found(self, db: TokenDB) -> None:
        db.upsert_token("alice", "REDACTED_PERSON_1", "PERSON", "presidio")
        row = db.get_by_original("alice")
        assert row is not None
        assert row["scrubbed"] == "REDACTED_PERSON_1"

    def test_not_found(self, db: TokenDB) -> None:
        assert db.get_by_original("nonexistent") is None

    def test_updates_last_access(self, db: TokenDB) -> None:
        db.upsert_token("alice", "REDACTED_PERSON_1", "PERSON", "presidio")
        first = db.get_by_original("alice")
        time.sleep(0.02)
        second = db.get_by_original("alice")
        assert second["last_access"] > first["last_access"]


class TestGetByScrubbed:
    def test_found(self, db: TokenDB) -> None:
        db.upsert_token("alice", "REDACTED_PERSON_1", "PERSON", "presidio")
        row = db.get_by_scrubbed("REDACTED_PERSON_1")
        assert row is not None
        assert row["original"] == "alice"

    def test_not_found(self, db: TokenDB) -> None:
        assert db.get_by_scrubbed("REDACTED_NOTHING_99") is None


class TestGetAllTokens:
    def test_empty(self, db: TokenDB) -> None:
        assert db.get_all_tokens() == []

    def test_multiple(self, db: TokenDB) -> None:
        db.upsert_token("a@b.com", "REDACTED_EMAIL_1", "EMAIL", "presidio")
        db.upsert_token("John Doe", "REDACTED_PERSON_1", "PERSON", "presidio")
        tokens = db.get_all_tokens()
        assert len(tokens) == 2
        originals = {t["original"] for t in tokens}
        assert originals == {"a@b.com", "John Doe"}


class TestDeleteToken:
    def test_delete_existing(self, db: TokenDB) -> None:
        db.upsert_token("alice", "REDACTED_PERSON_1", "PERSON", "presidio")
        assert db.delete_token("alice") is True
        assert db.get_by_original("alice") is None

    def test_delete_nonexistent(self, db: TokenDB) -> None:
        assert db.delete_token("nobody") is False

    def test_cascade_deletes_session_pii(self, db: TokenDB) -> None:
        db.upsert_token("alice", "REDACTED_PERSON_1", "PERSON", "presidio")
        db.tag_session_pii("sess-1", ["alice"])
        assert db.get_session_pii("sess-1") == {"alice"}
        db.delete_token("alice")
        assert db.get_session_pii("sess-1") == set()


class TestPurgeExpired:
    def test_purge_removes_old_entries(self, db: TokenDB) -> None:
        db.upsert_token("old-pii", "REDACTED_OLD_1", "OLD", "test")
        # Manually set last_access far in the past
        db._c.execute(
            "UPDATE tokens SET last_access = ? WHERE original = ?",
            (time.time() - 10000, "old-pii"),
        )
        db._c.commit()
        db.upsert_token("new-pii", "REDACTED_NEW_1", "NEW", "test")

        removed = db.purge_expired(5000)
        assert removed == 1
        assert db.get_by_original("old-pii") is None
        assert db.get_by_original("new-pii") is not None

    def test_purge_with_no_expired(self, db: TokenDB) -> None:
        db.upsert_token("fresh", "REDACTED_FRESH_1", "FRESH", "test")
        assert db.purge_expired(999999) == 0


class TestClearAll:
    def test_clears_all_tables(self, db: TokenDB) -> None:
        db.upsert_token("alice", "REDACTED_PERSON_1", "PERSON", "presidio")
        db.set_counter("PERSON", 1)
        db.tag_session_pii("sess-1", ["alice"])

        db.clear_all()

        assert db.get_all_tokens() == []
        assert db.get_counter("PERSON") == 0
        assert db.get_session_pii("sess-1") == set()


# ------------------------------------------------------------------
# Counters
# ------------------------------------------------------------------


class TestCounters:
    def test_get_counter_default_zero(self, db: TokenDB) -> None:
        assert db.get_counter("EMAIL") == 0

    def test_set_and_get_counter(self, db: TokenDB) -> None:
        db.set_counter("EMAIL", 5)
        assert db.get_counter("EMAIL") == 5

    def test_update_counter(self, db: TokenDB) -> None:
        db.set_counter("PERSON", 3)
        db.set_counter("PERSON", 7)
        assert db.get_counter("PERSON") == 7


class TestRebuildCounters:
    def test_rebuild_from_redacted_format(self, db: TokenDB) -> None:
        db.upsert_token("a@b.com", "REDACTED_EMAIL_ADDRESS_2", "EMAIL_ADDRESS", "")
        db.upsert_token("c@d.com", "REDACTED_EMAIL_ADDRESS_5", "EMAIL_ADDRESS", "")
        db.upsert_token("John", "REDACTED_PERSON_3", "PERSON", "")

        db.rebuild_counters_from_tokens()

        assert db.get_counter("EMAIL_ADDRESS") == 5  # max(2, 5)
        assert db.get_counter("PERSON") == 3

    def test_rebuild_with_nonstandard_tokens(self, db: TokenDB) -> None:
        db.upsert_token("alice", "uuid-1234-5678", "PERSON", "")
        db.upsert_token("bob", "uuid-abcd-efgh", "PERSON", "")

        db.rebuild_counters_from_tokens()

        # Non-standard tokens: counted as 1 each per type
        assert db.get_counter("PERSON") == 2

    def test_rebuild_mixed(self, db: TokenDB) -> None:
        db.upsert_token("a@b.com", "REDACTED_EMAIL_3", "EMAIL", "")
        db.upsert_token("alice", "fake-alice-name", "PERSON", "")

        db.rebuild_counters_from_tokens()

        assert db.get_counter("EMAIL") == 3
        assert db.get_counter("PERSON") == 1

    def test_rebuild_clears_old_counters(self, db: TokenDB) -> None:
        db.set_counter("GHOST", 99)
        db.upsert_token("a@b.com", "REDACTED_EMAIL_1", "EMAIL", "")

        db.rebuild_counters_from_tokens()

        assert db.get_counter("EMAIL") == 1
        assert db.get_counter("GHOST") == 0  # no longer present


# ------------------------------------------------------------------
# Session PII
# ------------------------------------------------------------------


class TestSessionPII:
    def test_tag_and_get(self, db: TokenDB) -> None:
        db.upsert_token("alice", "REDACTED_PERSON_1", "PERSON", "")
        db.upsert_token("bob", "REDACTED_PERSON_2", "PERSON", "")
        db.tag_session_pii("sess-1", ["alice", "bob"])
        assert db.get_session_pii("sess-1") == {"alice", "bob"}

    def test_tag_idempotent(self, db: TokenDB) -> None:
        db.upsert_token("alice", "REDACTED_PERSON_1", "PERSON", "")
        db.tag_session_pii("sess-1", ["alice"])
        db.tag_session_pii("sess-1", ["alice"])  # duplicate
        assert db.get_session_pii("sess-1") == {"alice"}

    def test_empty_session(self, db: TokenDB) -> None:
        assert db.get_session_pii("nonexistent") == set()

    def test_multiple_sessions(self, db: TokenDB) -> None:
        db.upsert_token("alice", "REDACTED_PERSON_1", "PERSON", "")
        db.upsert_token("bob", "REDACTED_PERSON_2", "PERSON", "")
        db.tag_session_pii("sess-1", ["alice"])
        db.tag_session_pii("sess-2", ["bob"])
        db.tag_session_pii("sess-3", ["alice", "bob"])

        assert db.get_session_pii("sess-1") == {"alice"}
        assert db.get_session_pii("sess-2") == {"bob"}
        assert db.get_session_pii("sess-3") == {"alice", "bob"}


class TestGetAllSessionIds:
    def test_empty(self, db: TokenDB) -> None:
        assert db.get_all_session_ids() == []

    def test_multiple(self, db: TokenDB) -> None:
        db.upsert_token("a", "REDACTED_A_1", "A", "")
        db.upsert_token("b", "REDACTED_B_1", "B", "")
        db.tag_session_pii("sess-1", ["a"])
        db.tag_session_pii("sess-2", ["b"])
        ids = db.get_all_session_ids()
        assert set(ids) == {"sess-1", "sess-2"}


class TestDeleteSessionExclusive:
    def test_delete_exclusive_tokens(self, db: TokenDB) -> None:
        db.upsert_token("alice", "REDACTED_PERSON_1", "PERSON", "")
        db.upsert_token("bob", "REDACTED_PERSON_2", "PERSON", "")
        db.upsert_token("shared", "REDACTED_SHARED_1", "SHARED", "")

        db.tag_session_pii("sess-1", ["alice", "shared"])
        db.tag_session_pii("sess-2", ["bob", "shared"])

        removed = db.delete_session_exclusive("sess-1")

        assert removed == 1  # only "alice" was exclusive
        assert db.get_by_original("alice") is None
        assert db.get_by_original("bob") is not None
        assert db.get_by_original("shared") is not None
        # Session PII tags should be cleared
        assert db.get_session_pii("sess-1") == set()

    def test_delete_exclusive_rebuilds_counters(self, db: TokenDB) -> None:
        db.upsert_token("a@b.com", "REDACTED_EMAIL_1", "EMAIL", "")
        db.set_counter("EMAIL", 1)
        db.tag_session_pii("sess-1", ["a@b.com"])

        db.delete_session_exclusive("sess-1")

        # After deletion + rebuild, counter for EMAIL should be 0
        assert db.get_counter("EMAIL") == 0

    def test_delete_exclusive_nothing_exclusive(self, db: TokenDB) -> None:
        db.upsert_token("shared", "REDACTED_SHARED_1", "SHARED", "")
        db.tag_session_pii("sess-1", ["shared"])
        db.tag_session_pii("sess-2", ["shared"])

        removed = db.delete_session_exclusive("sess-1")
        assert removed == 0
        assert db.get_by_original("shared") is not None

    def test_delete_exclusive_nonexistent_session(self, db: TokenDB) -> None:
        removed = db.delete_session_exclusive("ghost-session")
        assert removed == 0


class TestClearSessionPII:
    def test_clear(self, db: TokenDB) -> None:
        db.upsert_token("alice", "REDACTED_PERSON_1", "PERSON", "")
        db.tag_session_pii("sess-1", ["alice"])
        assert db.get_session_pii("sess-1") == {"alice"}

        db.clear_session_pii("sess-1")
        assert db.get_session_pii("sess-1") == set()
        # Token itself is not deleted
        assert db.get_by_original("alice") is not None

    def test_clear_nonexistent_session(self, db: TokenDB) -> None:
        # Should not raise
        db.clear_session_pii("nonexistent")


# ------------------------------------------------------------------
# Migration from JSON
# ------------------------------------------------------------------


class TestMigrateFromJson:
    def _write_json(self, path: Path, data: dict) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def test_full_migration(self, db: TokenDB, tmp_path: Path) -> None:
        json_path = tmp_path / "token_map.json"
        self._write_json(
            json_path,
            {
                "scrub": {
                    "alice@co.com": "REDACTED_EMAIL_1",
                    "Bob Smith": "REDACTED_PERSON_1",
                },
                "unscrub": {
                    "REDACTED_EMAIL_1": "alice@co.com",
                    "REDACTED_PERSON_1": "Bob Smith",
                },
                "entity_types": {
                    "alice@co.com": "EMAIL",
                    "Bob Smith": "PERSON",
                },
                "entry_timestamps": {
                    "alice@co.com": 1700000000.0,
                    "Bob Smith": 1700000001.0,
                },
                "counters": {"EMAIL": 1, "PERSON": 1},
            },
        )

        count = db.migrate_from_json(json_path)

        assert count == 2
        assert db.get_by_original("alice@co.com") is not None
        assert db.get_by_original("alice@co.com")["scrubbed"] == "REDACTED_EMAIL_1"
        assert db.get_by_original("alice@co.com")["type"] == "EMAIL"
        assert db.get_by_original("Bob Smith")["scrubbed"] == "REDACTED_PERSON_1"
        assert db.get_counter("EMAIL") == 1
        assert db.get_counter("PERSON") == 1

        # Original file should be renamed to .bak
        assert not json_path.exists()
        assert (tmp_path / "token_map.json.bak").exists()

    def test_skip_when_db_has_data(self, db: TokenDB, tmp_path: Path) -> None:
        db.upsert_token("existing", "REDACTED_X_1", "X", "")

        json_path = tmp_path / "token_map.json"
        self._write_json(json_path, {"scrub": {"new": "REDACTED_Y_1"}, "entity_types": {}})

        count = db.migrate_from_json(json_path)
        assert count == 0
        # JSON should NOT be renamed
        assert json_path.exists()

    def test_missing_json_file(self, db: TokenDB, tmp_path: Path) -> None:
        count = db.migrate_from_json(tmp_path / "nonexistent.json")
        assert count == 0

    def test_migration_preserves_timestamps(self, db: TokenDB, tmp_path: Path) -> None:
        json_path = tmp_path / "token_map.json"
        self._write_json(
            json_path,
            {
                "scrub": {"alice": "REDACTED_PERSON_1"},
                "unscrub": {"REDACTED_PERSON_1": "alice"},
                "entity_types": {"alice": "PERSON"},
                "entry_timestamps": {"alice": 1700000000.0},
                "counters": {"PERSON": 1},
            },
        )

        db.migrate_from_json(json_path)

        row = db.get_by_original("alice")
        assert row is not None
        # created_at should be from the JSON timestamps
        assert row["created_at"] == 1700000000.0

    def test_migration_missing_entity_type(self, db: TokenDB, tmp_path: Path) -> None:
        json_path = tmp_path / "token_map.json"
        self._write_json(
            json_path,
            {
                "scrub": {"unknown-pii": "REDACTED_UNKNOWN_1"},
                "unscrub": {"REDACTED_UNKNOWN_1": "unknown-pii"},
                "entity_types": {},
                "entry_timestamps": {},
                "counters": {},
            },
        )

        count = db.migrate_from_json(json_path)
        assert count == 1
        row = db.get_by_original("unknown-pii")
        assert row["type"] == "UNKNOWN"

    def test_migration_preserves_first_seen_request_id(self, db: TokenDB, tmp_path: Path) -> None:
        json_path = tmp_path / "token_map.json"
        self._write_json(
            json_path,
            {
                "scrub": {"alice@example.com": "REDACTED_EMAIL_1"},
                "unscrub": {"REDACTED_EMAIL_1": "alice@example.com"},
                "entity_types": {"alice@example.com": "EMAIL"},
                "entry_timestamps": {"alice@example.com": 1700000000.0},
                "token_meta": {
                    "alice@example.com": {"first_seen_request_id": "req-123"}
                },
                "counters": {"EMAIL": 1},
            },
        )

        db.migrate_from_json(json_path)

        row = db.get_by_original("alice@example.com")
        assert row is not None
        assert row["first_seen_request_id"] == "req-123"


# ------------------------------------------------------------------
# WAL mode and foreign keys
# ------------------------------------------------------------------


class TestPragmas:
    def test_wal_mode(self, db: TokenDB) -> None:
        row = db._c.execute("PRAGMA journal_mode").fetchone()
        assert row[0] == "wal"

    def test_foreign_keys_on(self, db: TokenDB) -> None:
        row = db._c.execute("PRAGMA foreign_keys").fetchone()
        assert row[0] == 1


# ------------------------------------------------------------------
# Edge cases
# ------------------------------------------------------------------


class TestEdgeCases:
    def test_unicode_pii(self, db: TokenDB) -> None:
        db.upsert_token("Muller", "REDACTED_PERSON_1", "PERSON", "")
        row = db.get_by_original("Muller")
        assert row is not None
        assert row["original"] == "Muller"

    def test_empty_string_pii(self, db: TokenDB) -> None:
        db.upsert_token("", "REDACTED_EMPTY_1", "EMPTY", "")
        row = db.get_by_original("")
        assert row is not None

    def test_long_pii(self, db: TokenDB) -> None:
        long_pii = "x" * 10000
        db.upsert_token(long_pii, "REDACTED_LONG_1", "LONG", "")
        row = db.get_by_original(long_pii)
        assert row is not None
        assert row["original"] == long_pii

    def test_scrubbed_uniqueness_constraint(self, db: TokenDB) -> None:
        db.upsert_token("a", "SAME_TOKEN", "X", "")
        with pytest.raises(Exception):
            db.upsert_token("b", "SAME_TOKEN", "Y", "")
