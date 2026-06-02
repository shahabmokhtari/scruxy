# SQLite Token Storage Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace JSON file storage with SQLite for the token map, session PII tracking, and counters.

**Architecture:** Single `~/.scruxy/scruxy.db` file with three tables (`tokens`, `counters`, `session_pii`). In-memory cache (`_scrub`/`_unscrub` dicts) for pipeline speed. DB is source of truth, cache rebuilt on startup. Sliding expiration via `last_access` column. Auto-migration from `token_map.json` on first run.

**Tech Stack:** Python 3.11+ `sqlite3` (stdlib), `aiosqlite` for async, existing `TokenMap` + `ConcurrentSessionStore` classes.

---

### Task 1: Add aiosqlite dependency

**Files:**
- Modify: `pyproject.toml`

**Step 1:** Add `"aiosqlite>=0.20"` to `dependencies` list in `pyproject.toml`.

**Step 2:** Run: `pip install aiosqlite`

**Step 3:** Commit: `git commit -m "Add aiosqlite dependency"`

---

### Task 2: Create SQLite database module

**Files:**
- Create: `src/scruxy/tokenmap/db.py`
- Test: `tests/test_token_db.py`

This module owns the DB connection, schema creation, and all SQL operations. It's a thin layer — no business logic.

**Step 1: Write failing tests**

```python
# tests/test_token_db.py
"""Tests for SQLite token database."""
import time
from pathlib import Path
import pytest
from scruxy.tokenmap.db import TokenDB


class TestTokenDB:

    def test_create_db(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        assert (tmp_path / "test.db").exists()
        db.close()

    def test_insert_and_get(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        db.upsert_token("john@test.com", "REDACTED_EMAIL_1", "EMAIL_ADDRESS", "presidio")
        row = db.get_by_original("john@test.com")
        assert row is not None
        assert row["scrubbed"] == "REDACTED_EMAIL_1"
        assert row["type"] == "EMAIL_ADDRESS"
        db.close()

    def test_get_by_scrubbed(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        db.upsert_token("john@test.com", "REDACTED_EMAIL_1", "EMAIL_ADDRESS", "presidio")
        row = db.get_by_scrubbed("REDACTED_EMAIL_1")
        assert row is not None
        assert row["original"] == "john@test.com"
        db.close()

    def test_last_access_updated_on_get(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        db.upsert_token("john@test.com", "REDACTED_EMAIL_1", "EMAIL", "presidio")
        row1 = db.get_by_original("john@test.com")
        time.sleep(0.01)
        row2 = db.get_by_original("john@test.com")
        assert row2["last_access"] >= row1["last_access"]
        db.close()

    def test_delete_token(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        db.upsert_token("a@b.com", "REDACTED_EMAIL_1", "EMAIL", "regex")
        assert db.delete_token("a@b.com") is True
        assert db.get_by_original("a@b.com") is None
        db.close()

    def test_get_all(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        db.upsert_token("a@b.com", "REDACTED_EMAIL_1", "EMAIL", "regex")
        db.upsert_token("John", "REDACTED_PERSON_1", "PERSON", "presidio")
        rows = db.get_all_tokens()
        assert len(rows) == 2
        db.close()

    def test_purge_expired(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        db.upsert_token("old@test.com", "REDACTED_EMAIL_1", "EMAIL", "regex")
        # Backdate last_access
        db._conn.execute("UPDATE tokens SET last_access = ? WHERE original = ?",
                         (time.time() - 10000, "old@test.com"))
        db.upsert_token("new@test.com", "REDACTED_EMAIL_2", "EMAIL", "regex")
        purged = db.purge_expired(max_age_seconds=5000)
        assert purged == 1
        assert db.get_by_original("old@test.com") is None
        assert db.get_by_original("new@test.com") is not None
        db.close()

    def test_counter_get_and_increment(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        assert db.get_counter("EMAIL") == 0
        db.set_counter("EMAIL", 3)
        assert db.get_counter("EMAIL") == 3
        db.close()

    def test_session_pii_tag_and_get(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        db.upsert_token("a@b.com", "REDACTED_EMAIL_1", "EMAIL", "regex")
        db.tag_session_pii("s1", ["a@b.com"])
        pii = db.get_session_pii("s1")
        assert "a@b.com" in pii
        db.close()

    def test_delete_exclusive_session(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        db.upsert_token("shared@t.com", "REDACTED_EMAIL_1", "EMAIL", "regex")
        db.upsert_token("exclusive@t.com", "REDACTED_EMAIL_2", "EMAIL", "regex")
        db.tag_session_pii("s1", ["shared@t.com", "exclusive@t.com"])
        db.tag_session_pii("s2", ["shared@t.com"])
        removed = db.delete_session_exclusive("s1")
        assert removed == 1
        assert db.get_by_original("shared@t.com") is not None
        assert db.get_by_original("exclusive@t.com") is None
        db.close()

    def test_clear_all(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        db.upsert_token("a@b.com", "REDACTED_EMAIL_1", "EMAIL", "regex")
        db.set_counter("EMAIL", 1)
        db.tag_session_pii("s1", ["a@b.com"])
        db.clear_all()
        assert len(db.get_all_tokens()) == 0
        assert db.get_counter("EMAIL") == 0
        assert len(db.get_session_pii("s1")) == 0
        db.close()

    def test_rebuild_counters(self, tmp_path: Path) -> None:
        db = TokenDB(tmp_path / "test.db")
        db.open()
        db.upsert_token("a@b.com", "REDACTED_EMAIL_1", "EMAIL", "regex")
        db.upsert_token("c@d.com", "REDACTED_EMAIL_2", "EMAIL", "regex")
        db.upsert_token("John", "REDACTED_PERSON_1", "PERSON", "presidio")
        db.rebuild_counters_from_tokens()
        assert db.get_counter("EMAIL") == 2
        assert db.get_counter("PERSON") == 1
        db.close()
```

**Step 2: Implement `src/scruxy/tokenmap/db.py`**

```python
"""SQLite storage for token mappings, counters, and session PII tracking."""
from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    original    TEXT PRIMARY KEY,
    scrubbed    TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL,
    last_access REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_scrubbed ON tokens(scrubbed);
CREATE INDEX IF NOT EXISTS idx_tokens_last_access ON tokens(last_access);

CREATE TABLE IF NOT EXISTS counters (
    type  TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS session_pii (
    session_id TEXT NOT NULL,
    original   TEXT NOT NULL,
    PRIMARY KEY (session_id, original),
    FOREIGN KEY (original) REFERENCES tokens(original) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_session_pii_session ON session_pii(session_id);
"""


class TokenDB:
    """Synchronous SQLite wrapper for token storage."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path).expanduser()
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # -- Token CRUD --------------------------------------------------------

    def upsert_token(self, original: str, scrubbed: str, entity_type: str, source: str = "") -> None:
        now = time.time()
        self._conn.execute(
            "INSERT INTO tokens (original, scrubbed, type, source, created_at, last_access) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(original) DO UPDATE SET last_access=?, source=?",
            (original, scrubbed, entity_type, source, now, now, now, source),
        )
        self._conn.commit()

    def get_by_original(self, original: str) -> dict | None:
        now = time.time()
        row = self._conn.execute("SELECT * FROM tokens WHERE original=?", (original,)).fetchone()
        if row is None:
            return None
        self._conn.execute("UPDATE tokens SET last_access=? WHERE original=?", (now, original))
        self._conn.commit()
        return dict(row)

    def get_by_scrubbed(self, scrubbed: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM tokens WHERE scrubbed=?", (scrubbed,)).fetchone()
        return dict(row) if row else None

    def get_all_tokens(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM tokens ORDER BY created_at").fetchall()
        return [dict(r) for r in rows]

    def delete_token(self, original: str) -> bool:
        cursor = self._conn.execute("DELETE FROM tokens WHERE original=?", (original,))
        self._conn.commit()
        return cursor.rowcount > 0

    def purge_expired(self, max_age_seconds: float) -> int:
        if max_age_seconds <= 0:
            return 0
        cutoff = time.time() - max_age_seconds
        cursor = self._conn.execute("DELETE FROM tokens WHERE last_access < ?", (cutoff,))
        self._conn.commit()
        return cursor.rowcount

    def clear_all(self) -> None:
        self._conn.execute("DELETE FROM session_pii")
        self._conn.execute("DELETE FROM tokens")
        self._conn.execute("DELETE FROM counters")
        self._conn.commit()

    # -- Counters ----------------------------------------------------------

    def get_counter(self, entity_type: str) -> int:
        row = self._conn.execute("SELECT count FROM counters WHERE type=?", (entity_type,)).fetchone()
        return row["count"] if row else 0

    def set_counter(self, entity_type: str, value: int) -> None:
        self._conn.execute(
            "INSERT INTO counters (type, count) VALUES (?, ?) ON CONFLICT(type) DO UPDATE SET count=?",
            (entity_type, value, value),
        )
        self._conn.commit()

    def rebuild_counters_from_tokens(self) -> None:
        """Recalculate counters by parsing REDACTED_{TYPE}_{N} tokens."""
        self._conn.execute("DELETE FROM counters")
        rows = self._conn.execute("SELECT scrubbed, type FROM tokens").fetchall()
        counters: dict[str, int] = {}
        for row in rows:
            et = row["type"]
            token = row["scrubbed"]
            parts = token.rsplit("_", 1)
            if len(parts) == 2:
                try:
                    n = int(parts[1])
                    counters[et] = max(counters.get(et, 0), n)
                    continue
                except ValueError:
                    pass
            counters[et] = counters.get(et, 0) + 1
        for et, count in counters.items():
            self.set_counter(et, count)

    # -- Session PII -------------------------------------------------------

    def tag_session_pii(self, session_id: str, originals: list[str]) -> None:
        for orig in originals:
            self._conn.execute(
                "INSERT OR IGNORE INTO session_pii (session_id, original) VALUES (?, ?)",
                (session_id, orig),
            )
        self._conn.commit()

    def get_session_pii(self, session_id: str) -> set[str]:
        rows = self._conn.execute(
            "SELECT original FROM session_pii WHERE session_id=?", (session_id,)
        ).fetchall()
        return {r["original"] for r in rows}

    def get_all_session_ids(self) -> list[str]:
        rows = self._conn.execute("SELECT DISTINCT session_id FROM session_pii").fetchall()
        return [r["session_id"] for r in rows]

    def delete_session_exclusive(self, session_id: str) -> int:
        """Delete tokens used ONLY by this session. Returns count removed."""
        cursor = self._conn.execute("""
            DELETE FROM tokens WHERE original IN (
                SELECT sp.original FROM session_pii sp
                WHERE sp.session_id = ?
                AND sp.original NOT IN (
                    SELECT original FROM session_pii WHERE session_id != ?
                )
            )
        """, (session_id, session_id))
        self._conn.execute("DELETE FROM session_pii WHERE session_id=?", (session_id,))
        self._conn.commit()
        removed = cursor.rowcount
        if removed > 0:
            self.rebuild_counters_from_tokens()
        return removed

    def clear_session_pii(self, session_id: str) -> None:
        self._conn.execute("DELETE FROM session_pii WHERE session_id=?", (session_id,))
        self._conn.commit()

    # -- Migration ---------------------------------------------------------

    def migrate_from_json(self, token_map_path: Path) -> int:
        """Import records from a token_map.json file. Returns count imported."""
        import json
        if not token_map_path.exists():
            return 0
        if self._conn.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] > 0:
            return 0  # DB already has data

        data = json.loads(token_map_path.read_text(encoding="utf-8"))
        scrub = data.get("scrub", {})
        entity_types = data.get("entity_types", {})
        timestamps = data.get("entry_timestamps", {})
        counters = data.get("counters", {})
        now = time.time()

        for original, scrubbed in scrub.items():
            et = entity_types.get(original, "UNKNOWN")
            ts = timestamps.get(original, now)
            self._conn.execute(
                "INSERT OR IGNORE INTO tokens (original, scrubbed, type, source, created_at, last_access) "
                "VALUES (?, ?, ?, '', ?, ?)",
                (original, scrubbed, et, ts, ts),
            )
        for et, count in counters.items():
            self.set_counter(et, count)
        self._conn.commit()

        # Rename old file
        bak = token_map_path.with_suffix(".json.bak")
        token_map_path.rename(bak)
        logger.info("Migrated %d tokens from %s → DB, backed up to %s", len(scrub), token_map_path, bak)
        return len(scrub)
```

**Step 3:** Run tests: `pytest tests/test_token_db.py -v`

**Step 4:** Commit: `git commit -m "Add SQLite token database module with tests"`

---

### Task 3: Wire TokenMap to use TokenDB

**Files:**
- Modify: `src/scruxy/tokenmap/token_map.py`
- Modify: `src/scruxy/tokenmap/service.py`

Replace JSON serialization with DB calls. Keep in-memory dicts as cache. Load from DB on startup, write-through on mutations.

Key changes to `TokenMap`:
- Add `_db: TokenDB | None` parameter
- `get_or_create_token()`: write-through to DB
- `remove_entry()` / `clear()`: sync to DB
- Remove `to_dict()` / `from_dict()` (no longer needed for persistence)
- Keep `to_dict()` for API responses (tester, tokens page) but mark as read-only

Key changes to `ConcurrentSessionStore`:
- Create `TokenDB` in `__init__`, open in `start()`, close in `stop()`
- `_load_from_disk()` → `_load_from_db()`: populate cache from DB
- `flush_session()` / `_flush_shared_map()` → no-op (write-through, no batching needed)
- `delete_session_mappings()` → delegate to `TokenDB.delete_session_exclusive()`
- `clear_all_mappings()` → delegate to `TokenDB.clear_all()`
- `tag_session_pii()` → write-through to DB
- Auto-migration: call `db.migrate_from_json()` on startup

**Step 1:** Implement changes to token_map.py and service.py

**Step 2:** Run all tests: `pytest tests/ -q`

**Step 3:** Commit: `git commit -m "Wire TokenMap and ConcurrentSessionStore to SQLite"`

---

### Task 4: Update existing tests

**Files:**
- Modify: `tests/test_concurrent_sessions.py`
- Modify: `tests/test_disk_persistence.py`
- Modify: `tests/test_shared_token_map.py`
- Modify: `tests/test_e2e.py`

Update tests that check for JSON files on disk to instead verify DB state. The `test_disk_persistence.py` tests need the most changes (they check for `token_map.json` and `session_pii.json` paths).

**Step 1:** Update tests

**Step 2:** Run: `pytest tests/ -q`

**Step 3:** Commit: `git commit -m "Update tests for SQLite storage"`

---

### Task 5: Settings UI for expiration

**Files:**
- Modify: `src/scruxy/ui/static/js/settings.js` (already has expiration_hours field)

The `expiration_hours` field already exists in the Settings UI. Verify it works end-to-end with the new sliding expiration. No code changes expected — just verification.

**Step 1:** Manual test: change expiration_hours in Settings → verify purge runs on next flush

**Step 2:** Commit if any fixes needed

---

### Task 6: Clean up old JSON artifacts

**Files:**
- Modify: `src/scruxy/tokenmap/token_map.py` — remove `to_dict()`/`from_dict()` JSON methods (keep for API use)
- Delete old `session_pii.json` handling from service.py

**Step 1:** Clean up

**Step 2:** Run: `pytest tests/ -q`

**Step 3:** Commit: `git commit -m "Remove JSON persistence code, SQLite is sole storage"`
