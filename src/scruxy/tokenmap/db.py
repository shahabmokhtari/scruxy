"""SQLite storage layer for the token map.

Provides a synchronous :class:`TokenDB` that wraps a ``sqlite3`` connection
with WAL journaling, foreign-key support, and three tables (``tokens``,
``counters``, ``session_pii``).  All public methods are synchronous so
the service layer can call them via ``asyncio.to_thread``.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from os.path import expanduser
from pathlib import Path

logger = logging.getLogger(__name__)

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS tokens (
    original    TEXT PRIMARY KEY,
    scrubbed    TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL,
    last_access REAL NOT NULL,
    first_seen_request_id TEXT NOT NULL DEFAULT '',
    word_boundary INTEGER NOT NULL DEFAULT 0,
    case_sensitive INTEGER NOT NULL DEFAULT 1,
    exclude_from_prefilter INTEGER NOT NULL DEFAULT 0
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

CREATE TABLE IF NOT EXISTS _migrations (
    name        TEXT PRIMARY KEY,
    applied_at  REAL NOT NULL
);
"""


class TokenDB:
    """Synchronous SQLite wrapper for token map persistence.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file (``~`` is expanded).
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(expanduser(str(db_path)))
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Create the parent directory, connect, and initialise the schema.

        R71-10 fix: wrap schema initialisation + migrations in a
        try/except that closes the connection on failure.  Without
        this, a corrupt DB or a failed ``ALTER TABLE`` mid-migration
        leaks the open ``sqlite3.Connection`` (and its lock on the
        DB file) → next ``open()`` retry can't acquire the file.
        """
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        try:
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

            # Migration: add first_seen_request_id column if missing
            try:
                self._conn.execute("SELECT first_seen_request_id FROM tokens LIMIT 0")
            except sqlite3.OperationalError:
                self._conn.execute(
                    "ALTER TABLE tokens ADD COLUMN first_seen_request_id TEXT NOT NULL DEFAULT ''"
                )
                self._conn.commit()

            # Migration: add token metadata columns if missing
            for col, default in [
                ("word_boundary", "0"),
                ("case_sensitive", "1"),
                ("exclude_from_prefilter", "0"),
            ]:
                try:
                    self._conn.execute(f"SELECT {col} FROM tokens LIMIT 0")
                except sqlite3.OperationalError:
                    self._conn.execute(
                        f"ALTER TABLE tokens ADD COLUMN {col} INTEGER NOT NULL DEFAULT {default}"
                    )
                    self._conn.commit()
        except Exception:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
            raise

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def _c(self) -> sqlite3.Connection:
        """Return the active connection, raising if closed."""
        if self._conn is None:
            raise RuntimeError("TokenDB is not open")
        return self._conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        return dict(row)

    # ------------------------------------------------------------------
    # Token CRUD
    # ------------------------------------------------------------------

    def upsert_token(
        self,
        original: str,
        scrubbed: str,
        type: str,
        source: str = "",
        first_seen_request_id: str = "",
        *,
        word_boundary: bool = False,
        case_sensitive: bool = True,
        exclude_from_prefilter: bool = False,
    ) -> None:
        """Insert a new token or update an existing one.

        On conflict (same ``original``), the ``scrubbed``, ``type``,
        ``source``, ``last_access``, and matching metadata columns are
        updated; ``created_at`` and ``first_seen_request_id`` are preserved.
        """
        now = time.time()
        self._c.execute(
            """
            INSERT INTO tokens (original, scrubbed, type, source, created_at, last_access,
                                first_seen_request_id, word_boundary, case_sensitive, exclude_from_prefilter)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(original) DO UPDATE SET
                scrubbed              = excluded.scrubbed,
                type                  = excluded.type,
                source                = excluded.source,
                last_access           = excluded.last_access,
                word_boundary         = excluded.word_boundary,
                case_sensitive        = excluded.case_sensitive,
                exclude_from_prefilter = excluded.exclude_from_prefilter
            """,
            (original, scrubbed, type, source, now, now, first_seen_request_id,
             int(word_boundary), int(case_sensitive), int(exclude_from_prefilter)),
        )
        self._c.commit()

    def get_by_original(self, original: str) -> dict | None:
        """Look up a token by its original PII value.

        If found, ``last_access`` is updated (sliding expiration) and the
        row is returned as a :class:`dict`.
        """
        now = time.time()
        self._c.execute(
            "UPDATE tokens SET last_access = ? WHERE original = ?",
            (now, original),
        )
        self._c.commit()  # Always commit (UPDATE is a no-op if row doesn't exist)
        row = self._c.execute(
            "SELECT * FROM tokens WHERE original = ?", (original,)
        ).fetchone()
        return self._row_to_dict(row)

    def get_by_scrubbed(self, scrubbed: str) -> dict | None:
        """Reverse-lookup a token by its scrubbed value."""
        row = self._c.execute(
            "SELECT * FROM tokens WHERE scrubbed = ?", (scrubbed,)
        ).fetchone()
        return self._row_to_dict(row)

    def get_all_tokens(self) -> list[dict]:
        """Return all token rows as a list of dicts."""
        rows = self._c.execute("SELECT * FROM tokens").fetchall()
        return [dict(r) for r in rows]

    def evict_stale_tokens(self, max_idle_seconds: float) -> int:
        """Delete tokens whose ``last_access`` is older than *max_idle_seconds*.

        Unlike ``purge_expired`` (which uses an absolute age), this evicts
        tokens that haven't been *accessed* recently — i.e. their session
        hasn't been active.  Returns the number of rows removed.
        """
        cutoff = time.time() - max_idle_seconds
        cur = self._c.execute(
            "DELETE FROM tokens WHERE last_access < ?", (cutoff,)
        )
        self._c.commit()
        removed = cur.rowcount
        if removed:
            logger.info(
                "Evicted %d stale tokens (idle > %ds)", removed, int(max_idle_seconds)
            )
        return removed

    def delete_token(self, original: str) -> bool:
        """Delete a single token by original value. Returns ``True`` if removed."""
        cur = self._c.execute("DELETE FROM tokens WHERE original = ?", (original,))
        self._c.commit()
        return cur.rowcount > 0

    def purge_expired(self, max_age_seconds: float) -> int:
        """Delete tokens whose ``last_access`` is older than *max_age_seconds*.

        Returns the number of rows removed.
        """
        cutoff = time.time() - max_age_seconds
        cur = self._c.execute(
            "DELETE FROM tokens WHERE last_access < ?", (cutoff,)
        )
        self._c.commit()
        return cur.rowcount

    def clear_all(self) -> None:
        """Delete every row from all three tables."""
        self._c.execute("DELETE FROM session_pii")
        self._c.execute("DELETE FROM tokens")
        self._c.execute("DELETE FROM counters")
        self._c.commit()

    # ------------------------------------------------------------------
    # Counters
    # ------------------------------------------------------------------

    def get_counter(self, type: str) -> int:
        """Return the counter value for *type*, or ``0`` if unset."""
        row = self._c.execute(
            "SELECT count FROM counters WHERE type = ?", (type,)
        ).fetchone()
        return row["count"] if row is not None else 0

    def set_counter(self, type: str, value: int) -> None:
        """Set the counter for *type* to *value* (upsert)."""
        self._c.execute(
            """
            INSERT INTO counters (type, count) VALUES (?, ?)
            ON CONFLICT(type) DO UPDATE SET count = excluded.count
            """,
            (type, value),
        )
        self._c.commit()

    def rebuild_counters_from_tokens(self) -> None:
        """Recompute counters by parsing ``REDACTED_{TYPE}_{N}`` tokens.

        For each token, ``rsplit("_", 1)`` extracts the trailing integer
        ``N``; the maximum ``N`` per type becomes the counter.  Non-
        standard tokens (UUIDs, fake data) are counted by entity type.

        Uses a targeted SELECT (scrubbed + type only) to minimize data
        transferred from SQLite.
        """
        rows = self._c.execute("SELECT scrubbed, type FROM tokens").fetchall()

        new_counters: dict[str, int] = {}
        for row in rows:
            scrubbed: str = row["scrubbed"]
            entity_type: str = row["type"]
            # Only parse counter from canonical REDACTED_{TYPE}_{N} tokens
            if scrubbed.startswith("REDACTED_"):
                parts = scrubbed.rsplit("_", 1)
                if len(parts) == 2:
                    try:
                        n = int(parts[1])
                        new_counters[entity_type] = max(new_counters.get(entity_type, 0), n)
                        continue
                    except ValueError:
                        pass
            # Non-canonical token: count by type
            new_counters[entity_type] = new_counters.get(entity_type, 0) + 1

        # Replace all counters
        self._c.execute("DELETE FROM counters")
        for ctype, count in new_counters.items():
            self._c.execute(
                "INSERT INTO counters (type, count) VALUES (?, ?)",
                (ctype, count),
            )
        self._c.commit()

    # ------------------------------------------------------------------
    # Session PII
    # ------------------------------------------------------------------

    def tag_session_pii(self, session_id: str, originals: list[str]) -> None:
        """Associate *originals* with *session_id* in the ``session_pii`` table.

        Originals that do not yet exist in the ``tokens`` table are silently
        skipped (the FK constraint would reject them).
        """
        for orig in originals:
            try:
                self._c.execute(
                    """
                    INSERT OR IGNORE INTO session_pii (session_id, original)
                    VALUES (?, ?)
                    """,
                    (session_id, orig),
                )
            except sqlite3.IntegrityError:
                pass  # original not in tokens table yet
        self._c.commit()

    def get_session_pii(self, session_id: str) -> set[str]:
        """Return the set of original PII values tagged for *session_id*."""
        rows = self._c.execute(
            "SELECT original FROM session_pii WHERE session_id = ?",
            (session_id,),
        ).fetchall()
        return {r["original"] for r in rows}

    def get_all_session_ids(self) -> list[str]:
        """Return a deduplicated list of all session IDs in ``session_pii``."""
        rows = self._c.execute(
            "SELECT DISTINCT session_id FROM session_pii"
        ).fetchall()
        return [r["session_id"] for r in rows]

    def delete_session_exclusive(self, session_id: str) -> int:
        """Delete tokens used *only* by *session_id* (not shared with others).

        After deletion the counters are rebuilt.  Returns the count of
        tokens removed.
        """
        # Find originals exclusive to this session
        cur = self._c.execute(
            """
            SELECT sp.original
            FROM session_pii sp
            WHERE sp.session_id = ?
              AND sp.original NOT IN (
                  SELECT original FROM session_pii WHERE session_id != ?
              )
            """,
            (session_id, session_id),
        )
        exclusive = [r["original"] for r in cur.fetchall()]

        removed = 0
        for orig in exclusive:
            del_cur = self._c.execute(
                "DELETE FROM tokens WHERE original = ?", (orig,)
            )
            removed += del_cur.rowcount

        # Clear this session's PII tags
        self._c.execute(
            "DELETE FROM session_pii WHERE session_id = ?", (session_id,)
        )
        self._c.commit()

        if removed > 0:
            self.rebuild_counters_from_tokens()

        return removed

    def clear_session_pii(self, session_id: str) -> None:
        """Remove all ``session_pii`` rows for *session_id* (tags only, not tokens)."""
        self._c.execute(
            "DELETE FROM session_pii WHERE session_id = ?", (session_id,)
        )
        self._c.commit()

    # ------------------------------------------------------------------
    # Migration from JSON
    # ------------------------------------------------------------------

    def migrate_from_json(self, token_map_path: Path) -> int:
        """Import data from an existing ``token_map.json`` file.

        The migration is recorded in the ``_migrations`` table within the
        same transaction as the imported data, so a crash between commit
        and source-file rename will *not* cause a re-import on next
        startup (which would otherwise reset entity counters and risk
        token-numbering collisions for any tokens minted in between).

        Returns the number of tokens imported.
        """
        token_map_path = Path(expanduser(str(token_map_path)))
        if not token_map_path.exists():
            return 0

        # Idempotency check: if we've already recorded a migration for
        # this file path, skip even if the source still exists (e.g.
        # because the rename failed on a previous run).
        migration_key = f"json_import:{token_map_path.resolve()}"
        row = self._c.execute(
            "SELECT 1 FROM _migrations WHERE name = ?", (migration_key,),
        ).fetchone()
        if row is not None:
            logger.info(
                "TokenDB: JSON migration %s already recorded; skipping",
                migration_key,
            )
            return 0

        # Only migrate into an empty DB
        row = self._c.execute("SELECT COUNT(*) AS cnt FROM tokens").fetchone()
        if row["cnt"] > 0:
            logger.info("TokenDB already has data; skipping JSON migration")
            # Still record the migration so a later attempt won't try
            # again on what may now be a stale source file.
            self._c.execute(
                "INSERT OR IGNORE INTO _migrations (name, applied_at) VALUES (?, ?)",
                (migration_key, time.time()),
            )
            self._c.commit()
            return 0

        with open(token_map_path, encoding="utf-8") as f:
            data = json.load(f)

        scrub_map: dict[str, str] = data.get("scrub", {})
        entity_types: dict[str, str] = data.get("entity_types", {})
        timestamps: dict[str, float] = data.get("entry_timestamps", {})
        counters: dict[str, int] = data.get("counters", {})
        token_meta: dict[str, dict] = data.get("token_meta", {})

        now = time.time()
        imported = 0
        skipped = 0
        for pii, token in scrub_map.items():
            # R60-6 fix: reject empty/None pii or token rows during
            # migration — defense-in-depth on top of R58-3 (in-memory
            # rejection) and R59-4 (load-time rejection).  An empty
            # token in the DB triggers the same infinite-loop /
            # response-corruption DoS class.
            if not pii or not token:
                skipped += 1
                continue
            etype = entity_types.get(pii, "UNKNOWN")
            ts = timestamps.get(pii, now)
            meta = token_meta.get(pii, {})
            req_id = str(meta.get("first_seen_request_id", ""))
            wb = int(meta.get("word_boundary", False))
            cs = int(meta.get("case_sensitive", True))
            efp = int(meta.get("exclude_from_prefilter", False))
            self._c.execute(
                """
                INSERT OR IGNORE INTO tokens
                    (original, scrubbed, type, source, created_at, last_access,
                     first_seen_request_id, word_boundary, case_sensitive, exclude_from_prefilter)
                VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?)
                """,
                (pii, token, etype, ts, ts, req_id, wb, cs, efp),
            )
            imported += 1
        if skipped:
            logger.warning(
                "JSON migration skipped %d empty token-map entries "
                "(would trigger DoS if loaded)", skipped,
            )

        # Restore counters
        for ctype, count in counters.items():
            self._c.execute(
                """
                INSERT OR IGNORE INTO counters (type, count) VALUES (?, ?)
                """,
                (ctype, count),
            )

        # Mark migration applied in the same transaction as the data —
        # ensures atomicity: either both data and marker are committed
        # or neither is.
        self._c.execute(
            "INSERT OR REPLACE INTO _migrations (name, applied_at) VALUES (?, ?)",
            (migration_key, time.time()),
        )

        self._c.commit()

        # Rename original file to .bak
        bak_path = token_map_path.with_suffix(".json.bak")
        try:
            token_map_path.rename(bak_path)
            logger.info(
                "Migrated %d tokens from %s (renamed to %s)",
                imported,
                token_map_path,
                bak_path,
            )
        except OSError:
            logger.warning(
                "Migrated %d tokens but failed to rename %s",
                imported,
                token_map_path,
                exc_info=True,
            )

        return imported
