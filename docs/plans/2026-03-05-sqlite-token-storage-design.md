# SQLite Token Map Storage

**Date:** 2026-03-05
**Status:** Approved

## Overview

Replace the JSON-based token map storage (`token_map.json` + `session_pii.json` files) with a single SQLite database (`~/.scruxy/scruxy.db`). This gives us atomic operations, indexed lookups, sliding expiration via `last_access` timestamps, and a single file to manage.

## Database Location

`~/.scruxy/scruxy.db`

## Schema

```sql
CREATE TABLE tokens (
    original    TEXT PRIMARY KEY,
    scrubbed    TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL,
    last_access REAL NOT NULL
);
CREATE INDEX idx_tokens_scrubbed ON tokens(scrubbed);
CREATE INDEX idx_tokens_last_access ON tokens(last_access);

CREATE TABLE counters (
    type  TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE session_pii (
    session_id TEXT NOT NULL,
    original   TEXT NOT NULL,
    FOREIGN KEY (original) REFERENCES tokens(original) ON DELETE CASCADE,
    PRIMARY KEY (session_id, original)
);
CREATE INDEX idx_session_pii_session ON session_pii(session_id);
```

## Key Operations

- **get_or_create_token**: SELECT by original → if found, UPDATE last_access, return scrubbed. If not found → run replacement strategy, INSERT, return token.
- **get_pii (reverse lookup)**: SELECT original FROM tokens WHERE scrubbed=?
- **Sliding expiration**: Background task: `DELETE FROM tokens WHERE last_access < now - ttl_seconds`. Configurable via `tokens.expiration_hours` in config (default 168h / 7 days, 0=never). Shown in Settings UI.
- **Session deletion**: Delete exclusive entries (PII used only by target session), then clear session_pii rows. Rebuild counters.
- **Clear all**: DELETE FROM all three tables.

## In-Memory Cache

The pipeline needs sub-millisecond lookups. Keep `_scrub: dict[str, str]` and `_unscrub: dict[str, str]` in memory, loaded from DB on startup. Mutations go to both cache and DB. The DB is the source of truth; cache is rebuilt from DB on startup.

## Migration

On startup, if `token_map.json` exists and the DB `tokens` table is empty:
1. Read JSON, INSERT all records into `tokens` and `counters` tables.
2. Read any `session_pii.json` files, INSERT into `session_pii` table.
3. Rename `token_map.json` → `token_map.json.bak`.

## Files Changed

- `src/scruxy/tokenmap/token_map.py` — Add SQLite persistence methods alongside in-memory dicts
- `src/scruxy/tokenmap/service.py` — Replace JSON flush with DB sync, remove session_pii.json handling
- `src/scruxy/config/models.py` — No change (expiration_hours already exists)
- `src/scruxy/app.py` — Pass DB path to session store
- `src/scruxy/ui/routes.py` — No change to API contracts (just storage layer swap)
- `tests/` — Update persistence tests to verify DB instead of JSON files
