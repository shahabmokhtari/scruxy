"""ConcurrentSessionStore: shared TokenMap with per-session PII tracking and SQLite persistence."""
from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from scruxy.tokenmap.db import TokenDB
from scruxy.tokenmap.token_map import TokenMap

if TYPE_CHECKING:
    from scruxy.tokenmap.replacer import ReplacementStrategy

logger = logging.getLogger(__name__)


class SessionTokenMapView:
    """Session-scoped deanonymization view over the shared token map.

    E4 fix: snapshots the allowed PII set at construction time so a
    subsequent LRU eviction (under load) cannot evict the in-flight
    session's tracking and cause the response unscrub to leak raw
    `REDACTED_*` tokens to the user.  The snapshot is point-in-time;
    PII tagged AFTER view creation won't be visible — but the proxy
    never tags new PII during response unscrub anyway.
    """

    def __init__(self, store: ConcurrentSessionStore, session_id: str) -> None:
        self._store = store
        self._session_id = session_id
        # E4 fix: snapshot the allowed PII set at construction.
        with self._store._session_pii_lock:
            self._allowed_pii_snapshot: set[str] = set(
                self._store._session_pii.get(session_id, set())
            )

    def __getattr__(self, name: str):
        if name.startswith("_") and name != "_token_version":
            raise AttributeError(name)
        return getattr(self._store._shared_map, name)

    def _allowed_pii(self) -> set[str]:
        """Return the union of the session's snapshot AND any newly-tagged
        PII still tracked in the live session_pii map.

        E4 (and r51 residuals): each call MERGES current live PII into
        the snapshot, so the snapshot grows monotonically across the
        view's lifetime.  In addition, the proxy can call
        :meth:`absorb_pii` to seed the snapshot with the current
        request's PII immediately after tagging — that closes the
        race where the session is evicted between tag and the FIRST
        deanonymize call.
        """
        with self._store._session_pii_lock:
            live = self._store._session_pii.get(self._session_id, set())
            if live:
                self._allowed_pii_snapshot |= set(live)
            return set(self._allowed_pii_snapshot)

    def absorb_pii(self, pii_set: set[str]) -> None:
        """Add *pii_set* to this view's snapshot.

        Used by the proxy right after it calls
        ``tag_session_pii(session_id, request_pii)`` so that even if
        eviction happens BEFORE the first response read, the view
        still resolves the current request's tokens.
        """
        if not pii_set:
            return
        with self._store._session_pii_lock:
            self._allowed_pii_snapshot |= set(pii_set)

    @property
    def unscrub_map(self) -> dict[str, str]:
        """Return only the token mappings known to this session.

        Includes per-sub-token aliases (e.g. for `Alice Smith` →
        `REDACTED_PERSON_1A REDACTED_PERSON_1B`, also expose
        `REDACTED_PERSON_1A → Alice` and `REDACTED_PERSON_1B → Smith`)
        so that LLM responses referencing a single sub-token still
        deanonymize correctly.  Without these aliases the response
        path leaks the raw token to the user (C2 fix).
        """
        allowed_pii = self._allowed_pii()
        if not allowed_pii:
            return {}
        with self._store._shared_map._lock:
            scrub = self._store._shared_map._scrub
            unscrub = self._store._shared_map._unscrub
            result: dict[str, str] = {}
            for pii in allowed_pii:
                token = scrub.get(pii)
                if token is None:
                    continue
                result[token] = pii
                # Add per-sub-token aliases for multi-word tokens whose
                # joint mapping belongs to this session.  Mirror the
                # alias-creation logic in TokenMap.get_or_create_token.
                sub_tokens = token.split()
                sub_piis = pii.split()
                if (
                    len(sub_tokens) > 1
                    and len(sub_tokens) == len(sub_piis)
                    and all(st != sp for st, sp in zip(sub_tokens, sub_piis))
                ):
                    for sub_t, sub_p in zip(sub_tokens, sub_piis):
                        if unscrub.get(sub_t) == sub_p and sub_t not in result:
                            result[sub_t] = sub_p
            return result

    def get_pii(self, token: str) -> str | None:
        """Reverse-lookup constrained to the current session's known PII.

        Allows sub-token aliases (e.g. `REDACTED_PERSON_1A → Alice`)
        when their parent joint token belongs to a PII tagged for this
        session — so the LLM referring to a single sub-token in its
        reply still deanonymizes (C2 fix).
        """
        pii = self._store._shared_map.get_pii(token)
        if pii is None:
            return None
        session_set = self._allowed_pii()
        if pii in session_set:
            return pii
        # Sub-token alias path.
        for allowed in session_set:
            sub_piis = allowed.split()
            if len(sub_piis) <= 1 or pii not in sub_piis:
                continue
            with self._store._shared_map._lock:
                joint_token = self._store._shared_map._scrub.get(allowed)
            if not joint_token:
                continue
            sub_tokens = joint_token.split()
            if len(sub_tokens) != len(sub_piis):
                continue
            for idx, sp in enumerate(sub_piis):
                if sp == pii and sub_tokens[idx] == token:
                    return pii
        return None


class ConcurrentSessionStore:
    """Manages a single shared :class:`TokenMap` across all sessions.

    All sessions share the same PII-token mappings so that the same PII
    always maps to the same token regardless of session.  Per-session PII
    usage is tracked in ``session_pii`` (in SQLite) so exclusive entries
    can be deleted when a session is cleared.

    Persistence is handled by a :class:`TokenDB` SQLite database at
    ``{storage_dir}/../scruxy.db`` (i.e. ``~/.scruxy/scruxy.db``).  New
    tokens are written through synchronously from the pipeline thread;
    there is no longer a periodic JSON flush.
    """

    def __init__(
        self,
        storage_dir: str | Path,
        flush_interval_seconds: float = 5.0,
        replacements: dict[str, ReplacementStrategy] | None = None,
        expiration_hours: int = 0,
        db_path: str | Path | None = None,
        persistent: bool = True,
    ) -> None:
        self._storage_dir = Path(storage_dir).expanduser()
        self._flush_interval = flush_interval_seconds
        self._replacements: dict[str, ReplacementStrategy] = replacements or {}
        self._expiration_hours = expiration_hours
        self._persistent = persistent

        # SQLite database (None when running in-memory mode)
        if persistent:
            if db_path is None:
                db_path = self._storage_dir.parent / "scruxy.db"
            self._db: TokenDB | None = TokenDB(db_path)
        else:
            self._db = None

        # Single shared token map for all sessions (db=None for in-memory mode)
        self._shared_map = TokenMap(replacements=self._replacements, db=self._db)

        # Per-session PII tracking: session_id -> set of PII strings used.
        # D5 fix: use OrderedDict for LRU eviction so a flood of unique
        # session IDs cannot grow either map indefinitely.  Cap is high
        # enough for normal workloads (thousands of concurrent
        # harnesses) but bounds worst-case memory.
        from collections import OrderedDict as _OrderedDict
        self._session_pii: "_OrderedDict[str, set[str]]" = _OrderedDict()
        self._session_max = 4096
        # Thread-safe lock for _session_pii (accessed from asyncio.to_thread workers)
        self._session_pii_lock = threading.Lock()
        # Serializes all DB access so only one thread touches SQLite at a time
        self._db_lock = threading.Lock()

        # Per-session locks (protects shared map mutations per-session).
        # Bounded with the same LRU semantics as _session_pii.
        self._locks: "_OrderedDict[str, asyncio.Lock]" = _OrderedDict()
        self._flush_task: asyncio.Task[None] | None = None
        self._drain_task: asyncio.Task[None] | None = None
        self._meta_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Open the DB, run migration from JSON if needed, and load cache."""
        if self._persistent and self._db is not None:
            await asyncio.to_thread(self._db.open)

            # Migrate from legacy JSON if present
            json_path = self._storage_dir.parent / "token_map.json"
            if json_path.exists():
                await asyncio.to_thread(self._db.migrate_from_json, json_path)

            # Load cache from DB
            await self._load_from_db()

        # Start background tasks
        self._flush_task = asyncio.create_task(self._periodic_expiration())
        self._drain_task = asyncio.create_task(self._periodic_drain())

    async def stop(self) -> None:
        """Cancel background tasks, drain remaining writes, and close the DB."""
        for task in (self._flush_task, self._drain_task):
            if task is not None:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._flush_task = None
        self._drain_task = None
        if self._persistent and self._db is not None:
            # Final drain of pending writes before closing DB
            await asyncio.to_thread(self._drain_with_db_lock)
            await asyncio.to_thread(self._db.close)

    # ------------------------------------------------------------------
    # Session access
    # ------------------------------------------------------------------

    async def get_or_create_session(self, session_id: str) -> TokenMap:
        """Return the shared :class:`TokenMap`, creating session tracking if needed.

        D5: bounded LRU — when over ``_session_max`` the oldest
        unused session is evicted from BOTH ``_session_pii`` and
        ``_locks``.  We never delete shared-map mappings here because
        other sessions may still need them; only the per-session
        bookkeeping is dropped.

        E3 fix: hold ``_session_pii_lock`` for ALL OrderedDict
        mutations (in addition to the asyncio ``_meta_lock``) so the
        threading-side ``tag_session_pii`` and the asyncio-side
        eviction cannot race on the LRU pop sequence.  Also
        ``move_to_end`` BOTH dicts so their LRU orders never drift.
        """
        async with self._meta_lock:
            with self._session_pii_lock:
                if session_id not in self._session_pii:
                    self._session_pii[session_id] = set()
                    self._locks[session_id] = asyncio.Lock()
                    while len(self._session_pii) > self._session_max:
                        evicted_id, _ = self._session_pii.popitem(last=False)
                        self._locks.pop(evicted_id, None)
                else:
                    # LRU: promote on access.  Move BOTH dicts so the
                    # _locks LRU never drifts from _session_pii LRU
                    # (drift previously caused eviction of an
                    # in-flight session's lock → KeyError in get_lock).
                    self._session_pii.move_to_end(session_id)
                    if session_id in self._locks:
                        self._locks.move_to_end(session_id)
        return self._shared_map

    def get_lock(self, session_id: str) -> asyncio.Lock:
        """Return the per-session lock for *session_id*.

        E3 fix: tolerate the rare race where the lock was evicted
        between session creation and lookup by lazily creating a new
        one rather than raising ``KeyError`` (which would surface as
        a 500 to the client).
        """
        with self._session_pii_lock:
            lock = self._locks.get(session_id)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[session_id] = lock
                while len(self._locks) > self._session_max:
                    self._locks.popitem(last=False)
            return lock

    def has_session(self, session_id: str) -> bool:
        """Return ``True`` if *session_id* is currently tracked.

        R68-1 fix: acquire ``_session_pii_lock`` for the membership
        check, mirroring the R52-F5 / R53-2 fixes for ``sessions``
        and ``session_ids``.  Without the lock, a concurrent
        ``tag_session_pii`` worker could mutate the ``OrderedDict``
        during the ``in`` operator (a single C-op in CPython, so
        not a crash, but TOCTOU-inconsistent with sibling readers).
        """
        with self._session_pii_lock:
            return session_id in self._session_pii

    @property
    def session_ids(self) -> list[str]:
        """Return a snapshot list of all tracked session IDs.

        R53-2 fix: snapshot under ``_session_pii_lock`` to prevent
        ``RuntimeError: OrderedDict mutated during iteration`` when a
        concurrent ``tag_session_pii`` worker thread mutates
        ``_session_pii``.  Same bug class as the F5 fix that was
        applied to the sibling ``sessions`` property.
        """
        with self._session_pii_lock:
            return list(self._session_pii.keys())

    @property
    def sessions(self) -> dict[str, TokenMap]:
        """Backward-compatible view: all sessions point to the shared map.

        F5 fix: snapshot the keys under ``_session_pii_lock`` so a
        concurrent ``tag_session_pii`` worker thread cannot trigger
        ``RuntimeError: OrderedDict mutated during iteration``, which
        previously surfaced as a 500 on ``/ui/api/dashboard``.
        """
        with self._session_pii_lock:
            sids = list(self._session_pii.keys())
        return {sid: self._shared_map for sid in sids}

    def get_token_map(self, session_id: str) -> TokenMap | None:
        """Return the shared TokenMap (for backward compat)."""
        return self._shared_map

    def get_session_token_map(self, session_id: str) -> SessionTokenMapView:
        """Return a session-scoped view for safe response deanonymization."""
        return SessionTokenMapView(self, session_id)

    @property
    def shared_map(self) -> TokenMap:
        """Direct access to the shared token map."""
        return self._shared_map

    # ------------------------------------------------------------------
    # Session PII tagging
    # ------------------------------------------------------------------

    def tag_session_pii(self, session_id: str, pii_texts: Iterable[str]) -> None:
        """Record that *session_id* used the given PII strings.

        Thread-safe: called from ``asyncio.to_thread`` workers in both
        proxy paths.
        """
        pii_list = list(pii_texts)

        with self._session_pii_lock:
            session_set = self._session_pii.get(session_id)
            if session_set is None:
                # D5 residual fix: enforce the LRU cap when a session
                # is created here (not just in get_or_create_session).
                self._session_pii[session_id] = set()
                while len(self._session_pii) > self._session_max:
                    evicted_id, _ = self._session_pii.popitem(last=False)
                    self._locks.pop(evicted_id, None)
                session_set = self._session_pii[session_id]
            else:
                # E3 fix: keep _locks LRU order in sync with
                # _session_pii so eviction never drops a live session's
                # lock while leaving its PII set tracked.
                self._session_pii.move_to_end(session_id)
                if session_id in self._locks:
                    self._locks.move_to_end(session_id)
            session_set.update(pii_list)

        if not self._persistent or self._db is None:
            return

        # R70-11 (partial fix): Drain pending writes first (FK
        # constraint requires the token row to exist before we can
        # tag session PII).  Use ``_db_lock`` to serialize all DB
        # access so the drain → tag sequence is observed atomically
        # by other ``tag_session_pii`` callers (no interleaved tag
        # for a different session can sneak in between).  A crash
        # between drain commit and tag commit can still leave tokens
        # persisted but untagged → orphan; reclaiming such orphans
        # at startup is tracked separately (see
        # ``delete_session_mappings`` for the read side).  Wrapping
        # drain + tag in a single SQLite transaction would require
        # rewriting drain's per-write commits; deferred to a focused
        # refactor.
        with self._db_lock:
            self._drain_pending_writes()

            # Write-through to DB: only tag PII that exists in the tokens table.
            with self._shared_map._lock:
                known = [p for p in pii_list if p in self._shared_map._scrub]
            if known:
                self._db.tag_session_pii(session_id, known)

    def get_session_pii_count(self, session_id: str) -> int:
        """Return the number of PII entries tagged for *session_id*."""
        with self._session_pii_lock:
            return len(self._session_pii.get(session_id, set()))

    # ------------------------------------------------------------------
    # Session deletion
    # ------------------------------------------------------------------

    async def delete_session_mappings(self, session_id: str) -> int:
        """Remove entries exclusive to *session_id* from the shared map."""
        async with self._meta_lock:
            with self._session_pii_lock:
                session_set = self._session_pii.get(session_id)
                if not session_set:
                    return 0
                session_set_copy = set(session_set)

            if self._persistent and self._db is not None:
                def _delete_with_lock():
                    with self._db_lock:
                        return self._db.delete_session_exclusive(session_id)
                removed = await asyncio.to_thread(_delete_with_lock)
                # Clear the deleted session's PII set before reload so merge
                # doesn't preserve PII that was just removed from DB.
                with self._session_pii_lock:
                    self._session_pii[session_id] = set()
                await self._load_from_db()
            else:
                # In-memory mode: only remove PII exclusive to this session.
                # Hold both locks together to prevent TOCTOU race with
                # concurrent tag_session_pii adding PII between snapshot and removal.
                removed = 0
                with self._session_pii_lock:
                    other_pii: set[str] = set()
                    for sid, pset in self._session_pii.items():
                        if sid != session_id:
                            other_pii.update(pset)
                    with self._shared_map._lock:
                        for pii in list(session_set_copy):
                            if pii in other_pii:
                                continue
                            token = self._shared_map._scrub.pop(pii, None)
                            if token:
                                self._shared_map._unscrub.pop(token, None)
                                # B3 cleanup (in-memory branch): purge
                                # per-sub-token aliases so a deleted
                                # multi-word PII isn't reachable
                                # through stale single-word aliases.
                                self._shared_map._purge_subtoken_aliases(pii, token)
                                self._shared_map._entity_types.pop(pii, None)
                                self._shared_map._entry_timestamps.pop(pii, None)
                                self._shared_map._token_meta.pop(pii, None)
                                removed += 1
                        # Rebuild counters from remaining tokens — O(n) via _unscrub.
                        # Only tokens matching the canonical REDACTED_{TYPE}_{N}
                        # format are parsed; all others preserve the existing
                        # high-water counter to prevent rewind/collision.
                        if removed > 0:
                            new_counters: dict[str, int] = {}
                            for remaining_token, remaining_pii in self._shared_map._unscrub.items():
                                et = self._shared_map._entity_types.get(remaining_pii)
                                if not et:
                                    continue
                                # Only parse as canonical if it matches REDACTED_{et}_{N}
                                canonical_prefix = f"REDACTED_{et}_"
                                if remaining_token.startswith(canonical_prefix):
                                    suffix = remaining_token[len(canonical_prefix):]
                                    try:
                                        n = int(suffix)
                                        new_counters[et] = max(new_counters.get(et, 0), n)
                                        continue
                                    except ValueError:
                                        pass
                                # Non-canonical: preserve existing counter
                                old_count = self._shared_map._counters.get(et, 0)
                                new_counters[et] = max(new_counters.get(et, 0), old_count)
                            self._shared_map._counters = new_counters
                    self._session_pii[session_id] -= session_set_copy
                    # Clean up empty session entries to prevent memory leak
                    if not self._session_pii[session_id]:
                        del self._session_pii[session_id]
                        self._locks.pop(session_id, None)

        return removed

    async def clear_all_mappings(self) -> None:
        """Reset the entire shared map and all session PII sets."""
        async with self._meta_lock:
            def _clear_with_lock():
                with self._db_lock:
                    # Clear DB first so a failure leaves in-memory state intact.
                    if self._persistent and self._db is not None:
                        self._db.clear_all()
                    self._shared_map.clear()
                    # Drain clears any leftover pending_clear flag.
                    self._drain_pending_writes()
            await asyncio.to_thread(_clear_with_lock)
            # E3 residual fix: clear BOTH dicts under the same lock so
            # a concurrent tag_session_pii / get_lock cannot observe
            # the desynchronised state.  Matches clear_all_sessions.
            with self._session_pii_lock:
                self._session_pii.clear()
                self._locks.clear()

    async def clear_all_sessions(self) -> int:
        """Remove all session tracking, PII sets, and locks."""
        async with self._meta_lock:
            with self._session_pii_lock:
                count = len(self._session_pii)
            def _clear_with_lock():
                with self._db_lock:
                    if self._persistent and self._db is not None:
                        self._db.clear_all()
                    self._shared_map.clear()
                    self._drain_pending_writes()
            await asyncio.to_thread(_clear_with_lock)
            with self._session_pii_lock:
                self._session_pii.clear()
                self._locks.clear()
            return count

    # ------------------------------------------------------------------
    # Flush / persistence (simplified for DB-backed storage)
    # ------------------------------------------------------------------

    def mark_dirty(self, session_id: str) -> None:
        """No-op for backward compatibility.

        With DB write-through, dirty tracking is no longer needed.
        """
        pass

    async def flush_session(self, session_id: str) -> None:
        """No-op for backward compatibility.

        Session PII is written through to the DB on ``tag_session_pii``.
        """
        pass

    async def flush_all(self) -> None:
        """No-op for backward compatibility.

        All data is written through to the DB immediately.
        """
        pass

    # ------------------------------------------------------------------
    # DB loading
    # ------------------------------------------------------------------

    async def _load_from_db(self) -> None:
        """Populate in-memory cache from the SQLite database.

        Honors configured token expiration on startup so persisted mappings
        are not silently purged when expiration is disabled or extended.
        """
        if not self._persistent or self._db is None:
            return

        self._storage_dir.mkdir(parents=True, exist_ok=True)

        def _full_rebuild() -> int:
            """Run the whole DB → in-memory rebuild atomically.

            Holds ``_db_lock`` for the entire operation so
            ``_periodic_drain`` cannot drain ``_pending_writes`` into the
            DB between the ``get_all_tokens`` snapshot and the
            ``_shared_map`` apply — which would otherwise orphan writes
            that were persisted to DB after the snapshot but before the
            apply captured ``_pending_writes``.
            """
            with self._db_lock:
                # Drain first so the snapshot includes all queued writes.
                self._drain_pending_writes()
                if self._expiration_hours > 0:
                    self._db.evict_stale_tokens(self._expiration_hours * 3600)
                rows = self._db.get_all_tokens()
                counters: dict[str, int] = {}
                etypes_in_rows: set[str] = set()
                for r in rows:
                    etypes_in_rows.add(r["type"])
                for et in etypes_in_rows:
                    counters[et] = self._db.get_counter(et)

                new_scrub: dict[str, str] = {}
                new_unscrub: dict[str, str] = {}
                new_entity_types: dict[str, str] = {}
                new_token_meta: dict[str, dict] = {}
                new_entry_timestamps: dict[str, float] = {}

                for row in rows:
                    pii = row["original"]
                    token = row["scrubbed"]
                    etype = row["type"]
                    ts = row["created_at"]

                    # R59-4 fix: a legacy DB row may persist a stale
                    # empty ``scrubbed`` (or ``original``) string from
                    # a buggy historical version of the proxy.  An
                    # empty token would (a) infinite-loop
                    # ``_build_occupied_ranges`` via ``str.find("", pos)``
                    # and (b) corrupt every response in
                    # ``deanonymize_text``.  Skip such rows on load
                    # — same fail-safe as R58-3 applied to persisted
                    # state.  Logged at WARNING for operator visibility.
                    if not pii or not token:
                        logger.warning(
                            "Skipping malformed token-map row from DB "
                            "(pii_len=%d, token_len=%d, type=%r)",
                            len(pii or ""), len(token or ""), etype,
                        )
                        continue

                    # 72-4 fix: warn on conflicting DB rows.  A
                    # corrupt DB or manual edit can produce two rows
                    # with the same ``original`` mapping to different
                    # ``scrubbed`` tokens (or the same ``scrubbed``
                    # mapping to different originals).  The previous
                    # behaviour silently overwrote — last-row-wins —
                    # which can cause incorrect deanonymization.
                    prev_token = new_scrub.get(pii)
                    if prev_token is not None and prev_token != token:
                        logger.warning(
                            "DB load: conflicting token rows for same "
                            "original (pii_len=%d type=%r); keeping "
                            "first-seen, dropping later row.",
                            len(pii), etype,
                        )
                        continue
                    prev_pii = new_unscrub.get(token)
                    if prev_pii is not None and prev_pii != pii:
                        logger.warning(
                            "DB load: token %r reverse-maps to two "
                            "different originals; keeping first-seen, "
                            "dropping later row.",
                            token,
                        )
                        continue

                    new_scrub[pii] = token
                    new_unscrub[token] = pii
                    # B3: rebuild per-sub-token reverse aliases for
                    # multi-word PII so a partial-token reference in a
                    # post-restart response still deanonymizes.  Mirror
                    # the alias logic in TokenMap.get_or_create_token.
                    sub_tokens = token.split()
                    sub_piis = pii.split()
                    if (
                        len(sub_tokens) > 1
                        and len(sub_tokens) == len(sub_piis)
                        and all(st != sp for st, sp in zip(sub_tokens, sub_piis))
                    ):
                        for sub_t, sub_p in zip(sub_tokens, sub_piis):
                            existing = new_unscrub.get(sub_t)
                            if existing is None or existing == sub_p:
                                new_unscrub[sub_t] = sub_p
                    new_entity_types[pii] = etype
                    new_entry_timestamps[pii] = ts

                    meta: dict = {}
                    req_id = row.get("first_seen_request_id", "")
                    if req_id:
                        meta["first_seen_request_id"] = req_id
                    meta["word_boundary"] = bool(row.get("word_boundary", 0))
                    meta["case_sensitive"] = bool(row.get("case_sensitive", 1))
                    meta["exclude_from_prefilter"] = bool(row.get("exclude_from_prefilter", 0))
                    new_token_meta[pii] = meta

                def _counter_from_token(token: str) -> int:
                    try:
                        return int(token.rsplit("_", 1)[1])
                    except (IndexError, ValueError):
                        return 0

                with self._shared_map._lock:
                    # While holding _db_lock no periodic_drain can run,
                    # so _pending_writes / _pending_deletes are authoritative.
                    pending_deletes = set(self._shared_map._pending_deletes)
                    pending_overrides: dict[str, tuple[str, str, float | None, dict]] = {}
                    pending_writes_seen: set[str] = set()
                    for write in list(self._shared_map._pending_writes):
                        pii = write[0]
                        if pii in pending_writes_seen:
                            continue
                        pending_writes_seen.add(pii)
                        # A pii currently being (re-)written must not remain in
                        # pending_deletes — the write wins.
                        pending_deletes.discard(pii)
                        token = self._shared_map._scrub.get(pii)
                        if token is None:
                            continue
                        pending_overrides[pii] = (
                            token,
                            self._shared_map._entity_types.get(pii, ""),
                            self._shared_map._entry_timestamps.get(pii),
                            dict(self._shared_map._token_meta.get(pii, {})),
                        )

                    self._shared_map._scrub.clear()
                    self._shared_map._scrub.update(new_scrub)
                    self._shared_map._unscrub.clear()
                    self._shared_map._unscrub.update(new_unscrub)
                    self._shared_map._entity_types.clear()
                    self._shared_map._entity_types.update(new_entity_types)
                    self._shared_map._token_meta.clear()
                    self._shared_map._token_meta.update(new_token_meta)
                    self._shared_map._counters.clear()
                    self._shared_map._counters.update(counters)
                    self._shared_map._entry_timestamps.clear()
                    self._shared_map._entry_timestamps.update(new_entry_timestamps)
                    self._shared_map._stats_total = 0
                    self._shared_map._stats_by_type.clear()
                    self._shared_map._stats_by_source.clear()

                    for pii in pending_deletes:
                        token = self._shared_map._scrub.pop(pii, None)
                        if token is not None:
                            self._shared_map._unscrub.pop(token, None)
                        self._shared_map._entity_types.pop(pii, None)
                        self._shared_map._token_meta.pop(pii, None)
                        self._shared_map._entry_timestamps.pop(pii, None)

                    for pii, (token, etype, ts, meta) in pending_overrides.items():
                        # If a prior token (from the DB snapshot) is being
                        # replaced by a freshly-minted override token, drop
                        # the stale reverse entry first.  Otherwise
                        # ``_unscrub`` would retain the obsolete token
                        # mapping, allowing a deanonymize-after-invalidate
                        # leak when the caller invalidated and re-created
                        # the same PII during the rebuild's race window.
                        prior_token = self._shared_map._scrub.get(pii)
                        if prior_token is not None and prior_token != token:
                            if self._shared_map._unscrub.get(prior_token) == pii:
                                self._shared_map._unscrub.pop(prior_token, None)
                            # D6 fix: ALSO purge per-sub-token aliases
                            # of the prior token.  Without this, a
                            # rebuild that overrides a multi-word PII's
                            # token leaves the prior token's sub-aliases
                            # as dead reverse mappings — slow leak and
                            # potential confusion if the same sub-token
                            # is later re-bound to a different PII.
                            self._shared_map._purge_subtoken_aliases(pii, prior_token)
                        self._shared_map._scrub[pii] = token
                        self._shared_map._unscrub[token] = pii
                        # B3: rebuild per-sub-token aliases for
                        # multi-word PII overrides too.
                        sub_tokens = token.split()
                        sub_piis = pii.split()
                        if (
                            len(sub_tokens) > 1
                            and len(sub_tokens) == len(sub_piis)
                            and all(st != sp for st, sp in zip(sub_tokens, sub_piis))
                        ):
                            for sub_t, sub_p in zip(sub_tokens, sub_piis):
                                existing = self._shared_map._unscrub.get(sub_t)
                                if existing is None or existing == sub_p:
                                    self._shared_map._unscrub[sub_t] = sub_p
                        if etype:
                            self._shared_map._entity_types[pii] = etype
                            self._shared_map._counters[etype] = max(
                                self._shared_map._counters.get(etype, 0),
                                _counter_from_token(token),
                            )
                        if ts is not None:
                            self._shared_map._entry_timestamps[pii] = ts
                        self._shared_map._token_meta[pii] = meta

                    self._shared_map._token_version += 1

                return len(rows)

        loaded = await asyncio.to_thread(_full_rebuild)
        if loaded:
            logger.info("Loaded %d tokens from DB into cache", loaded)

        # Reload session PII from DB — merge with existing in-memory sets
        # rather than overwriting, to avoid dropping concurrently-tagged PII.
        def _get_session_data():
            with self._db_lock:
                sids = self._db.get_all_session_ids()
                result = {}
                for sid in sids:
                    result[sid] = self._db.get_session_pii(sid)
                return result

        session_data = await asyncio.to_thread(_get_session_data)

        with self._session_pii_lock:
            # Replace session PII from DB snapshot.
            db_sids = set(session_data.keys())
            mem_sids = set(self._session_pii.keys())
            # Update/create sessions from DB — use DB snapshot as truth,
            # then add any concurrently-tagged PII not yet flushed to DB.
            for sid in db_sids:
                db_set = session_data[sid]
                existing = self._session_pii.get(sid, set())
                # Pending writes contain PII tagged since last drain — keep those.
                pending = set()
                with self._shared_map._lock:
                    for pii in existing - db_set:
                        if pii in self._shared_map._scrub:
                            pending.add(pii)
                self._session_pii[sid] = db_set | pending
            # Remove sessions not in DB — their tokens have been purged.
            # Check if any of their PII still exists in the token map;
            # if not, the session is fully expired and should be cleaned up.
            for sid in mem_sids - db_sids:
                pii_set = self._session_pii[sid]
                if not pii_set:
                    del self._session_pii[sid]
                    self._locks.pop(sid, None)
                else:
                    # Check if any PII still has a live token (under lock)
                    with self._shared_map._lock:
                        has_live = any(
                            pii in self._shared_map._scrub for pii in pii_set
                        )
                    if not has_live:
                        del self._session_pii[sid]
                        self._locks.pop(sid, None)
            for sid in db_sids:
                if sid not in self._locks:
                    self._locks[sid] = asyncio.Lock()

            # D5 residual fix: enforce the LRU cap after reload.  A
            # legacy DB with millions of session_pii rows would
            # otherwise repopulate `_session_pii` past the cap on
            # startup.  We trim from the front (oldest insertion
            # order) since the DB doesn't carry per-session timestamps.
            while len(self._session_pii) > self._session_max:
                evicted_id, _ = self._session_pii.popitem(last=False)
                self._locks.pop(evicted_id, None)

        if session_data:
            logger.info("Loaded session PII for %d sessions from DB", len(session_data))

    # ------------------------------------------------------------------
    # Background task
    # ------------------------------------------------------------------

    async def _periodic_expiration(self) -> None:
        """Background coroutine that purges expired entries periodically."""
        try:
            while True:
                await asyncio.sleep(self._flush_interval)
                if self._expiration_hours > 0 and self._persistent and self._db is not None:
                    max_age = self._expiration_hours * 3600
                    def _purge_with_lock():
                        with self._db_lock:
                            return self._db.purge_expired(max_age)
                    purged = await asyncio.to_thread(_purge_with_lock)
                    if purged > 0:
                        logger.info("Purged %d expired tokens from DB", purged)
                        async with self._meta_lock:
                            await self._load_from_db()
        except asyncio.CancelledError:
            return

    async def _periodic_drain(self) -> None:
        """Background coroutine that drains pending DB writes without blocking the event loop."""
        try:
            while True:
                await asyncio.sleep(0.1)  # drain every 100ms
                has_pending = await asyncio.to_thread(self._has_pending_db_work)
                if has_pending:
                    try:
                        await asyncio.to_thread(self._drain_with_db_lock)
                    except Exception:
                        logger.exception("Error draining pending writes (will retry)")
        except asyncio.CancelledError:
            return

    def _has_pending_db_work(self) -> bool:
        """Return whether the shared map has queued DB mutations."""
        with self._shared_map._lock:
            return bool(
                self._shared_map._pending_writes
                or self._shared_map._pending_touches
                or self._shared_map._pending_deletes
                or self._shared_map._pending_clear
            )

    def _drain_with_db_lock(self) -> None:
        """Acquire _db_lock then drain. Used by _periodic_drain."""
        with self._db_lock:
            self._drain_pending_writes()

    def _drain_pending_writes(self) -> None:
        """Flush all pending token writes to the DB (called from a thread).

        Must be called while holding ``_db_lock`` or from the periodic
        drain (which acquires it).
        """
        if not self._persistent or self._db is None:
            with self._shared_map._lock:
                self._shared_map._pending_writes = []
                self._shared_map._pending_touches.clear()
                self._shared_map._pending_deletes.clear()
                self._shared_map._pending_clear = False
            return
        # Atomically swap the pending list while holding the TokenMap lock
        with self._shared_map._lock:
            writes = self._shared_map._pending_writes
            touches = set(self._shared_map._pending_touches)
            deletes = set(self._shared_map._pending_deletes)
            clear_requested = self._shared_map._pending_clear
            if not clear_requested and not writes and not touches and not deletes:
                return
            self._shared_map._pending_writes = []
            self._shared_map._pending_touches = set()
            self._shared_map._pending_deletes = set()
            self._shared_map._pending_clear = False

        if clear_requested:
            try:
                self._db.clear_all()
            except Exception:
                with self._shared_map._lock:
                    self._shared_map._pending_clear = True
                    self._shared_map._pending_writes = writes + self._shared_map._pending_writes
                    self._shared_map._pending_touches.update(touches)
                    self._shared_map._pending_deletes.update(deletes)
                raise
            touches.clear()
            deletes.clear()

        # Write to DB — if a write fails, re-queue the remaining items
        for i, (pii, token, entity_type, source, count, request_id, wb, cs, efp) in enumerate(writes):
            try:
                self._db.upsert_token(
                    pii, token, entity_type, source, request_id,
                    word_boundary=wb, case_sensitive=cs, exclude_from_prefilter=efp,
                )
                self._db.set_counter(entity_type, count)
            except Exception:
                # Re-queue unprocessed writes so they aren't lost
                with self._shared_map._lock:
                    self._shared_map._pending_writes = writes[i:] + self._shared_map._pending_writes
                    self._shared_map._pending_touches.update(touches)
                    self._shared_map._pending_deletes.update(deletes)
                raise

        written_originals = {pii for pii, *_rest in writes}
        touch_list = sorted(touches - written_originals - deletes)
        for i, pii in enumerate(touch_list):
            try:
                self._db.get_by_original(pii)
            except Exception:
                with self._shared_map._lock:
                    self._shared_map._pending_touches.update(touch_list[i:])
                    self._shared_map._pending_deletes.update(deletes)
                raise

        delete_list = sorted(deletes)
        for i, pii in enumerate(delete_list):
            try:
                self._db.delete_token(pii)
            except Exception:
                with self._shared_map._lock:
                    self._shared_map._pending_deletes.update(delete_list[i:])
                raise
