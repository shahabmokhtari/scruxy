"""Per-session JSONL recording of scrubbed request/response pairs."""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import weakref
from datetime import datetime, timezone
from pathlib import Path


logger = logging.getLogger(__name__)


_SENSITIVE_HEADER_NAMES = frozenset({
    "authorization",
    "api-key",
    "x-api-key",
    "cookie",
    "set-cookie",
    "proxy-authorization",
})


def _mask_sensitive_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of *headers* with sensitive values masked.

    All sensitive headers (Authorization, Api-Key, Cookie, etc.) are masked
    unconditionally so that recordings never store full credentials,
    regardless of value length.
    """
    masked: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _SENSITIVE_HEADER_NAMES:
            if len(value) > 4:
                masked[key] = value[:4] + "…[masked]"
            else:
                masked[key] = "[masked]"
        else:
            masked[key] = value
    return masked


def _utc_now() -> str:
    """Return current UTC time as ISO 8601 string with milliseconds and Z suffix."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _utc_now_seconds() -> str:
    """Return current UTC time as ISO 8601 string with seconds precision and Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_text(path: Path) -> str:
    """Read file contents synchronously (for use inside ``to_thread``)."""
    return path.read_text(encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    """Write file contents synchronously (for use inside ``to_thread``).

    R53-5 fix: write atomically via tmp+rename so a crash mid-write
    never leaves a truncated file.  This protects every caller —
    ``_index.json`` and per-session ``metadata.json`` — from the
    permanent-500 failure mode where ``json.loads`` later raises on
    a partial file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    import os as _os
    _os.replace(tmp, path)


def _append_text(path: Path, content: str, lock: threading.Lock | None = None) -> None:
    """Append text to a file synchronously with optional per-session locking.

    R70-5 fix: re-create the parent directory inside the lock if it
    has been removed by a concurrent ``clear_all`` between
    ``_ensure_session_dir`` and ``open()``.  Without this, a recording
    write that races with the admin "clear all" op crashes with
    ``FileNotFoundError`` and the request record is silently lost.
    """
    if lock is not None:
        with lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, mode="a", encoding="utf-8") as f:
                f.write(content)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, mode="a", encoding="utf-8") as f:
            f.write(content)


def append_capped_text(
    parts: list[str],
    text: str,
    current_len: int,
    max_chars: int,
) -> tuple[int, bool]:
    """Append *text* to *parts* without letting the joined size exceed *max_chars*.

    Returns ``(new_len, truncated)`` where ``truncated`` is ``True`` if any
    part of *text* had to be discarded.
    """
    if max_chars <= 0:
        return current_len, bool(text)
    if current_len >= max_chars:
        return current_len, bool(text)
    remaining = max_chars - current_len
    chunk = text[:remaining]
    if chunk:
        parts.append(chunk)
        current_len += len(chunk)
    return current_len, len(text) > len(chunk)


_WIN_RESERVED_BASENAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})


def _safe_session_id(session_id: str) -> str:
    """72-3 fix: shared sanitizer for session-derived path components.

    Replaces path-unsafe chars + control chars with ``_``, strips
    trailing dots/spaces, rejects ``.``/``..``, and rejects Windows
    reserved device basenames (``CON``, ``NUL``, ``COM1``..``LPT9``).
    Without the reserved-name guard, a client-controlled session
    header like ``x-session-id: CON`` triggers ``Path.mkdir()`` /
    ``open()`` failures on Windows and the recording / audit trail
    is lost.  Mirrors the PluginStorage R71-13 fix.
    """
    import re as _re_local
    safe = _re_local.sub(r'[/\\:*?"<>|]', '_', session_id)
    # Strip control chars (RFC 9110 forbids these in tokens too).
    safe = "".join(c if ord(c) >= 32 and c != "\x7f" else "_" for c in safe)
    safe = safe.strip("._ ")
    if not safe or safe in (".", ".."):
        return "_invalid_session_"
    base = safe.split(".")[0].upper()
    if base in _WIN_RESERVED_BASENAMES:
        return "_" + safe
    return safe


class SessionRecorder:
    """Records scrubbed request/response pairs to per-session JSONL files.

    Storage layout::

        {storage_dir}/
        +-- {session_id}/
        |   +-- recording.jsonl   # one JSON object per line
        |   +-- metadata.json     # session metadata
        +-- _index.json           # session index for fast listing
    """

    # File locks use a WeakValueDictionary so unused locks are garbage
    # collected once no recorder instance still references them; this
    # prevents unbounded growth and throughput collapse on the fallback.
    _shared_file_locks: "weakref.WeakValueDictionary[tuple[str, str], threading.Lock]" = weakref.WeakValueDictionary()
    # Index locks are keyed by (storage_key, id(event_loop)) so a lock
    # created on a closed loop (uvicorn reload, test runner) is not
    # reused after the loop has been torn down.  D7 fix: same
    # weak-ref + cap policy as ``_shared_file_locks`` so dev/CI loops
    # don't accumulate stale entries indefinitely.  Recorder instances
    # pin their lock via ``_owned_index_lock`` for the loop's lifetime.
    _shared_index_locks: "weakref.WeakValueDictionary[tuple[str, int], asyncio.Lock]" = weakref.WeakValueDictionary()
    _shared_locks_guard = threading.Lock()
    _MAX_SHARED_LOCKS = 10_000
    _fallback_file_lock = threading.Lock()
    # E7 fix + F6 follow-up: shared coarse fallback for index locks.
    # Two recorders that hit the over-cap branch on the same storage_dir
    # AND the same loop must share a lock so concurrent `_index.json`
    # writes serialise.  We use a WeakValueDictionary keyed by loop_id
    # so dead loops' entries are GC'd automatically once no recorder
    # holds them (each recorder pins its own lock via `_owned_index_lock`,
    # so the entry survives as long as any peer recorder needs it).
    # F6 fix: the previous strong-ref `_owned_fallback_index_locks`
    # pinned one lock per `id(loop)` forever, leaking across event-loop
    # restarts and exposing an `id()` reuse hazard.
    _fallback_index_locks: "weakref.WeakValueDictionary[int, asyncio.Lock]" = weakref.WeakValueDictionary()

    def __init__(self, storage_dir: str, *, store_body_original: bool = False) -> None:
        """Initialize with base storage directory for all sessions."""
        self.storage_dir = Path(storage_dir).expanduser()
        self._storage_key = str(self.storage_dir.resolve())
        # Raw/original payload recording is opt-in because it can contain PII.
        self._store_body_original = store_body_original
        # Strong refs so the WeakValueDictionary entries survive for the
        # lifetime of this recorder instance; otherwise GC might evict the
        # lock while another thread is holding it via the weak reference.
        self._owned_file_locks: dict[tuple[str, str], threading.Lock] = {}
        self._owned_index_lock: asyncio.Lock | None = None
        # Share locks across recorder instances that point at the same storage
        # directory so hot-swapped recorders cannot race on the same files.
        self._index_lock = self._get_index_lock()

    def _get_index_lock(self) -> asyncio.Lock:
        """Return the async index lock for this storage directory + loop."""
        try:
            loop = asyncio.get_running_loop()
            loop_id = id(loop)
        except RuntimeError:
            # No running loop — use a sentinel so locks created now are
            # not confused with locks created under a real loop.
            loop_id = 0
        key = (self._storage_key, loop_id)
        with self._shared_locks_guard:
            lock = self._shared_index_locks.get(key)
            if lock is None:
                # D7 fix: same cap policy as `_shared_file_locks` to
                # bound worst-case memory if many short-lived loops
                # are created (uvicorn --reload, test suites).
                if len(self._shared_index_locks) >= self._MAX_SHARED_LOCKS:
                    # E7 fix: over-cap recorders now share a per-loop
                    # fallback lock so concurrent writers to the same
                    # `_index.json` still serialise (coarsely but
                    # correctly).  Previous behaviour created a fresh
                    # unshared lock and let peer recorders corrupt the
                    # index.
                    lock = self._fallback_index_locks.get(loop_id)
                    if lock is None:
                        lock = asyncio.Lock()
                        self._fallback_index_locks[loop_id] = lock
                        # F6 fix: do NOT pin at class level.  The
                        # `_owned_index_lock` set below pins the lock
                        # for the lifetime of THIS recorder; once all
                        # recorders sharing this fallback are GC'd,
                        # the WeakValueDictionary entry can be evicted
                        # too — closing the per-loop leak.
                else:
                    lock = asyncio.Lock()
                    self._shared_index_locks[key] = lock
            # Pin for our lifetime so a peer recorder's GC cycle
            # cannot evict the lock while we're using it.
            self._owned_index_lock = lock
            return lock

    def _get_file_lock(self, session_id: str) -> threading.Lock:
        """Return a per-session threading lock for file writes.

        Uses the sanitized session ID as key to match the actual
        path-unsafe chars (``/\\:*?\"<>|``) with ``_`` to make a safe
        directory path and prevent two raw IDs from racing on the
        same directory with different locks.
        """
        safe_id = _safe_session_id(session_id)
        key = (self._storage_key, safe_id)
        with self._shared_locks_guard:
            # Look up with strong reference first (from this recorder), then
            # the shared WeakValueDictionary (from another recorder on the
            # same storage dir).
            lock = self._owned_file_locks.get(key)
            if lock is None:
                lock = self._shared_file_locks.get(key)
            if lock is None:
                if len(self._shared_file_locks) >= self._MAX_SHARED_LOCKS:
                    return self._fallback_file_lock
                lock = threading.Lock()
                self._shared_file_locks[key] = lock
            # Pin for our lifetime so a peer recorder's GC cycle cannot
            # collect the lock mid-use.
            self._owned_file_locks[key] = lock
            return lock

    def _session_dir(self, session_id: str) -> Path:
        """Return the directory path for a given session.

        Sanitizes the session ID to prevent directory traversal and
        Windows reserved-name collisions (72-3 fix).
        """
        return self.storage_dir / _safe_session_id(session_id)

    def _recording_path(self, session_id: str) -> Path:
        """Return the recording.jsonl path for a given session."""
        return self._session_dir(session_id) / "recording.jsonl"

    def _metadata_path(self, session_id: str) -> Path:
        """Return the metadata.json path for a given session."""
        return self._session_dir(session_id) / "metadata.json"

    def _index_path(self) -> Path:
        """Return the _index.json path at the storage root."""
        return self.storage_dir / "_index.json"

    async def _ensure_session_dir(self, session_id: str) -> None:
        """Create the session directory if it does not already exist."""
        session_dir = self._session_dir(session_id)
        await asyncio.to_thread(session_dir.mkdir, parents=True, exist_ok=True)

    async def record_request(
        self,
        session_id: str,
        provider: str,
        method: str,
        path: str,
        body_scrubbed: dict,
        pii_entities_found: int,
        latency_ms: float,
        request_id: str = "",
        body_original: dict | None = None,
        url: str = "",
        headers: dict[str, str] | None = None,
        pipeline_breakdown: list[dict] | None = None,
        proxy_type: str = "",
    ) -> None:
        """Append a scrubbed request record to the session's recording.jsonl.

        Args:
            session_id: The session identifier.
            provider: Provider name (e.g. ``"anthropic"``).
            method: HTTP method (e.g. ``"POST"``).
            path: Request path (e.g. ``"/v1/messages"``).
            body_scrubbed: The scrubbed request body (dict). Must not contain
                real PII -- only scrubbed/tokenized content.
            pii_entities_found: Number of PII entities detected.
            latency_ms: Pipeline scrubbing latency in milliseconds.
            request_id: Unique ID to pair request with its response.
            body_original: The original request body before scrubbing (optional).
            url: Full request URL (optional).
            headers: Request headers (sensitive values masked).
            pipeline_breakdown: Per-stage detection counts,
                e.g. ``[{"stage": "presidio", "count": 5}, ...]``.
            proxy_type: ``"reverse"`` or ``"forward"``.
        """
        await self._ensure_session_dir(session_id)
        record: dict = {
            "ts": _utc_now(),
            "dir": "request",
            "request_id": request_id,
            "provider": provider,
            "method": method,
            "path": path,
            "body_scrubbed": body_scrubbed,
            "pii_entities_found": pii_entities_found,
            "latency_ms": latency_ms,
        }
        if url:
            record["url"] = url
        if proxy_type:
            record["proxy_type"] = proxy_type
        if body_original is not None and getattr(self, '_store_body_original', False):
            record["body_original"] = body_original
        if headers is not None:
            record["headers"] = _mask_sensitive_headers(headers)
        if pipeline_breakdown is not None:
            record["pipeline_breakdown"] = pipeline_breakdown
        line = json.dumps(record, separators=(",", ":")) + "\n"
        await asyncio.to_thread(_append_text, self._recording_path(session_id), line, self._get_file_lock(session_id))

    async def record_response(
        self,
        session_id: str,
        status: int,
        streaming: bool,
        body_scrubbed: str | dict,
        tokens_unscrubbed: int,
        request_id: str = "",
        body_original: str | dict | None = None,
        headers: dict[str, str] | None = None,
        network_ms: float = 0.0,
        unscrub_ms: float = 0.0,
        total_ms: float = 0.0,
    ) -> None:
        """Append a scrubbed response record to the session's recording.jsonl.

        Args:
            session_id: The session identifier.
            status: HTTP status code.
            streaming: Whether the response was an SSE stream.
            body_scrubbed: The scrubbed response body. For streaming responses
                this is typically a summary string like
                ``"[SSE stream - 47 events]"``.
            tokens_unscrubbed: Number of tokens that were unscrubbed in the
                response.
            request_id: Unique ID to pair response with its request.
            body_original: The original/unscrubbed response body (optional).
                For requests this is the pre-scrub body; for responses this
                is the post-unscrub body.
            headers: Response headers (sensitive values masked).
            network_ms: Time spent waiting for upstream response.
            unscrub_ms: Time spent unscrubbing the response.
            total_ms: Total request-to-response time.
        """
        await self._ensure_session_dir(session_id)
        record: dict = {
            "ts": _utc_now(),
            "dir": "response",
            "request_id": request_id,
            "status": status,
            "streaming": streaming,
            "body_scrubbed": body_scrubbed,
            "tokens_unscrubbed": tokens_unscrubbed,
        }
        if body_original is not None and getattr(self, '_store_body_original', False):
            record["body_original"] = body_original
        if headers is not None:
            record["headers"] = _mask_sensitive_headers(headers)
        if network_ms > 0:
            record["network_ms"] = round(network_ms, 2)
        if unscrub_ms > 0:
            record["unscrub_ms"] = round(unscrub_ms, 2)
        if total_ms > 0:
            record["total_ms"] = round(total_ms, 2)
        line = json.dumps(record, separators=(",", ":")) + "\n"
        await asyncio.to_thread(_append_text, self._recording_path(session_id), line, self._get_file_lock(session_id))

    async def write_metadata(
        self,
        session_id: str,
        provider: str,
        harness: str,
        agent_info: dict | None = None,
    ) -> None:
        """Write or update metadata.json for a session.

        If the metadata file already exists, the ``last_activity_at`` and
        ``request_count`` fields are updated (request_count is incremented).
        Otherwise a new metadata file is created.

        Args:
            session_id: The session identifier.
            provider: Provider name.
            harness: Harness name (e.g. ``"claude-code"``).
            agent_info: Optional dictionary with agent details (model, version).
        """
        await self._ensure_session_dir(session_id)
        metadata_path = self._metadata_path(session_id)
        now = _utc_now_seconds()
        lock = self._get_file_lock(session_id)

        def _read_modify_write():
            with lock:
                existing: dict | None = None
                if metadata_path.exists():
                    existing = json.loads(metadata_path.read_text(encoding="utf-8"))

                if existing is not None:
                    existing["last_activity_at"] = now
                    existing["request_count"] = existing.get("request_count", 0) + 1
                    if agent_info is not None:
                        existing["agent_info"] = agent_info
                    metadata = existing
                else:
                    metadata = {
                        "session_id": session_id,
                        "provider": provider,
                        "harness": harness,
                        "started_at": now,
                        "last_activity_at": now,
                        "request_count": 1,
                        "agent_info": agent_info,
                    }

                _write_text(metadata_path, json.dumps(metadata, indent=2))

        await asyncio.to_thread(_read_modify_write)

    async def get_session_recordings(self, session_id: str) -> list[dict]:
        """Read all recording entries for a session.

        Args:
            session_id: The session identifier.

        Returns:
            List of recording entry dicts, one per JSONL line. Returns an
            empty list if the recording file does not exist.

        R55-4 fix: skip individual malformed JSONL lines instead of
        propagating ``JSONDecodeError`` to the UI as a 500 (matches
        ``get_recent_recordings`` behavior).  A crash during append
        can leave a truncated final line — that should not break the
        session-recordings endpoint.
        """
        recording_path = self._recording_path(session_id)
        if not recording_path.exists():
            return []

        content = await asyncio.to_thread(_read_text, recording_path)
        entries: list[dict] = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entries.append(json.loads(stripped))
            except (json.JSONDecodeError, ValueError):
                logger.warning(
                    "Skipping malformed JSONL line in %s (len=%d)",
                    recording_path, len(stripped),
                )
        return entries

    async def list_sessions(self) -> list[dict]:
        """List all sessions from the index file.

        Returns:
            List of session summary dicts from ``_index.json``. Returns an
            empty list if the index file does not exist or is corrupt.

        R53-5 fix: tolerate a corrupt/truncated ``_index.json`` (which
        can occur if the process is killed mid-write on a non-atomic
        filesystem) by returning an empty list rather than raising
        ``JSONDecodeError`` to the UI as a permanent 500.
        """
        index_path = self._index_path()
        if not index_path.exists():
            return []

        content = await asyncio.to_thread(_read_text, index_path)
        try:
            parsed = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            logger.warning(
                "Recording index %s is corrupt; returning empty session list.",
                index_path,
            )
            return []
        if not isinstance(parsed, list):
            logger.warning(
                "Recording index %s root is %s, not a list; returning empty.",
                index_path, type(parsed).__name__,
            )
            return []
        return parsed

    async def clear_all(self) -> int:
        """Delete all session recording directories and the index file.

        Returns:
            Number of session directories removed.

        R69-4 fix: acquire ``_index_lock`` around the operation so a
        concurrent ``update_index`` doesn't race with the index
        deletion (which would either re-create a stale entry post-
        delete or unlink the file just-written).
        """
        import shutil

        count = 0

        def _do_clear():
            nonlocal count
            if not self.storage_dir.exists():
                return
            for child in self.storage_dir.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                    count += 1
            index_path = self._index_path()
            if index_path.exists():
                index_path.unlink()

        async with self._index_lock:
            await asyncio.to_thread(_do_clear)
        return count

    async def update_index(
        self,
        session_id: str,
        provider: str,
        harness: str,
        request_count: int,
    ) -> None:
        """Update _index.json with session summary for fast listing.

        If the session already exists in the index, its entry is updated.
        Otherwise a new entry is appended.

        Args:
            session_id: The session identifier.
            provider: Provider name.
            harness: Harness name.
            request_count: Current request count for the session.
        """
        index_path = self._index_path()
        index_path.parent.mkdir(parents=True, exist_ok=True)

        async with self._index_lock:
            entries: list[dict] = []
            if index_path.exists():
                content = await asyncio.to_thread(_read_text, index_path)
                # R53-5 fix: a truncated/corrupt index must not
                # permanently break recording.  Treat it as empty and
                # rewrite atomically below.
                try:
                    parsed = json.loads(content)
                    if isinstance(parsed, list):
                        entries = parsed
                except (json.JSONDecodeError, ValueError):
                    logger.warning(
                        "Recording index %s is corrupt; rewriting from scratch.",
                        index_path,
                    )

            now = _utc_now_seconds()
            found = False
            for entry in entries:
                if entry.get("session_id") == session_id:
                    entry["provider"] = provider
                    entry["harness"] = harness
                    entry["request_count"] = request_count
                    entry["last_activity_at"] = now
                    found = True
                    break

            if not found:
                entries.append({
                    "session_id": session_id,
                    "provider": provider,
                    "harness": harness,
                    "started_at": now,
                    "request_count": request_count,
                })

            await asyncio.to_thread(
                _write_text, index_path, json.dumps(entries, indent=2)
            )

    async def get_recent_recordings(self, limit: int = 50) -> list[dict]:
        """Read recent recording entries across all sessions.

        Iterates every session directory, reads JSONL files, tags each entry
        with its ``session_id``, and returns the *limit* most recent entries
        sorted by timestamp descending.

        Args:
            limit: Maximum number of entries to return.

        Returns:
            List of recording entry dicts, newest first.
        """
        if not self.storage_dir.exists():
            return []

        all_entries: list[dict] = []
        for session_dir in self.storage_dir.iterdir():
            if not session_dir.is_dir() or session_dir.name.startswith("_"):
                continue
            recording_path = session_dir / "recording.jsonl"
            if not recording_path.exists():
                continue
            sid = session_dir.name
            content = await asyncio.to_thread(_read_text, recording_path)
            for line in content.splitlines():
                stripped = line.strip()
                if stripped:
                    try:
                        entry = json.loads(stripped)
                        entry["session_id"] = sid
                        all_entries.append(entry)
                    except json.JSONDecodeError:
                        continue

        # Sort by timestamp descending, take the most recent entries
        all_entries.sort(key=lambda e: e.get("ts", ""), reverse=True)
        return all_entries[:limit]
