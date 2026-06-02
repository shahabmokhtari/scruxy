"""Resolve session titles from Claude and Copilot transcript files.

Claude stores JSONL transcripts in ``~/.claude/projects/{project}/{session}.jsonl``.
The title is the first user message text (truncated to 200 chars).

Copilot stores session state in ``~/.copilot/session-state/{session}/``.
The title comes from the ``summary`` field in ``workspace.yaml``.

Results are cached in memory so repeated lookups are O(1).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_MAX_TITLE_LEN = 200


class SessionTitleResolver:
    """Resolve human-readable titles for proxy session IDs.

    Titles are cached in ``_cache`` (session_id → title).  The resolver
    scans transcript directories lazily on first call to :meth:`resolve`
    and can be refreshed with :meth:`refresh`.
    """

    def __init__(self) -> None:
        self._cache: dict[str, str] = {}
        self._scanned = False
        # Track session IDs we've attempted but got no title — retry later
        self._pending: set[str] = set()
        self._claude_base = Path.home() / ".claude" / "projects"
        self._copilot_base = Path.home() / ".copilot" / "session-state"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve(self, session_id: str) -> str:
        """Return the cached title for *session_id*, or empty string."""
        if not self._scanned:
            self._scan_all()
        if session_id in self._cache:
            return self._cache[session_id]
        # Retry for pending sessions (transcript may have been created since last scan)
        if session_id in self._pending:
            self._resolve_single(session_id)
        return self._cache.get(session_id, "")

    def resolve_all(self, session_ids: list[str]) -> dict[str, str]:
        """Return a dict mapping session_id → title for all known titles.

        Sessions without a cached title are retried individually (the
        transcript file may have appeared since the initial scan).
        """
        if not self._scanned:
            self._scan_all()
        # Retry any requested session that's still pending
        for sid in session_ids:
            if sid not in self._cache and sid in self._pending:
                self._resolve_single(sid)
            elif sid not in self._cache:
                # Brand new session we've never seen — try resolving
                self._pending.add(sid)
                self._resolve_single(sid)
        return {sid: self._cache[sid] for sid in session_ids if sid in self._cache}

    def set_title(self, session_id: str, title: str) -> None:
        """Manually set or override a title (e.g. from live request data)."""
        if title:
            self._cache[session_id] = title[:_MAX_TITLE_LEN]

    def refresh(self) -> None:
        """Force a full rescan of transcript directories."""
        self._scanned = False
        self._cache.clear()
        self._scan_all()

    @property
    def titles(self) -> dict[str, str]:
        """Read-only view of the full cache."""
        if not self._scanned:
            self._scan_all()
        return dict(self._cache)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def _scan_all(self) -> None:
        """Scan both Claude and Copilot transcript directories."""
        self._scanned = True
        self._scan_claude()
        self._scan_copilot()
        # All scanned sessions that didn't get a title are pending for retry
        logger.info(
            "SessionTitleResolver: resolved %d session titles (claude=%s, copilot=%s)",
            len(self._cache),
            self._claude_base,
            self._copilot_base,
        )

    def _resolve_single(self, session_id: str) -> None:
        """Try to resolve a single session's title (retry for pending sessions).

        Checks both Copilot workspace.yaml and Claude JSONL by session ID.
        On success, moves the session from pending to cache.
        """
        # Try Copilot first (direct directory lookup by session ID)
        # Sanitize: reject session IDs with path separators or traversal
        if "/" in session_id or "\\" in session_id or ".." in session_id:
            self._pending.discard(session_id)
            return
        copilot_dir = self._copilot_base / session_id
        # Verify the resolved path is actually under the base directory
        try:
            copilot_dir.resolve().relative_to(self._copilot_base.resolve())
        except ValueError:
            self._pending.discard(session_id)
            return
        if copilot_dir.is_dir():
            ws = copilot_dir / "workspace.yaml"
            if ws.is_file():
                title = self._extract_copilot_title(str(ws))
                if title:
                    self._cache[session_id] = title
                    self._pending.discard(session_id)
                    return

        # Try Claude — session ID may be "claude-{uuid}", strip prefix
        claude_id = session_id
        if claude_id.startswith("claude-"):
            claude_id = claude_id[7:]
        # Search all project dirs for a matching JSONL
        if self._claude_base.is_dir():
            try:
                for project_dir in self._claude_base.iterdir():
                    if not project_dir.is_dir():
                        continue
                    jsonl = project_dir / f"{claude_id}.jsonl"
                    if jsonl.is_file():
                        title = self._extract_claude_title(str(jsonl))
                        if title:
                            self._cache[session_id] = title
                            self._pending.discard(session_id)
                            return
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Claude: ~/.claude/projects/{project}/{session_id}.jsonl
    # ------------------------------------------------------------------

    def _scan_claude(self) -> None:
        """Scan Claude transcript JSONL files for session titles."""
        if not self._claude_base.is_dir():
            return
        try:
            for project_dir in self._claude_base.iterdir():
                if not project_dir.is_dir():
                    continue
                for entry in project_dir.iterdir():
                    if entry.is_file() and entry.suffix == ".jsonl":
                        session_id = entry.stem
                        # Claude sessions are keyed as "claude-{uuid}"
                        cache_key = f"claude-{session_id}"
                        if cache_key in self._cache:
                            continue
                        title = self._extract_claude_title(str(entry))
                        if title:
                            self._cache[cache_key] = title
        except OSError:
            logger.debug("Failed to scan Claude transcripts", exc_info=True)

    @staticmethod
    def _extract_claude_title(file_path: str) -> str:
        """Read first ~30 lines of a Claude JSONL to find the first user message."""
        try:
            with open(file_path, encoding="utf-8") as f:
                for _ in range(30):
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    msg = data.get("message")
                    if isinstance(msg, dict) and msg.get("role") == "user":
                        text = _extract_text_content(msg.get("content"))
                        if text:
                            return text[:_MAX_TITLE_LEN]
        except OSError:
            pass
        return ""

    # ------------------------------------------------------------------
    # Copilot: ~/.copilot/session-state/{session_id}/workspace.yaml
    # ------------------------------------------------------------------

    def _scan_copilot(self) -> None:
        """Scan Copilot session directories for workspace.yaml summaries."""
        if not self._copilot_base.is_dir():
            return
        try:
            for entry in self._copilot_base.iterdir():
                if not entry.is_dir():
                    continue
                session_id = entry.name
                if session_id in self._cache:
                    continue
                workspace_yaml = entry / "workspace.yaml"
                if workspace_yaml.is_file():
                    title = self._extract_copilot_title(str(workspace_yaml))
                    if title:
                        self._cache[session_id] = title
        except OSError:
            logger.debug("Failed to scan Copilot sessions", exc_info=True)

    @staticmethod
    def _extract_copilot_title(yaml_path: str) -> str:
        """Read workspace.yaml and return the 'summary' field."""
        try:
            with open(yaml_path, encoding="utf-8") as f:
                for line in f:
                    line = line.rstrip("\n\r")
                    if not line or line.startswith("#") or line[0] in (" ", "\t"):
                        continue
                    colon = line.find(":")
                    if colon < 1:
                        continue
                    key = line[:colon].strip()
                    if key == "summary":
                        value = line[colon + 1:].strip()
                        if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]:
                            value = value[1:-1]
                        if value:
                            return value[:_MAX_TITLE_LEN]
        except OSError:
            pass
        return ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_text_content(content: Any) -> str | None:
    """Extract plain text from Claude message content (str or list of blocks)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    return text
    return None
