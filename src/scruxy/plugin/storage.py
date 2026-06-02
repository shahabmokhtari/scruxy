"""Per-plugin key-value storage with optional TTL and disk persistence."""
from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class PluginStorage:
    """Per-plugin key-value store with optional TTL, persisted to disk as JSON.

    Data is stored at ``{base_dir}/{plugin_name}/kv_store.json``.
    Expired entries are automatically evicted on read operations.
    Writes are atomic (write to temp file, then rename).
    """

    def __init__(self, base_dir: str, plugin_name: str) -> None:
        # R67-7 / R68-2 / R71-13 fix: validate plugin_name to prevent
        # path traversal and Windows-specific path-name traps.
        # Plugin names today come from internal registration (not user
        # input), but defense-in-depth: reject path separators,
        # parent-directory references, Windows drive letters,
        # control characters, trailing dots/spaces (silently stripped
        # by Win32 file system), and Windows reserved names
        # (CON, PRN, AUX, NUL, COM1-9, LPT1-9 — these refer to
        # devices, not files, on Windows).
        _WIN_RESERVED = {
            "CON", "PRN", "AUX", "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }
        if (
            not plugin_name
            or "/" in plugin_name
            or "\\" in plugin_name
            or ":" in plugin_name
            or plugin_name in (".", "..")
            or any(ord(c) < 32 for c in plugin_name)
            or plugin_name.endswith((".", " "))
            or plugin_name.upper().split(".")[0] in _WIN_RESERVED
        ):
            raise ValueError(
                f"Invalid plugin_name: {plugin_name!r} (must not contain "
                f"path separators, drive colons, control characters, "
                f"trailing dot/space, Windows reserved names, or be '.' "
                f"or '..')"
            )
        if ".." in plugin_name.split("/") or ".." in plugin_name.split("\\"):
            raise ValueError(f"Invalid plugin_name: {plugin_name!r}")
        # Belt-and-suspenders: ensure resolved path stays under base_dir.
        base_resolved = Path(base_dir).resolve()
        candidate = (base_resolved / plugin_name).resolve()
        try:
            candidate.relative_to(base_resolved)
        except ValueError:
            raise ValueError(
                f"plugin_name {plugin_name!r} would escape storage base_dir"
            )
        self._dir = Path(base_dir) / plugin_name
        self._file = self._dir / "kv_store.json"
        self._data: dict[str, dict[str, Any]] = {}  # key -> {"value": ..., "expires": float|None}
        self._load()

    def _load(self) -> None:
        """Load data from disk if it exists."""
        if self._file.exists():
            try:
                raw = json.loads(self._file.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self._data = raw
            except (json.JSONDecodeError, OSError):
                logger.warning("Failed to load plugin storage from %s", self._file)
                self._data = {}
        self._evict_expired()

    def _evict_expired(self) -> None:
        """Remove expired entries."""
        now = time.time()
        expired = [
            k for k, v in self._data.items()
            if v.get("expires") is not None and v["expires"] <= now
        ]
        for k in expired:
            del self._data[k]

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value by key, returning default if not found or expired."""
        entry = self._data.get(key)
        if entry is None:
            return default
        if entry.get("expires") is not None and entry["expires"] <= time.time():
            del self._data[key]
            return default
        return entry["value"]

    def set(self, key: str, value: Any, ttl_seconds: float | None = None) -> None:
        """Set a key-value pair with optional TTL in seconds."""
        expires = None
        if ttl_seconds is not None:
            expires = time.time() + ttl_seconds
        self._data[key] = {"value": value, "expires": expires}

    def delete(self, key: str) -> bool:
        """Delete a key. Returns True if it existed."""
        return self._data.pop(key, None) is not None

    def keys(self) -> list[str]:
        """Return all non-expired keys."""
        self._evict_expired()
        return list(self._data.keys())

    def flush(self) -> None:
        """Persist current data to disk atomically."""
        self._evict_expired()
        self._dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=str(self._dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
            os.replace(tmp_path, str(self._file))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
