"""Replacement strategies for token generation.

Each strategy controls how a replacement token is generated for a given
entity type.  The default strategy produces ``REDACTED_{TYPE}_{N}`` tokens.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
import sys
import uuid
from abc import ABC, abstractmethod

from scruxy.config.models import ReplacementConfig

logger = logging.getLogger(__name__)


class ReplacementStrategy(ABC):
    """Base class for token replacement strategies.

    Implementations must ensure that ``generate`` returns values that are
    **unique across all PII within a session**.  If two different PII strings
    receive the same token, the reverse (unscrub) mapping will silently
    corrupt.  The ``DefaultReplacement`` and ``UuidReplacement`` strategies
    guarantee uniqueness; custom ``ScriptReplacement`` scripts must do so
    themselves.
    """

    @abstractmethod
    def generate(self, entity_type: str, pii: str, count: int) -> str | None:
        """Generate a replacement token.

        Args:
            entity_type: The entity category (e.g. ``"EMAIL"``, ``"PERSON"``).
            pii: The original PII text.
            count: The per-type counter value for this token.

        Returns:
            The replacement string, or ``None`` to signal "skip redaction"
            (keep original PII in output).
        """


def _word_count(text: str) -> int:
    """Count whitespace-separated words in *text*."""
    return len(text.split())


def _suffix_letter(index: int) -> str:
    """Return suffix letter(s) for sub-token indexing: A, B, ..., Z, AA, AB, ..."""
    result = []
    n = index
    while True:
        result.append(chr(ord("A") + n % 26))
        n = n // 26 - 1
        if n < 0:
            break
    return "".join(reversed(result))


class DefaultReplacement(ReplacementStrategy):
    """Produces ``REDACTED_{TYPE}_{N}`` tokens.

    Preserves word count: multi-word PII gets suffixed sub-tokens so the
    replacement has the same number of whitespace-separated words.
    E.g. ``"Alice Johnson"`` (2 words) → ``"REDACTED_PERSON_1A REDACTED_PERSON_1B"``.
    """

    def generate(self, entity_type: str, pii: str, count: int) -> str:
        n_words = _word_count(pii)
        if n_words <= 1:
            return f"REDACTED_{entity_type}_{count}"
        parts = [
            f"REDACTED_{entity_type}_{count}{_suffix_letter(i)}"
            for i in range(n_words)
        ]
        return " ".join(parts)


class UuidReplacement(ReplacementStrategy):
    """Produces a random UUID v4 as the replacement token.

    Preserves word count by generating one UUID per word in the original PII.
    """

    def generate(self, entity_type: str, pii: str, count: int) -> str:
        n_words = _word_count(pii)
        if n_words <= 1:
            return str(uuid.uuid4())
        return " ".join(str(uuid.uuid4()) for _ in range(n_words))


class ScriptReplacement(ReplacementStrategy):
    """Runs an external command to generate the replacement token.

    The command receives ``entity_type`` and ``count`` as arguments.  The
    original PII is passed via **stdin** (not argv) to avoid leaking it
    in the OS process table.  The replacement is read from stdout.

    On error, non-zero exit, or timeout the strategy falls back to
    :class:`DefaultReplacement`.

    Special return values from the script:
    - Empty/whitespace-only output -> ``None`` (skip redaction)
    - Output identical to *pii* -> ``None`` (skip redaction)
    """

    def __init__(self, command: str, timeout_ms: int = 5000) -> None:
        from pathlib import Path

        parts = shlex.split(command, posix=(sys.platform != "win32"))
        # Expand ~ in command parts (subprocess doesn't do shell expansion)
        self._command_parts = [
            str(Path(p).expanduser()) if p.startswith("~") else p
            for p in parts
        ]
        # When running inside a virtualenv, resolve bare 'python'/'python3'
        # to the venv interpreter so subprocess scripts can import venv packages.
        if (
            self._command_parts
            and self._command_parts[0] in ("python", "python3")
            and sys.prefix != sys.base_prefix
        ):
            bin_dir = "Scripts" if sys.platform == "win32" else "bin"
            venv_python = Path(sys.prefix) / bin_dir / self._command_parts[0]
            if not venv_python.exists() and sys.platform == "win32":
                venv_python = venv_python.with_suffix(".exe")
            if venv_python.exists():
                self._command_parts[0] = str(venv_python)
        self._timeout = timeout_ms / 1000.0
        self._fallback = DefaultReplacement()
        self._failure_logged: set[str] = set()

    def generate(self, entity_type: str, pii: str, count: int) -> str | None:
        try:
            result = subprocess.run(
                [*self._command_parts, entity_type, str(count)],
                input=pii,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            if result.returncode != 0:
                if entity_type not in self._failure_logged:
                    logger.error(
                        "Script replacement exited with code %d for %s. stderr: %s",
                        result.returncode,
                        entity_type,
                        result.stderr.strip() or "(empty)",
                    )
                    self._failure_logged.add(entity_type)
                return self._fallback.generate(entity_type, pii, count)

            output = result.stdout.strip()
            if not output:
                return None
            if output == pii:
                return None
            return output
        except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
            if entity_type not in self._failure_logged:
                logger.error(
                    "Script replacement failed for %s, falling back to default",
                    entity_type,
                    exc_info=True,
                )
                self._failure_logged.add(entity_type)
            return self._fallback.generate(entity_type, pii, count)


def build_strategies(
    config: dict[str, ReplacementConfig],
) -> dict[str, ReplacementStrategy]:
    """Convert a config dict to a strategy dict keyed by entity type.

    Args:
        config: Mapping of entity type name to :class:`ReplacementConfig`.

    Returns:
        Mapping of entity type name to :class:`ReplacementStrategy`.
    """
    strategies: dict[str, ReplacementStrategy] = {}
    for entity_type, cfg in config.items():
        if not cfg.enabled:
            continue
        if cfg.strategy == "uuid":
            strategies[entity_type] = UuidReplacement()
        elif cfg.strategy == "script":
            strategies[entity_type] = ScriptReplacement(
                command=cfg.command,
                timeout_ms=cfg.timeout_ms,
            )
        else:
            strategies[entity_type] = DefaultReplacement()
    return strategies
