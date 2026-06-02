"""Whitelist plugin — prevents specified terms from being scrubbed.

Runs as the first pipeline stage. Whitelisted terms are detected as PII with
entity type ``WHITELIST``, which the token map resolves to an identity mapping
(the token equals the original text). Because the pipeline replaces detections
with placeholders before later stages run, downstream detectors (Presidio,
regex, user plugins) never see the whitelisted text and cannot scrub it.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml

from scruxy.plugin.base import ConfigField, DetectorPlugin, PiiEntity

logger = logging.getLogger(__name__)


class WhitelistPlugin(DetectorPlugin):
    """Prevents specified terms from being scrubbed by creating identity mappings.

    Terms are matched case-insensitively by default. The original case is
    preserved in the identity token so unscrubbing is transparent.
    """

    name = "whitelist"
    plugin_type = "builtin"
    version = "built-in"
    description = "Allowlist filter that suppresses false-positive PII detections for known safe terms."
    enabled = True

    config_schema = [
        ConfigField(
            name="whitelist_file",
            field_type="file",
            default="~/.scruxy/whitelist.yaml",
            description="Path to YAML file containing whitelisted terms",
            label="Whitelist File",
            details="YAML file with a 'whitelist' list of terms to never scrub.",
        ),
        ConfigField(
            name="word_boundary",
            field_type="boolean",
            default=False,
            description="When enabled, whitelist terms only match whole words (\\b boundaries)",
            label="Word Boundary",
        ),
        ConfigField(
            name="case_sensitive",
            field_type="boolean",
            default=False,
            description="When enabled, whitelist matching is case-sensitive",
            label="Case Sensitive",
        ),
    ]

    def setup(self, config: dict) -> None:
        """Load whitelist terms from the configured YAML file.

        Args:
            config: Configuration dictionary with optional keys:
                ``whitelist_file`` (str path to YAML file),
                ``word_boundary`` (bool), ``case_sensitive`` (bool).
        """
        self._terms: list[str] = []
        self._pattern: re.Pattern[str] | None = None
        self._word_boundary: bool = config.get("word_boundary", False)
        self._case_sensitive: bool = config.get("case_sensitive", False)

        # Propagate to plugin-level attributes for the pipeline engine
        self.use_word_boundary = self._word_boundary
        self.case_sensitive = self._case_sensitive

        whitelist_file = config.get("whitelist_file", "")
        if whitelist_file:
            path = Path(whitelist_file).expanduser()
            if path.exists():
                try:
                    with open(path) as f:
                        data = yaml.safe_load(f) or {}
                    raw = data.get("whitelist", [])
                    if isinstance(raw, list):
                        self._terms = [str(t) for t in raw if t]
                except Exception:
                    logger.warning("Failed to load whitelist file %s", path)

        if self._terms:
            sorted_terms = sorted(self._terms, key=len, reverse=True)
            escaped = [re.escape(t) for t in sorted_terms]
            inner = "|".join(escaped)
            if self._word_boundary:
                inner = "|".join(r"\b" + e + r"\b" for e in escaped)
            flags = 0 if self._case_sensitive else re.IGNORECASE
            self._pattern = re.compile("(?:" + inner + ")", flags)
            logger.info(
                "WhitelistPlugin initialized with %d terms (word_boundary=%s, case_sensitive=%s)",
                len(self._terms),
                self._word_boundary,
                self._case_sensitive,
            )
        else:
            logger.info("WhitelistPlugin initialized with 0 terms (no-op)")

    def detect(self, text: str, language: str = "") -> list[PiiEntity]:
        """Find all occurrences of whitelisted terms in *text*.

        Returns PiiEntity instances with entity_type ``WHITELIST`` and
        score 1.0 so they take priority during merge/deduplication.
        """
        if not text or self._pattern is None:
            return []

        entities: list[PiiEntity] = []
        for match in self._pattern.finditer(text):
            entities.append(
                PiiEntity(
                    entity_type="WHITELIST",
                    start=match.start(),
                    end=match.end(),
                    score=1.0,
                    source="whitelist",
                )
            )

        if entities:
            logger.debug(
                "Whitelist matched %d occurrences in text of length %d",
                len(entities),
                len(text),
            )
        return entities
