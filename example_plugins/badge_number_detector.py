"""Example plugin: detect employee badge numbers.

Drop this file into ``~/.scruxy/plugins/`` to activate.
Detects employee badge numbers matching a configurable regex pattern
(default: ``BADGE-XXXX`` where X is a digit) and reports them as
``BADGE_NUMBER`` entities.

Installation:
    cp example_plugins/badge_number_detector.py ~/.scruxy/plugins/

Configuration (in config.yaml under the plugins stage):
    pipeline:
      stages:
        - name: plugins
          config:
            plugin_configs:
              badge_number_detector:
                pattern: "BADGE-\\d{4}"      # Default pattern
                score: 1.0                    # Detection confidence
                context_words:                # Words that boost score
                  - badge
                  - employee
                  - id

Alternative configurations:
    # 6-digit badge numbers:
    pattern: "BADGE-\\d{6}"

    # Custom prefix:
    pattern: "EMP-\\d{4}"

    # Multiple formats:
    pattern: "(BADGE|EMP|ID)-\\d{4,6}"

    # Lower confidence with context boosting:
    score: 0.7
    context_words: ["badge", "employee", "id", "number"]

Testing:
    Use the Pipeline Tester page (/ui/tester) to verify detection.
    The default Anthropic/OpenAI samples include "BADGE-4872" which
    this plugin will detect.
"""
from __future__ import annotations

import re

from scruxy.plugin.base import ConfigField, DetectorPlugin, PiiEntity

# Default pattern: "BADGE-" followed by exactly 4 digits.
_DEFAULT_PATTERN = r"BADGE-\d{4}"

# Number of characters around a match to search for context words.
_CONTEXT_WINDOW = 50

# Score boost when a context word is found near a match.
_CONTEXT_BOOST = 0.15


class BadgeNumberDetector(DetectorPlugin):
    """Detect employee badge numbers matching a configurable regex pattern.

    Supports optional context-word boosting: when words like "badge" or
    "employee" appear near a match, the confidence score is increased.
    """

    name = "badge_number_detector"
    version = "1.1"
    description = "Detect employee badge numbers matching a configurable regex pattern with optional context-word boosting."

    config_schema = [
        ConfigField(
            name="pattern",
            field_type="string",
            default=_DEFAULT_PATTERN,
            description="Regex pattern for badge numbers",
            label="Badge Pattern",
            details="Default matches BADGE-XXXX where X is a digit. Adjust for your organization's badge format (e.g. EMP-\\d{6}).",
        ),
        ConfigField(
            name="score",
            field_type="number",
            default=1.0,
            description="Base confidence score for detected badges",
            label="Detection Score",
            details="Score before context boosting. Range 0.0-1.0. Lower values pair well with context_words for boosting.",
            min_value=0.0,
            max_value=1.0,
        ),
        ConfigField(
            name="context_words",
            field_type="list",
            default=["badge", "employee", "id"],
            description="Words near a match that boost the confidence score",
            label="Context Words",
            details="If any of these words appear within 50 characters of a match, the score is boosted by 0.15 (capped at 1.0).",
        ),
    ]

    def setup(self, config: dict) -> None:
        """Compile the badge number regex and load config values.

        Args:
            config: Plugin configuration dict with optional keys:
                ``pattern`` (str), ``score`` (float), ``context_words`` (list).
        """
        raw_pattern: str = config.get("pattern", _DEFAULT_PATTERN)
        self._pattern: re.Pattern[str] = re.compile(raw_pattern)
        self._score: float = config.get("score", 1.0)
        self._context_words: list[str] = config.get("context_words", ["badge", "employee", "id"])

    def detect(self, text: str, language: str) -> list[PiiEntity]:
        """Return all badge number matches in *text*.

        If context_words are configured and found near a match, the score
        is boosted by 0.15 (capped at 1.0).
        """
        if not text:
            return []

        text_lower = text.lower()
        results: list[PiiEntity] = []

        for match in self._pattern.finditer(text):
            score = self._score

            # Context-word boosting
            if self._context_words:
                window_start = max(0, match.start() - _CONTEXT_WINDOW)
                window_end = min(len(text_lower), match.end() + _CONTEXT_WINDOW)
                context = text_lower[window_start:window_end]
                for word in self._context_words:
                    if word.lower() in context:
                        score = min(score + _CONTEXT_BOOST, 1.0)
                        break

            results.append(
                PiiEntity(
                    entity_type="BADGE_NUMBER",
                    start=match.start(),
                    end=match.end(),
                    score=score,
                    source=self.name,
                )
            )

        return results

    def teardown(self) -> None:
        """No resources to clean up."""
