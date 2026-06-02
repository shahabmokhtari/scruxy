"""Example plugin: detect internal project codenames.

Drop this file into ``~/.scruxy/plugins/`` to activate.
Detects known project codenames like "Project Phoenix", "Project Titan",
and "Project Mercury" and reports them as ``PROJECT_CODENAME`` entities.

Installation:
    cp example_plugins/project_codename_detector.py ~/.scruxy/plugins/

Configuration (in config.yaml under the plugins stage):
    pipeline:
      stages:
        - name: plugins
          config:
            plugin_configs:
              project_codename_detector:
                codenames:
                  - "Project Phoenix"
                  - "Project Titan"
                  - "Project Mercury"
                case_sensitive: false
                score: 0.95

Alternative configurations:
    # Case-sensitive matching (exact case only):
    case_sensitive: true

    # Higher confidence:
    score: 1.0

    # Custom codenames for your organization:
    codenames:
      - "Project Apollo"
      - "Operation Falcon"
      - "Initiative Horizon"

    # Single codename:
    codenames:
      - "Project X"

Testing:
    Use the Pipeline Tester page (/ui/tester) to verify detection.
    The default Anthropic/OpenAI samples include "Project Phoenix" which
    this plugin will detect.
"""
from __future__ import annotations

from scruxy.plugin.base import ConfigField, DetectorPlugin, PiiEntity

_DEFAULT_CODENAMES = ["Project Phoenix", "Project Titan", "Project Mercury"]


class ProjectCodenameDetector(DetectorPlugin):
    """Detect internal project codenames in text.

    Supports case-insensitive matching (default) and configurable
    confidence scores. All occurrences of each codename are detected.
    """

    name = "project_codename_detector"
    version = "1.1"
    description = "Detect internal project codenames (e.g. 'Project Phoenix') with case-insensitive matching."

    config_schema = [
        ConfigField(
            name="codenames",
            field_type="list",
            default=_DEFAULT_CODENAMES,
            description="List of project codenames to detect",
            label="Project Codenames",
            details="Comma-separated list of internal project codenames to scrub from API traffic.",
        ),
        ConfigField(
            name="case_sensitive",
            field_type="boolean",
            default=False,
            description="Whether matching is case-sensitive",
            label="Case Sensitive",
            details="When disabled (default), 'project phoenix' matches 'Project Phoenix'. Enable for exact-case matching only.",
        ),
        ConfigField(
            name="score",
            field_type="number",
            default=0.95,
            description="Confidence score for detected codenames",
            label="Detection Score",
            details="Range 0.0-1.0. Higher values indicate stronger confidence. Default 0.95 is suitable for exact-match detection.",
            min_value=0.0,
            max_value=1.0,
        ),
    ]

    def setup(self, config: dict) -> None:
        """Load codenames and detection settings from config.

        Args:
            config: Plugin configuration dict with optional keys:
                ``codenames`` (list), ``case_sensitive`` (bool), ``score`` (float).
        """
        custom = config.get("codenames")
        raw_codenames: list[str] = list(custom) if custom is not None else list(_DEFAULT_CODENAMES)
        self._case_sensitive: bool = config.get("case_sensitive", False)
        self._score: float = config.get("score", 0.95)

        # Store codenames with their search variants
        if self._case_sensitive:
            self._codenames = raw_codenames
        else:
            # Store (original, lower) pairs for case-insensitive matching
            self._codenames = raw_codenames
            self._codenames_lower = [c.lower() for c in raw_codenames]

    def detect(self, text: str, language: str) -> list[PiiEntity]:
        """Return all occurrences of known project codenames in *text*.

        Performs case-insensitive matching by default unless case_sensitive
        is enabled in config.
        """
        if not text:
            return []

        results: list[PiiEntity] = []

        if self._case_sensitive:
            for codename in self._codenames:
                self._find_all(text, codename, len(codename), results)
        else:
            text_lower = text.lower()
            for i, codename in enumerate(self._codenames):
                codename_lower = self._codenames_lower[i]
                # Find in lowered text, but use original offsets
                start = 0
                while True:
                    idx = text_lower.find(codename_lower, start)
                    if idx == -1:
                        break
                    results.append(
                        PiiEntity(
                            entity_type="PROJECT_CODENAME",
                            start=idx,
                            end=idx + len(codename),
                            score=self._score,
                            source=self.name,
                        )
                    )
                    start = idx + 1

        return results

    def _find_all(self, text: str, codename: str, length: int, results: list[PiiEntity]) -> None:
        """Find all exact occurrences of codename in text (case-sensitive)."""
        start = 0
        while True:
            idx = text.find(codename, start)
            if idx == -1:
                break
            results.append(
                PiiEntity(
                    entity_type="PROJECT_CODENAME",
                    start=idx,
                    end=idx + length,
                    score=self._score,
                    source=self.name,
                )
            )
            start = idx + 1

    def teardown(self) -> None:
        """No resources to clean up."""
