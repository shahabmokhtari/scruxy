"""File/folder path detector plugin.

Detects Windows and Linux file paths and creates a PII entity for each
path segment (directory or filename stem).  The root prefix (e.g. ``C:\\``,
``/home``) and file extensions are preserved; only the inner segments are
flagged for replacement.

Example::

    C:\\importantproject\\secure\\file.txt
    ─────────────────────────────────────────
    kept: C:\\              (root)
    PII:  importantproject  → PATH_SEGMENT entity
    PII:  secure            → PATH_SEGMENT entity
    PII:  file              → PATH_SEGMENT entity (extension .txt kept)
"""
from __future__ import annotations

import re

from scruxy.plugin.base import ConfigField, DetectorPlugin, PiiEntity

# Segments must start with a word char and can contain dots/hyphens only
# between word chars (no trailing dots like "Claude.").
_SEG = r"\.?[\w](?:[\w.\-]*[\w])?"

# Regex: Windows drive-letter paths OR Linux paths with common root dirs
_PATH_RE = re.compile(
    r"(?:"
    r"[A-Za-z]:[/\\]+" + _SEG +
    r"|"
    r"/(?:home|src|usr|etc|var|tmp|opt|bin|sbin|lib|lib64|dev|mnt|root|proc|sys|run|srv|boot|media|snap)"
    r")"
    r"(?:[/\\]+" + _SEG + r")*"
    r"[/\\]*",
)

# Match individual non-separator segments within a path
_SEGMENT_RE = re.compile(r"[^/\\]+")

# Minimum total segments (root + inner) for a path to be scrubbed
_MIN_SEGMENTS = 3


class FilePathDetector(DetectorPlugin):
    """Detect file/folder paths and flag each inner segment as PII."""

    name = "file_path_detector"
    version = "1.0"
    description = "Detect file and folder paths and scrub each segment with a fake word."
    enabled = True

    config_schema = [
        ConfigField(
            name="score",
            field_type="number",
            default=0.95,
            description="Confidence score for detected path segments",
            label="Detection Score",
            min_value=0.0,
            max_value=1.0,
        ),
    ]

    def setup(self, config: dict) -> None:
        self._score = config.get("score", 0.95)
        self._min_segments = int(config.get("min_segments", _MIN_SEGMENTS))

    def detect(self, text: str, language: str = "") -> list[PiiEntity]:
        if not text:
            return []

        entities: list[PiiEntity] = []

        for path_match in _PATH_RE.finditer(text):
            path_str = path_match.group()
            path_start = path_match.start()

            # Find all non-separator segments within the matched path
            segments = list(_SEGMENT_RE.finditer(path_str))

            # Skip short paths
            if len(segments) < self._min_segments:
                continue

            # Skip the first segment (root: drive letter or linux root dir)
            for i, seg in enumerate(segments):
                if i == 0:
                    continue

                seg_text = seg.group()
                abs_start = path_start + seg.start()

                # For the last segment: if it has an extension, only flag the stem
                is_last = i == len(segments) - 1
                dot_idx = seg_text.rfind(".")
                if is_last and dot_idx > 0:
                    stem = seg_text[:dot_idx]
                    if stem:
                        entities.append(
                            PiiEntity(
                                entity_type="PATH_SEGMENT",
                                start=abs_start,
                                end=abs_start + len(stem),
                                score=self._score,
                                source=self.name,
                            )
                        )
                else:
                    entities.append(
                        PiiEntity(
                            entity_type="PATH_SEGMENT",
                            start=abs_start,
                            end=abs_start + len(seg_text),
                            score=self._score,
                            source=self.name,
                        )
                    )

        return entities
