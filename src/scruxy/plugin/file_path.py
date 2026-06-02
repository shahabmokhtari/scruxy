"""File/folder path detector plugin.

Detects Windows and Linux file paths and creates a PII entity for each
path segment (directory or filename stem).  The root prefix (e.g. ``C:\\``,
``/home``) and file extensions are preserved; only the inner segments are
flagged for replacement.

Paths must have at least 3 total segments (root + 2 inner) to be considered
sensitive enough to scrub.

URLs (``http://``, ``https://``, ``ftp://``, and bare domain paths like
``example.com/src/...``) are excluded to avoid false positives.

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

# Regex: Windows drive-letter paths OR Unix/macOS paths with common root dirs
_PATH_RE = re.compile(
    r"(?:"
    r"(?<![A-Za-z])[A-Za-z]:[/\\]+" + _SEG +
    r"|"
    r"/(?:home|src|usr|etc|var|tmp|opt|bin|sbin|lib|lib64|dev|mnt|root|proc|sys|run|srv|boot|media|snap|Users|Applications|Library|System|Volumes)"
    r")"
    r"(?:[/\\]+" + _SEG + r")*"
    r"[/\\]*",
)

# Match individual non-separator segments within a path
_SEGMENT_RE = re.compile(r"[^/\\]+")

# Minimum total segments (root + inner) for a path to be scrubbed
_MIN_SEGMENTS = 3

# URL scheme keywords.  The drive-letter regex ``[A-Za-z]:`` can grab the
# last letter of a URL scheme (e.g. ``https`` → prefix ``http`` + match
# ``s://…``), so we need to look a few characters *before* the match start
# to detect the scheme.
_URL_SCHEMES = {"http", "https", "ftp", "ftps", "ssh", "git"}
_URL_CONTEXT_LOOKBACK = 2048

# Bare domain: e.g. "example.com/", "api.github.com/", "cdn.xyz.io/"
_BARE_DOMAIN_RE = re.compile(
    r"[\w.-]+\.(?:com|org|net|io|dev|co|edu|gov|info|me|app|cloud|ai|xyz|uk|ca|de|fr|jp|au|us|eu)"
    r"(?=[/:\?#]|$)"
    r"[^\s]*$",
    re.IGNORECASE,
)


class FilePathDetector(DetectorPlugin):
    """Detect file/folder paths and flag each inner segment as PII."""

    name = "file_path"
    version = "built-in"
    description = "Detect file and folder paths and scrub each segment with a fake word."
    plugin_type = "builtin"
    enabled = True
    use_word_boundary = True  # path segments must match whole words in pre-filter
    case_sensitive = True

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
        ConfigField(
            name="min_segments",
            field_type="number",
            default=_MIN_SEGMENTS,
            description="Minimum total path segments (including root) required to scrub",
            label="Min Segments",
            min_value=2,
            max_value=20,
        ),
    ]

    def setup(self, config: dict) -> None:
        self._score = config.get("score", 0.95)
        self._min_segments = int(config.get("min_segments", _MIN_SEGMENTS))

    def _is_url_context(self, text: str, match_start: int) -> bool:
        """Return True if the path match at *match_start* is part of a URL.

        Scans back to the nearest whitespace to find the full token containing
        the match, then checks if that token starts with a URL scheme or a bare
        domain pattern.
        """
        # Bound the lookback so minified or single-token blobs cannot trigger
        # pathological scans for every candidate match.
        window_start = max(0, match_start - _URL_CONTEXT_LOOKBACK)
        token_start = window_start
        hit_boundary = True  # assume we hit boundary unless whitespace found
        for idx in range(match_start - 1, window_start - 1, -1):
            if text[idx] in " \t\n\r":
                token_start = idx + 1
                hit_boundary = False
                break

        # If the lookback window ran out without finding whitespace, the path
        # may be inside a very long URL in minified content. Conservatively
        # treat it as a URL to avoid corrupting real URLs.
        if hit_boundary and window_start > 0:
            return True

        token = text[token_start:match_start + 4]  # include a few chars past match
        tl = token.lower()

        # Check for scheme://
        for scheme in _URL_SCHEMES:
            if (scheme + "://") in tl:
                return True

        # Check for bare domain immediately before the match within the same token
        if _BARE_DOMAIN_RE.search(token):
            return True

        return False

    def detect(self, text: str, language: str = "") -> list[PiiEntity]:
        if not text:
            return []

        entities: list[PiiEntity] = []

        for path_match in _PATH_RE.finditer(text):
            path_str = path_match.group()
            path_start = path_match.start()

            # Skip paths that are part of a URL
            if self._is_url_context(text, path_start):
                continue

            # Find all non-separator segments within the matched path
            segments = list(_SEGMENT_RE.finditer(path_str))

            # Skip short paths (e.g. C:\Users or /home/alice)
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
