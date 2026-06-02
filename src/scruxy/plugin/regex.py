"""Regex-based PII detection plugin with context-aware score boosting."""
from __future__ import annotations

import logging
import re
import threading

import yaml

from scruxy.plugin.base import ConfigField, DetectorPlugin, PiiEntity


logger = logging.getLogger(__name__)

# Try to import the third-party ``regex`` module which supports a true
# hard-interrupt timeout (``finditer(string, timeout=...)``).  Stdlib
# ``re`` cannot be interrupted from Python code, so a single
# catastrophic backtrack would otherwise stall the pipeline thread for
# an unbounded duration before the post-finditer time budget can react.
# We fall back to ``re`` if the optional dependency isn't installed.
try:
    import regex as _regex_engine
    _HAS_REGEX_LIB = True
except ImportError:  # pragma: no cover — covered via package install
    _regex_engine = None  # type: ignore[assignment]
    _HAS_REGEX_LIB = False


# Number of characters around a match to search for context words.
_CONTEXT_WINDOW = 50

# Maximum score after context boosting.
_MAX_SCORE = 1.0

# Score boost applied when a context word is found near a match.
_CONTEXT_BOOST = 0.1

# Per-pattern execution time budget (seconds).  Two purposes:
#   * When the ``regex`` library is available it is passed as the hard
#     ``timeout=`` argument to ``finditer``, killing the regex engine
#     mid-backtrack if it exceeds the budget.
#   * When the stdlib ``re`` module is the engine, the budget is
#     enforced *post-hoc* via ``perf_counter`` — a slow run still
#     consumes wall time but is detected and counted toward the
#     auto-disable streak below.
_PATTERN_TIME_BUDGET_S = 0.250

# After this many cumulative slow runs a pattern is permanently
# disabled for the lifetime of the plugin instance.
_PATTERN_SLOW_DISABLE_THRESHOLD = 3
# R66-2 fix: cooldown duration (seconds) when a pattern hits the
# slow-run threshold.  Transient instead of permanent so an attacker
# can't permanently disable a custom PII pattern by triggering 3
# consecutive slow inputs.  10 minutes is long enough to amortize
# the cost of a truly broken pattern over many requests, short
# enough that legitimate operators don't lose detection for hours.
_PATTERN_COOLDOWN_S = 600.0

# Heuristic patterns that flag obvious catastrophic-backtracking
# constructs in user-supplied regexes.  These do not catch every
# pathological pattern, but they reject the common textbook cases
# (``(a+)+``, ``(a*)*``, ``(a|a)+``, ``(.*)*``, ``(a|aa)+``) that an
# inattentive author or attacker is most likely to write.
_REDOS_HEURISTICS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Nested quantifier: (...+)+, (...*)*, (...+)*, (...*)+, (...{m,n})+
    (re.compile(r"\([^)]*[+*?][^)]*\)\s*[+*?{]"), "nested quantifier"),
    # Quantifier on a group whose body is .* or .+ (e.g. (.*)+ )
    (re.compile(r"\(\s*\.[+*]\s*\)\s*[+*?{]"), "(.{*+}) group with outer quantifier"),
    # Alternation of identical alternatives followed by a quantifier:
    # (a|a)+ — a common ReDoS construct.
    (re.compile(r"\(([^)|]+)\|\1\)\s*[+*?{]"), "duplicate alternation with quantifier"),
    # Alternation of OVERLAPPING alternatives followed by a quantifier
    # — e.g. ``(a|aa)+`` or ``(\d|\d\d)+`` where one alternative is a
    # prefix of another.  This is the classic ReDoS shape that does
    # not have a duplicate but still triggers exponential
    # backtracking on failing inputs.
    (
        re.compile(r"\(([^)|]+)\|(\1)[^)]*\)\s*[+*?{]"),
        "alternation with prefix overlap and quantifier",
    ),
    # Quantified group whose body contains an alternation of *any* two
    # alternates that are not strict literals (covers `(a+|b)+`,
    # `(\w|\d)+`, etc.).  This is broad and may produce false
    # positives on legitimate patterns; users who need such patterns
    # can rewrite them as non-quantified character classes
    # (e.g. `[ab]+` instead of `(a|b)+`).
    (
        re.compile(r"\([^)]*[+*?{][^)]*\|[^)]*\)\s*[+*?{]|\([^)]*\|[^)]*[+*?{][^)]*\)\s*[+*?{]"),
        "alternation containing nested quantifier",
    ),
)


def _looks_catastrophic(pattern: str) -> str | None:
    """Return a human-readable reason if *pattern* looks ReDoS-prone."""
    for rx, reason in _REDOS_HEURISTICS:
        if rx.search(pattern):
            return reason
    return None


class _CompiledPattern:
    """Internal holder for a compiled regex pattern and its metadata."""

    __slots__ = ("name", "entity_type", "regex", "score", "context_words",
                 "word_boundary", "case_sensitive", "_slow_runs",
                 "_disabled", "_disabled_until", "_state_lock")

    def __init__(
        self,
        name: str,
        entity_type: str,
        regex: re.Pattern[str],
        score: float,
        context_words: list[str],
        word_boundary: bool = False,
        case_sensitive: bool = True,
    ) -> None:
        self.name = name
        self.entity_type = entity_type
        self.regex = regex
        self.score = score
        self.context_words = context_words
        self.word_boundary = word_boundary
        self.case_sensitive = case_sensitive
        # Runtime ReDoS guard state.
        self._slow_runs: int = 0
        self._disabled: bool = False
        # R66-2 fix: ``_disabled_until`` is a monotonic timestamp
        # for transient cooldown.  When a pattern hits the slow-run
        # threshold we set this instead of the permanent
        # ``_disabled`` flag, so an attacker can't permanently
        # disable a pattern by triggering 3 consecutive slow inputs.
        # The hard ``regex.timeout=`` already bounds per-query CPU,
        # so the cooldown only needs to back off long enough to
        # avoid wasting work on a momentarily-slow pattern.
        self._disabled_until: float = 0.0
        # R68-4 fix: lock for compound RMW on `_slow_runs` so
        # concurrent ``detect()`` calls from the asyncio thread pool
        # don't lose increments and delay cooldown trigger.
        self._state_lock = threading.Lock()


class RegexPlugin(DetectorPlugin):
    """PII detection plugin using user-defined regular expression patterns.

    Each pattern specifies a regex, an entity type, a base confidence score, and
    optional context words that boost the score when they appear near a match.
    """

    name = "regex"
    plugin_type = "builtin"
    version = "built-in"
    description = "Custom regex pattern matching for domain-specific PII detection."
    enabled = True

    config_schema = [
        ConfigField(
            name="patterns_file",
            field_type="file",
            default="~/.scruxy/regex_patterns.yaml",
            description="Path to YAML file containing regex patterns",
            label="Patterns File",
            details="YAML file with regex_patterns list. Click Edit File to modify patterns.",
        ),
    ]

    def setup(self, config: dict) -> None:
        """Perform one-time initialisation using the provided config dict.

        Reads patterns from a YAML file (via ``patterns_file``), inline YAML
        (via ``patterns_yaml``), and/or a ``patterns`` list in the config dict.
        Sources are merged in order: file, inline YAML, raw patterns list.

        Args:
            config: Configuration dictionary with optional keys:
                ``patterns_file`` (str), ``patterns_yaml`` (str),
                and/or ``patterns`` (list[dict]).
        """
        patterns: list[dict] = []

        # Load from YAML file if specified
        patterns_file = config.get("patterns_file", "")
        if patterns_file:
            from pathlib import Path

            pf = Path(patterns_file).expanduser()
            if pf.exists():
                with open(pf) as f:
                    data = yaml.safe_load(f) or {}
                if isinstance(data, dict):
                    raw_patterns = data.get("regex_patterns", [])
                    if isinstance(raw_patterns, list):
                        patterns = raw_patterns
                    else:
                        logger.warning("regex_patterns in %s is not a list — ignoring", pf)
                else:
                    logger.warning("Patterns file %s is not a YAML mapping — ignoring", pf)

        # Load from inline YAML text if specified
        patterns_yaml = config.get("patterns_yaml", "")
        if patterns_yaml and isinstance(patterns_yaml, str):
            try:
                inline_data = yaml.safe_load(patterns_yaml)
                if isinstance(inline_data, dict):
                    inline_patterns = inline_data.get("regex_patterns", [])
                    if isinstance(inline_patterns, list):
                        patterns.extend(inline_patterns)
            except yaml.YAMLError as exc:
                logger.warning("Skipping invalid inline patterns_yaml: %s", exc)

        # Also accept raw patterns list in config for backward compat
        patterns.extend(config.get("patterns", []))

        self._compile_patterns(patterns)

    def _compile_patterns(self, patterns: list[dict]) -> None:
        """Compile raw pattern dicts into _CompiledPattern instances.

        Args:
            patterns: List of pattern dicts, each with keys:
                - name (str): Human-readable pattern name.
                - entity_type (str): PII category (e.g. "EMAIL_ADDRESS").
                - pattern (str): Regular expression string.
                - score (float): Base confidence score for matches.
                - context_words (list[str], optional): Words that boost score
                  when found within 50 chars of the match.
                - word_boundary (bool, optional): Use \\b word boundaries in
                  pre-filter matching for this pattern's entities.
                - case_sensitive (bool, optional): Case-sensitive matching.
        """
        self._patterns: list[_CompiledPattern] = []
        _REQUIRED_KEYS = ("name", "entity_type", "pattern", "score")
        for pat in patterns:
            # B11: validate entry shape before indexing.  A malformed
            # YAML entry missing a required key would otherwise raise
            # KeyError on startup and prevent Scruxy from booting.
            if not isinstance(pat, dict):
                logger.warning(
                    "Skipping non-dict pattern entry: %r", pat,
                )
                continue
            missing = [k for k in _REQUIRED_KEYS if k not in pat]
            if missing:
                logger.warning(
                    "Skipping pattern %r: missing required keys %s",
                    pat.get("name", "<unknown>"), missing,
                )
                continue
            try:
                _ = float(pat["score"])
            except (TypeError, ValueError):
                logger.warning(
                    "Skipping pattern %r: 'score' must be numeric, got %r",
                    pat.get("name", "<unknown>"), pat.get("score"),
                )
                continue
            pattern_str = pat["pattern"]
            if not isinstance(pattern_str, str) or not pattern_str:
                logger.warning(
                    "Skipping pattern %r: 'pattern' must be a non-empty string",
                    pat.get("name", "<unknown>"),
                )
                continue
            pat_cs = pat.get("case_sensitive", True)
            pat_wb = pat.get("word_boundary", False)

            # Apply word boundary wrapping if requested and not already present
            if pat_wb and not pattern_str.startswith(r"\b"):
                pattern_str = r"\b(?:" + pattern_str + r")\b"

            flags = 0 if pat_cs else re.IGNORECASE
            redos_reason = _looks_catastrophic(pattern_str)
            if redos_reason is not None:
                logger.warning(
                    "Skipping pattern %r: looks ReDoS-prone (%s); pattern=%r",
                    pat.get("name", "<unknown>"), redos_reason, pattern_str,
                )
                continue
            try:
                # Prefer the third-party ``regex`` engine when available
                # so we get a hard ``timeout=`` interrupt at run time.
                if _HAS_REGEX_LIB:
                    # R65-1 fix: include FULLCASE so Unicode full-case
                    # equivalents (``straße`` ↔ ``STRASSE``) match
                    # under ``case_sensitive=False``.  Mirrors the
                    # R64-2 fix in the engine pre-filter.
                    rgx_flags = 0
                    if not pat_cs:
                        rgx_flags = (
                            _regex_engine.IGNORECASE  # type: ignore[union-attr]
                            | _regex_engine.FULLCASE  # type: ignore[union-attr]
                        )
                    compiled = _regex_engine.compile(pattern_str, rgx_flags)  # type: ignore[union-attr]
                else:
                    compiled = re.compile(pattern_str, flags)
            except (re.error, Exception) as exc:
                # ``regex`` raises ``regex.error`` (a subclass of Exception)
                # for invalid patterns; we accept either.
                logger.warning(
                    "Skipping invalid regex pattern %r: %s", pat.get("name", "<unknown>"), exc
                )
                continue

            self._patterns.append(
                _CompiledPattern(
                    name=pat["name"],
                    entity_type=pat["entity_type"],
                    regex=compiled,
                    score=pat["score"],
                    context_words=pat.get("context_words", []),
                    word_boundary=pat_wb,
                    case_sensitive=pat_cs,
                )
            )

        logger.info("RegexPlugin initialized with %d compiled patterns", len(self._patterns))

    def detect(self, text: str, language: str = "") -> list[PiiEntity]:
        """Detect PII entities in text using compiled regex patterns.

        For each pattern, all non-overlapping matches are found. If the pattern
        specifies context_words and any of those words appear within 50 characters
        of the match, the score is boosted by 0.1 (capped at 1.0).

        Args:
            text: The input text to scan for PII patterns.
            language: Language code (unused by regex stage but accepted
                for DetectorPlugin interface compatibility).

        Returns:
            A list of PiiEntity instances representing detected matches.
        """
        if not text:
            return []

        text_lower = text.lower()
        entities: list[PiiEntity] = []

        import time as _time_mod
        for pattern in self._patterns:
            # R66-2 fix: check transient cooldown (preferred) AND
            # legacy permanent ``_disabled`` flag (back-compat for
            # any external code that sets it directly).
            if pattern._disabled:
                continue
            if pattern._disabled_until and _time_mod.monotonic() < pattern._disabled_until:
                continue
            _t0 = _time_mod.perf_counter()
            timed_out = False
            try:
                if _HAS_REGEX_LIB:
                    # ``regex.finditer`` accepts a ``timeout`` kwarg
                    # that hard-interrupts the engine mid-backtrack.
                    # The engine raises ``regex.TimeoutError`` once the
                    # budget elapses — caught below and treated as a
                    # slow run for the auto-disable counter.
                    matches = list(
                        pattern.regex.finditer(text, timeout=_PATTERN_TIME_BUDGET_S)
                    )
                else:
                    matches = list(pattern.regex.finditer(text))
            except TimeoutError as exc:
                # Hard interrupt from the ``regex`` engine after the
                # configured budget elapsed.  Treat as a slow run.
                timed_out = True
                logger.warning(
                    "Pattern %r hit hard %.3fs regex timeout — counted as a slow run",
                    pattern.name, _PATTERN_TIME_BUDGET_S,
                )
                matches = []
            except Exception as exc:
                # R67-1 fix: a non-timeout exception (MemoryError,
                # internal regex fault, etc.) is also a "the pattern
                # produced no output" event — treat it the same as
                # a timeout for slow-run accounting so a permanently-
                # broken pattern still trips the cooldown rather
                # than silently dropping every detection (fail-OPEN).
                logger.warning(
                    "Pattern %r raised %s — counted as a slow run",
                    pattern.name, exc,
                )
                timed_out = True
                matches = []
            elapsed = _time_mod.perf_counter() - _t0
            if timed_out or elapsed > _PATTERN_TIME_BUDGET_S:
                # R68-4 fix: protect compound RMW + threshold check
                # under the per-pattern state lock so concurrent
                # detect() calls don't lose updates.
                with pattern._state_lock:
                    pattern._slow_runs += 1
                    slow_runs_now = pattern._slow_runs
                    threshold_hit = slow_runs_now >= _PATTERN_SLOW_DISABLE_THRESHOLD
                    if threshold_hit:
                        # R66-2 fix: TRANSIENT cooldown rather than
                        # permanent disable.  An attacker who triggers
                        # the threshold once gets 10 minutes off; the
                        # pattern auto-recovers and the slow-run counter
                        # resets so a truly broken pattern only re-
                        # disables if it's slow on REAL traffic again.
                        pattern._disabled_until = _time_mod.monotonic() + _PATTERN_COOLDOWN_S
                        pattern._slow_runs = 0
                logger.warning(
                    "Pattern %r took %.3fs on text of length %d (slow run %d/%d)",
                    pattern.name, elapsed, len(text),
                    slow_runs_now, _PATTERN_SLOW_DISABLE_THRESHOLD,
                )
                if threshold_hit:
                    logger.error(
                        "Pattern %r temporarily disabled for %.0fs after %d consecutive slow runs "
                        "(likely ReDoS); will retry automatically. Edit "
                        "~/.scruxy/regex_patterns.yaml to fix permanently.",
                        pattern.name, _PATTERN_COOLDOWN_S,
                        _PATTERN_SLOW_DISABLE_THRESHOLD,
                    )
            else:
                # R65-2 fix: reset the consecutive-slow-run counter
                # on every successful fast run.  Without this, an
                # attacker who triggers 3 slow inputs OVER THE
                # LIFETIME OF THE PROCESS could permanently disable
                # the pattern — fail-OPEN: subsequent PII the
                # pattern would have caught is forwarded raw.  The
                # hard ``timeout=`` interrupt above already prevents
                # per-query CPU exhaustion, so the auto-disable
                # only needs to catch a truly-broken pattern (which
                # would be slow on EVERY input, hence consecutive).
                # R68-4 fix: under lock for thread safety.
                with pattern._state_lock:
                    pattern._slow_runs = 0

            for match in matches:
                # Skip matches that overlap pipeline placeholder markers
                matched_text = match.group()
                if "§§§SCRX" in matched_text:
                    continue

                score = pattern.score

                if pattern.context_words:
                    score = self._apply_context_boost(
                        text_lower, match.start(), match.end(), score, pattern.context_words
                    )

                entities.append(
                    PiiEntity(
                        entity_type=pattern.entity_type,
                        start=match.start(),
                        end=match.end(),
                        score=score,
                        source="regex",
                        use_word_boundary=pattern.word_boundary,
                        case_sensitive=pattern.case_sensitive,
                    )
                )

        logger.debug("Regex detected %d entities in text of length %d", len(entities), len(text))
        return entities

    @staticmethod
    def _apply_context_boost(
        text_lower: str,
        match_start: int,
        match_end: int,
        base_score: float,
        context_words: list[str],
    ) -> float:
        """Boost the score if a context word appears within the context window.

        The context window extends _CONTEXT_WINDOW characters before the match
        start and after the match end.

        Args:
            text_lower: Lowercased version of the full text.
            match_start: Start offset of the regex match.
            match_end: End offset of the regex match.
            base_score: The pattern's base confidence score.
            context_words: Words to search for in the surrounding context.

        Returns:
            The (possibly boosted) score, capped at _MAX_SCORE.
        """
        window_start = max(0, match_start - _CONTEXT_WINDOW)
        window_end = min(len(text_lower), match_end + _CONTEXT_WINDOW)
        context_region = text_lower[window_start:window_end]

        for word in context_words:
            if word.lower() in context_region:
                return min(base_score + _CONTEXT_BOOST, _MAX_SCORE)

        return base_score


# Backward-compatibility alias
RegexStage = RegexPlugin
