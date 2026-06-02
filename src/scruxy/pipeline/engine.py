"""Pipeline engine — stateless orchestrator that chains detection stages sequentially.

Each stage's detections are replaced with placeholders before the next stage
runs, so earlier (higher-priority) stages claim spans and later stages cannot
re-detect them.  Known PII from the global token map is also replaced with
placeholders first, preventing tokens (especially non-REDACTED formats like
UUIDs) from being re-detected by subsequent plugins.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from scruxy.pipeline.merger import merge_and_deduplicate
from scruxy.pipeline.models import PiiEntity, PipelineContext, PipelineResult
from scruxy.plugin.base import PiiEntity as BasePiiEntity

logger = logging.getLogger(__name__)

# Placeholder format: §§§SCRX0001§§§
# Uses § (section sign) which won't appear in PII patterns, emails, names,
# phone numbers, SSNs, or any other detectable entity type.
_PH_PREFIX = "§§§SCRX"
_PH_SUFFIX = "§§§"


def _make_placeholder(n: int) -> str:
    return f"{_PH_PREFIX}{n:04d}{_PH_SUFFIX}"


# M4 fix: ``\d`` in default mode matches Unicode digits (Devanagari,
# Arabic-Indic, etc.) — an attacker can craft a "fake placeholder"
# using non-ASCII digits like ``§§§SCRX०००१§§§`` (Devanagari for
# 0001) that satisfies the regex but doesn't correspond to a real
# token in ``_PH_RANGE_RE.finditer``.  The R70-1 overlap protection
# would then SKIP the attacker-supplied span as if it were a real
# placeholder, allowing the substring inside to bypass scrubbing.
# Restrict to ASCII 0-9 only.
_PH_RANGE_RE = re.compile(re.escape(_PH_PREFIX) + r"[0-9]+" + re.escape(_PH_SUFFIX))


def _is_placeholder(text: str) -> bool:
    """R71-8 fix: strict regex match instead of loose
    ``startswith/endswith``.  The loose form returned True for
    over-broad spans like ``§§§SCRX0001§§§ extra text §§§SCRX0002§§§``
    that contain TWO real placeholders separated by other text — a
    span the cleaning loop would then *skip* as if it were a single
    placeholder, leaking the real text between them.  Symmetric to
    R70-1 (placeholder integrity in pre-filter)."""
    return _PH_RANGE_RE.fullmatch(text) is not None


def _placeholder_ranges(text: str) -> list[tuple[int, int]]:
    """R70-1 fix: return ``[(start, end), ...]`` of every placeholder
    span currently in ``text``.  The pre-filter substring loop (and
    its regex sibling) must skip any PII match that overlaps a
    placeholder range, otherwise short PII whose text is a substring
    of ``"SCRX"`` (e.g. ``"SC"``, ``"CR"``, ``"RX"``) destroys
    previously-emitted placeholders → orphan fragments → PII token
    can no longer be deanonymized on the response path.
    """
    return [(m.start(), m.end()) for m in _PH_RANGE_RE.finditer(text)]


def _overlaps_placeholder(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
    """O(N) overlap check; N is small (placeholder count per text)."""
    for ps, pe in ranges:
        if start < pe and end > ps:
            return True
    return False


# Characters to strip from PII span edges.  These stay in the scrubbed
# text (sent to the model) — only the clean PII portion is replaced.
_STRIP_CHARS = "\r\n\t\x0b\x0c\x00"
# Regex splitting on internal newlines/carriage-returns for multi-part PII
_SPLIT_RE = re.compile(r"[\r\n]+")


def _clean_pii_span(
    raw_text: str,
    start: int,
    end: int,
) -> list[tuple[str, int, int]]:
    """Clean a detected PII span, returning sub-spans with adjusted offsets.

    1. Strip leading/trailing control characters (\\r, \\n, \\t, etc.)
       from the span — the stripped chars stay in the original text.
    2. Split on internal newlines into separate sub-spans so each gets
       its own token.
    3. Skip empty or single-char fragments.

    Returns a list of ``(clean_text, adjusted_start, adjusted_end)`` tuples.
    """
    # Strip leading control chars
    lstrip_count = 0
    while lstrip_count < len(raw_text) and raw_text[lstrip_count] in _STRIP_CHARS:
        lstrip_count += 1
    # Strip trailing control chars
    rstrip_count = 0
    while rstrip_count < len(raw_text) and raw_text[-(rstrip_count + 1)] in _STRIP_CHARS:
        rstrip_count += 1

    if lstrip_count + rstrip_count >= len(raw_text):
        return []  # All control chars

    trimmed = raw_text[lstrip_count:len(raw_text) - rstrip_count if rstrip_count else len(raw_text)]
    base_start = start + lstrip_count

    # Split on internal newlines
    parts = _SPLIT_RE.split(trimmed)
    if len(parts) <= 1:
        # No internal newlines — single span
        clean = trimmed.strip()
        if len(clean) < 2:
            return []
        # Find the clean portion within trimmed (handles leading/trailing spaces)
        inner_offset = trimmed.index(clean) if clean in trimmed else 0
        return [(clean, base_start + inner_offset, base_start + inner_offset + len(clean))]

    # Multiple parts — emit each non-trivial fragment
    result: list[tuple[str, int, int]] = []
    offset = base_start
    for part in parts:
        clean = part.strip()
        if len(clean) >= 2:
            inner_offset = part.index(clean) if clean in part else 0
            frag_start = offset + inner_offset
            result.append((clean, frag_start, frag_start + len(clean)))
        # Advance offset past this part + the delimiter that was split on
        # We need to find the actual position in the original trimmed text
        idx = trimmed.find(part, offset - base_start)
        if idx >= 0:
            offset = base_start + idx + len(part)
            # Skip past the newline delimiter(s) — count actual chars
            while offset - start < len(raw_text) and raw_text[offset - start] in "\r\n":
                offset += 1
        else:
            # Fallback: advance past part + scan for delimiter length
            offset += len(part)
            while offset - start < len(raw_text) and raw_text[offset - start] in "\r\n":
                offset += 1

    return result


@dataclass
class PreFilterMatch:
    """A PII match found by the pre-filter (not a PiiEntity — no offsets)."""
    pii_text: str
    token: str
    entity_type: str


@dataclass
class _PlaceholderEntry:
    """Internal record mapping a placeholder to its detected PII."""
    placeholder: str
    pii_text: str
    entity_type: str
    score: float
    source: str
    use_word_boundary: bool = False
    case_sensitive: bool = True
    exclude_from_prefilter: bool = False


# ---------------------------------------------------------------------------
# Pipeline engine
# ---------------------------------------------------------------------------

class PipelineEngine:
    """Stateless orchestrator running detection stages sequentially with placeholder masking.

    Stages run in config order (first = highest priority).  Each stage's
    detections are replaced with opaque placeholders before the next stage
    sees the text, so earlier stages "claim" spans that later stages cannot
    re-detect.  After all stages complete, placeholders are resolved to
    final tokens via ``token_map.get_or_create_token``.
    """

    def __init__(self, stages: list[Any] | None = None) -> None:
        self.stages: list[Any] = stages or []
        self.pre_filter_enabled: bool = True

    async def scrub_text(
        self,
        text: str,
        token_map: Any,
        context: PipelineContext | None = None,
        request_id: str = "",
    ) -> PipelineResult:
        """Run *text* through all enabled stages sequentially, then resolve placeholders."""
        start_time = time.perf_counter()

        # Fast path: empty / whitespace-only text
        if not text or not text.strip():
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return PipelineResult(entities=[], scrubbed_text=text, latency_ms=elapsed_ms)

        language = context.language if context else "en"

        # Placeholder counter and registry
        ph_counter = 0
        ph_entries: list[_PlaceholderEntry] = []
        pre_matches: list[PreFilterMatch] = []

        # Per-stage timing breakdown
        stage_timings: list[dict] = []

        # -- Step 0: Pre-filter known PII → placeholders --
        working_text = text
        if self.pre_filter_enabled:
            _pf_start = time.perf_counter()
            working_text, pre_matches, ph_counter = self._pre_filter_to_placeholders(
                working_text, token_map, ph_counter, ph_entries,
            )
            _pf_ms = (time.perf_counter() - _pf_start) * 1000
            stage_timings.append({"stage": "pre_filter", "ms": round(_pf_ms, 2), "entities": len(pre_matches)})

        # -- Step 1: Run each stage sequentially --
        for stage in self.stages:
            if not getattr(stage, "enabled", True):
                logger.debug("Skipping disabled stage %s", type(stage).__name__)
                continue

            stage_name = getattr(stage, "name", type(stage).__name__)
            _stage_start = time.perf_counter()
            try:
                stage_entities = await self._call_stage(stage, working_text, language)
            except Exception:
                logger.exception(
                    "Stage %s raised an exception — skipping its results",
                    type(stage).__name__,
                )
                _stage_ms = (time.perf_counter() - _stage_start) * 1000
                stage_timings.append({"stage": stage_name, "ms": round(_stage_ms, 2), "entities": 0, "error": True})
                continue
            _stage_ms = (time.perf_counter() - _stage_start) * 1000
            stage_timings.append({"stage": stage_name, "ms": round(_stage_ms, 2), "entities": len(stage_entities) if stage_entities else 0})

            if not stage_entities:
                continue

            # Resolve per-plugin defaults for word_boundary / case_sensitive
            stage_wb = getattr(stage, "use_word_boundary", False)
            stage_cs = getattr(stage, "case_sensitive", True)
            stage_excl = getattr(stage, "exclude_from_prefilter", False)

            # Merge/dedup within this stage's detections
            merged = merge_and_deduplicate(stage_entities)

            # Replace detected spans with placeholders (right-to-left)
            sorted_entities = sorted(merged, key=lambda e: e.start, reverse=True)
            for entity in sorted_entities:
                pii_text = working_text[entity.start:entity.end]

                # Skip if this span is already a placeholder
                if _is_placeholder(pii_text):
                    continue

                # Skip if span contains an embedded placeholder marker
                if _PH_PREFIX in pii_text:
                    continue

                # Clean PII: strip edge control chars, split on internal newlines.
                # Each sub-span gets its own placeholder; whitespace stays in text.
                sub_spans = _clean_pii_span(pii_text, entity.start, entity.end)
                if not sub_spans:
                    continue

                # Entity-level flags override stage defaults
                ent_wb = getattr(entity, "use_word_boundary", stage_wb)
                ent_cs = getattr(entity, "case_sensitive", stage_cs)

                # Process sub-spans right-to-left to preserve offsets
                for clean_text, adj_start, adj_end in reversed(sub_spans):
                    ph = _make_placeholder(ph_counter)
                    ph_counter += 1

                    ph_entries.append(_PlaceholderEntry(
                        placeholder=ph,
                        pii_text=clean_text,
                        entity_type=entity.entity_type,
                        score=entity.score,
                        source=entity.source,
                        use_word_boundary=ent_wb,
                        case_sensitive=ent_cs,
                        exclude_from_prefilter=stage_excl,
                    ))
                    working_text = working_text[:adj_start] + ph + working_text[adj_end:]

        # -- Step 2: Resolve all placeholders → actual tokens --
        scrubbed = working_text
        all_entities: list[BasePiiEntity] = []
        # Parallel list of (pii_text, token) for display — same index as all_entities
        detected_pii: list[tuple[str, str]] = []
        seen_pii: set[str] = set()  # deduplicate display entries

        for entry in ph_entries:
            token_args = dict(
                pii=entry.pii_text,
                entity_type=entry.entity_type,
                source=entry.source,
                use_word_boundary=entry.use_word_boundary,
                case_sensitive=entry.case_sensitive,
                exclude_from_prefilter=entry.exclude_from_prefilter,
                request_id=request_id,
            )
            # Always resolve tokens in a worker thread so the event loop never
            # contends on TokenMap's cross-thread lock while a blocking strategy
            # (for example ScriptReplacement subprocesses) is running.
            token = await asyncio.to_thread(
                token_map.get_or_create_token,
                **token_args,
            )
            if token is None:
                # Fail closed: use a default redaction token instead of
                # re-inserting raw PII (which would leak to upstream).
                fallback_token = f"REDACTED_{entry.entity_type}_FALLBACK"
                logger.warning(
                    "Token generation returned None for PII type %s — using fallback token",
                    entry.entity_type,
                )
                scrubbed = scrubbed.replace(entry.placeholder, fallback_token)
                continue

            scrubbed = scrubbed.replace(entry.placeholder, token)

            # Deduplicate: same PII text appearing multiple times
            if entry.pii_text in seen_pii:
                continue
            seen_pii.add(entry.pii_text)

            all_entities.append(BasePiiEntity(
                entity_type=entry.entity_type,
                start=0,
                end=len(entry.pii_text),
                score=entry.score,
                source=entry.source,
            ))
            detected_pii.append((entry.pii_text, token))

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Log per-stage breakdown at info level for visibility
        timing_str = " | ".join(
            f"{t['stage']}: {t['ms']:.1f}ms ({t['entities']})"
            for t in stage_timings
        )
        logger.info(
            "Pipeline: %d entities (%d pre-filtered), %.1fms total [%s]",
            len(all_entities),
            len(pre_matches),
            elapsed_ms,
            timing_str,
        )

        result = PipelineResult(
            entities=all_entities,
            scrubbed_text=scrubbed,
            latency_ms=elapsed_ms,
        )
        result.pre_filter_matches = pre_matches  # type: ignore[attr-defined]
        result.detected_pii = detected_pii  # type: ignore[attr-defined]
        result.stage_timings = stage_timings  # type: ignore[attr-defined]
        return result

    # ------------------------------------------------------------------
    # Pre-filter: replace known PII with placeholders
    # ------------------------------------------------------------------

    @staticmethod
    def _pre_filter_to_placeholders(
        text: str,
        token_map: Any,
        ph_counter: int,
        ph_entries: list[_PlaceholderEntry],
    ) -> tuple[str, list[PreFilterMatch], int]:
        """Replace known PII from the global token map with placeholders.

        Respects per-token metadata:
        - ``exclude_from_prefilter``: skip this token entirely
        - ``use_word_boundary``: use ``\\b`` regex matching instead of
          substring search (e.g. "repo" won't match "repositories")
        - ``case_sensitive``: when False, match case-insensitively

        Returns ``(placeholder_text, pre_filter_matches, updated_counter)``.
        """
        scrub_map: dict[str, str] = getattr(token_map, "scrub_map", {})
        if not scrub_map:
            return text, [], ph_counter

        token_meta: dict[str, dict] = getattr(token_map, "token_meta", {})

        # Sort by PII length descending so longer strings replace first
        sorted_pii = sorted(scrub_map.keys(), key=len, reverse=True)

        matches: list[PreFilterMatch] = []
        result = text
        for pii in sorted_pii:
            # R67-3 fix: defense-in-depth empty-PII guard (mirrors
            # `request_scrubber.py:_second_pass`).  An empty key in
            # ``scrub_map`` would infinite-loop both the regex
            # ``pattern.search`` and the substring ``in result``
            # paths because zero-width matches don't advance the
            # cursor.  Upstream ``token_map.register`` rejects
            # empty PII but DB corruption / custom strategies could
            # still slip one in.
            if not pii:
                continue
            meta = token_meta.get(pii, {})

            # Skip tokens excluded from pre-filter
            if meta.get("exclude_from_prefilter", False):
                continue

            use_wb = meta.get("word_boundary", False)
            case_sensitive = meta.get("case_sensitive", True)

            token = scrub_map[pii]
            get_et = getattr(token_map, "get_entity_type", None)
            et = get_et(pii) if get_et else _extract_entity_type(token)

            if use_wb or not case_sensitive:
                # Use regex matching for word boundaries and/or case insensitivity.
                # R64-2 fix: use the third-party ``regex`` library with
                # ``IGNORECASE | FULLCASE`` for case-insensitive matching
                # so Unicode full-case equivalents (``straße`` ↔ ``STRASSE``)
                # are caught.  Mirrors the body second-pass behavior in
                # ``RequestScrubber``.  Falls back to stdlib ``re`` on
                # ``regex`` import failure.
                pattern_str = re.escape(pii)
                if use_wb:
                    pattern_str = r"\b" + pattern_str + r"\b"
                pattern = None
                if not case_sensitive:
                    try:
                        import regex as _regex_lib
                        pattern = _regex_lib.compile(
                            pattern_str,
                            _regex_lib.IGNORECASE | _regex_lib.FULLCASE,
                        )
                    except (ImportError, Exception):
                        pattern = None
                if pattern is None:
                    flags = 0 if case_sensitive else re.IGNORECASE
                    try:
                        pattern = re.compile(pattern_str, flags)
                    except re.error:
                        # Fallback to plain matching on regex compilation errors
                        pattern = None

                if pattern is not None:
                    found_any = False
                    # R66-4 fix: O(N) sweep using ``search(result, start)``.
                    # R67-8 fix: store the CANONICAL ``pii`` (from the
                    # token map) as ``pii_text``, NOT ``m.group()``.
                    # R70-1 fix: skip any match overlapping an existing
                    # placeholder span.  Otherwise a short PII whose
                    # casefold form sits inside ``§§§SCRX0001§§§``
                    # would corrupt the placeholder.
                    parts: list[str] = []
                    search_start = 0
                    ph_ranges = _placeholder_ranges(result)
                    while True:
                        m = pattern.search(result, search_start)
                        if m is None:
                            parts.append(result[search_start:])
                            break
                        if _overlaps_placeholder(m.start(), m.end(), ph_ranges):
                            parts.append(result[search_start:m.end()])
                            search_start = m.end()
                            continue
                        found_any = True
                        ph = _make_placeholder(ph_counter)
                        ph_counter += 1
                        ph_entries.append(_PlaceholderEntry(
                            placeholder=ph,
                            pii_text=pii,
                            entity_type=et,
                            score=1.0,
                            source="pre_filter",
                        ))
                        parts.append(result[search_start:m.start()])
                        parts.append(ph)
                        # The just-inserted placeholder shifts indices,
                        # but ``search_start`` is into ``result``
                        # (pre-rewrite), so we keep iterating on the
                        # original.  ph_ranges is also pre-rewrite.
                        search_start = m.end()
                    if found_any:
                        result = "".join(parts)
                        matches.append(PreFilterMatch(
                            pii_text=pii, token=token, entity_type=et,
                        ))
                    continue

            # Plain substring matching (original behavior)
            if pii not in result:
                continue

            # R70-1 fix: skip matches inside placeholder spans.
            ph_ranges = _placeholder_ranges(result)
            search_start = 0
            replaced_any = False
            while True:
                idx = result.find(pii, search_start)
                if idx < 0:
                    break
                pii_end = idx + len(pii)
                if _overlaps_placeholder(idx, pii_end, ph_ranges):
                    search_start = pii_end
                    continue
                ph = _make_placeholder(ph_counter)
                ph_counter += 1
                ph_entries.append(_PlaceholderEntry(
                    placeholder=ph,
                    pii_text=pii,
                    entity_type=et,
                    score=1.0,
                    source="pre_filter",
                ))
                result = result[:idx] + ph + result[pii_end:]
                # The text just got longer/shorter — recompute ranges
                # before the next iteration so we keep skipping
                # placeholders correctly.
                ph_ranges = _placeholder_ranges(result)
                search_start = idx + len(ph)
                replaced_any = True

            if replaced_any:
                matches.append(PreFilterMatch(
                    pii_text=pii,
                    token=token,
                    entity_type=et,
                ))

        return result, matches, ph_counter

    # ------------------------------------------------------------------
    # Stage invocation
    # ------------------------------------------------------------------

    @staticmethod
    async def _call_stage(
        stage: Any, text: str, language: str,
    ) -> list[PiiEntity]:
        """Call a stage's detect method, handling sync/async results."""
        detect_fn = stage.detect
        if asyncio.iscoroutinefunction(detect_fn):
            return await detect_fn(text, language)
        return await asyncio.to_thread(detect_fn, text, language)


def _extract_entity_type(token: str) -> str:
    """Extract the entity type from a token like ``REDACTED_PERSON_1``."""
    parts = token.split("_")
    if len(parts) >= 3 and parts[0] == "REDACTED":
        return "_".join(parts[1:-1])
    return "UNKNOWN"
