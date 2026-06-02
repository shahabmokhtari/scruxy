"""Scrub PII from outgoing LLM API requests."""
from __future__ import annotations

import copy
import json
import logging
from typing import Any, Protocol, runtime_checkable

from scruxy.pipeline.models import PiiEntity, PipelineResult
from scruxy.providers.base import TextField

logger = logging.getLogger(__name__)


import bisect


def _build_occupied_ranges(
    text: str, tokens: list[str],
) -> list[tuple[int, int]]:
    """Find all positions of *tokens* in *text*, returning sorted, merged ranges.

    Merges overlapping/adjacent ranges so bisect-based overlap checks are
    correct even when one token is a substring of another.
    """
    ranges: list[tuple[int, int]] = []
    for tok in tokens:
        pos = 0
        while True:
            found = text.find(tok, pos)
            if found == -1:
                break
            ranges.append((found, found + len(tok)))
            pos = found + len(tok)
    if not ranges:
        return ranges
    ranges.sort()
    # Merge overlapping/adjacent ranges
    merged: list[tuple[int, int]] = [ranges[0]]
    for start, end in ranges[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def _overlaps_any(start: int, end: int, occupied: list[tuple[int, int]]) -> bool:
    """Check if [start, end) overlaps any range in the sorted *occupied* list.

    Uses bisect for O(log n) lookup instead of linear scan.
    """
    if not occupied:
        return False
    idx = max(0, bisect.bisect_right(occupied, (start, float("inf"))) - 1)
    for i in range(idx, len(occupied)):
        occ_start, occ_end = occupied[i]
        if occ_start >= end:
            break
        if start < occ_end and end > occ_start:
            return True
    return False


@runtime_checkable
class ProviderLike(Protocol):  # pragma: no cover
    """Minimal provider interface consumed by RequestScrubber."""

    def extract_text_fields(self, body: dict) -> list[TextField]: ...
    def replace_text_fields(self, body: dict, replacements: dict[str, str]) -> dict: ...


@runtime_checkable
class PipelineLike(Protocol):  # pragma: no cover
    """Minimal pipeline interface consumed by RequestScrubber."""

    async def scrub_text(
        self, text: str, token_map: Any, context: Any | None = None,
        request_id: str = "",
    ) -> PipelineResult: ...


class RequestScrubber:
    """Scrub PII from an outbound LLM API request body.

    Orchestrates provider field extraction, pipeline PII detection /
    anonymisation, and provider field replacement to produce a scrubbed
    copy of the request body.
    """

    async def scrub_request(
        self,
        body: dict,
        provider: ProviderLike,
        pipeline: PipelineLike,
        token_map: Any,
        context: Any | None = None,
        request_id: str = "",
    ) -> tuple[dict, list[PiiEntity], list[dict], set[str]]:
        """Scrub a request body using the provider and pipeline.

        Steps
        -----
        1. ``provider.extract_text_fields(body)`` -- get extractable text.
        2. For each field, ``pipeline.scrub_text(text, token_map, context)``.
        3. Build a ``{json_path: scrubbed_text}`` replacement map.
        4. ``provider.replace_text_fields(body, replacements)`` -- apply.
        5. Return ``(scrubbed_body, all_entities, stage_timings, prefilter_reused_pii)``.

        ``prefilter_reused_pii`` is the set of raw PII strings that were
        replaced via the second-pass prefilter using tokens already present
        in the shared map (i.e. no new entity was emitted).  Callers should
        tag these for the current session so response deanonymization works.
        """
        text_fields: list[TextField] = provider.extract_text_fields(body)

        replacements: dict[str, str] = {}
        all_entities: list[PiiEntity] = []
        # Accumulate per-stage timings across all text fields.
        _stage_timings_accum: dict[str, dict] = {}

        for tf in text_fields:
            result: PipelineResult = await pipeline.scrub_text(
                tf.text_value, token_map, context, request_id=request_id,
            )
            replacements[tf.json_path] = result.scrubbed_text
            # Annotate each entity with the actual matched PII text from
            # detected_pii (which has the correct text), rather than slicing
            # from entity offsets (which may be dummy/zero-based from the engine).
            detected_pii = getattr(result, "detected_pii", [])
            for i, ent in enumerate(result.entities):
                if i < len(detected_pii):
                    ent._matched_text = detected_pii[i][0]
            all_entities.extend(result.entities)
            # Merge stage timings (sum ms and entity counts across fields)
            for st in getattr(result, "stage_timings", []):
                name = st["stage"]
                if name in _stage_timings_accum:
                    _stage_timings_accum[name]["ms"] += st["ms"]
                    _stage_timings_accum[name]["entities"] += st.get("entities", 0)
                else:
                    _stage_timings_accum[name] = {"stage": name, "ms": st["ms"], "entities": st.get("entities", 0)}

        # Second pass: re-apply the pre-filter on all scrubbed fields using
        # the now-complete token map.  This catches PII discovered in LATER
        # fields (e.g. a name found in a user message that also appears as a
        # substring in the system prompt which was processed first).
        #
        # OPTIMIZATION: Only check PII that was actually detected in this
        # request (from all_entities), not the entire session token map.
        # This keeps cost proportional to request size, not session size.
        #
        # IMPORTANT: We use position-based replacement (not str.replace) to
        # avoid matching PII values inside already-placed tokens.  For example,
        # PII "PERSON" must not match inside "REDACTED_PERSON_1".
        scrub_map: dict[str, str] = getattr(token_map, "scrub_map", {})
        prefilter_reused_pii: set[str] = set()
        # PII that were emitted as entities in the first pass — already
        # captured via all_entities[i]._matched_text, so don't double-count.
        entity_pii: set[str] = {
            getattr(e, "_matched_text", "") for e in all_entities
        }
        entity_pii.discard("")
        if scrub_map:
            token_meta: dict[str, dict] = getattr(token_map, "token_meta", {})
            # Collect only PII that still appears as raw text in the scrubbed
            # fields.  This keeps cost proportional to request size, not session
            # size, while still catching cross-field PII leakage.
            all_scrubbed_text = "\n".join(replacements.values())
            # Use casefold() (not lower()) so the case-insensitive
            # cross-field rescan correctly handles Unicode equivalences
            # such as German "ß" ↔ "SS" and Turkish "İ" ↔ "i".  For the
            # candidate discovery step we use a regex with FULLCASE for
            # case-insensitive PII because Python's casefold() can
            # produce non-trivial mappings (``"İ".casefold() == "i\u0307"``)
            # that don't substring-match the corresponding plain "i" in
            # the scrubbed text — without a FULLCASE regex check the
            # variant would silently leak past the rescan.
            try:
                import regex as _candidate_regex_mod
                _has_regex_lib_for_candidate = True
            except ImportError:  # pragma: no cover
                import re as _candidate_regex_mod  # type: ignore[no-redef]
                _has_regex_lib_for_candidate = False
            all_scrubbed_lower = all_scrubbed_text.casefold()
            request_pii: set[str] = set()
            for pii, token in scrub_map.items():
                if token == pii:
                    continue
                _meta = token_meta.get(pii, {})
                _cs = _meta.get("case_sensitive", True)
                if _cs:
                    if pii in all_scrubbed_text:
                        request_pii.add(pii)
                else:
                    # Fast path: casefold substring check covers most
                    # ASCII / simple-fold cases without compiling a regex.
                    if pii.casefold() in all_scrubbed_lower:
                        request_pii.add(pii)
                        continue
                    # Slow path: full Unicode case-fold via regex FULLCASE.
                    # Catches ``İ ↔ i``, ``ß ↔ ss/SS`` and similar
                    # asymmetric foldings that the substring check misses.
                    if _has_regex_lib_for_candidate:
                        try:
                            if _candidate_regex_mod.search(  # type: ignore[attr-defined]
                                _candidate_regex_mod.escape(pii),
                                all_scrubbed_text,
                                _candidate_regex_mod.IGNORECASE | _candidate_regex_mod.FULLCASE,
                            ):
                                request_pii.add(pii)
                        except Exception:
                            pass

            if request_pii:
                # Protect ALL tokens already present in the scrubbed text,
                # not just the ones for PII we're about to replace.
                # Use a mutable set so newly inserted tokens are also protected.
                all_non_identity_tokens: set[str] = {
                    v for k, v in scrub_map.items() if v != k
                }
                protected_tokens: set[str] = {
                    t for t in all_non_identity_tokens if t in all_scrubbed_text
                }
                sorted_pii = sorted(request_pii, key=len, reverse=True)
                rescrub_count = 0
                # R69-2 fix: hoist the protected-tokens sort outside
                # the per-field loop and maintain it incrementally as
                # tokens are added.  The previous code re-sorted on
                # EVERY successful replacement → O(N×M×len) worst
                # case for N fields × M PIIs.  ``sorted_protected``
                # is a list maintained in length-descending order
                # (longest first) so ``_build_occupied_ranges`` finds
                # the broadest matches before narrower substrings.
                sorted_protected = sorted(protected_tokens, key=len, reverse=True)
                for json_path, scrubbed_text in replacements.items():
                    updated = scrubbed_text
                    occupied = _build_occupied_ranges(updated, sorted_protected)
                    for pii in sorted_pii:
                        if not pii:
                            continue
                        meta = token_meta.get(pii, {})
                        _cs = meta.get("case_sensitive", True)
                        # Case-aware bail-out: use casefold() for full
                        # Unicode case-equivalence (e.g. ß ↔ SS, İ ↔ i),
                        # not lower(), so the cross-field rescan
                        # actually catches the variants the outer
                        # casefold check identified.
                        if _cs:
                            if pii not in updated:
                                continue
                        else:
                            # Fast path: casefold substring covers most cases.
                            if pii.casefold() in updated.casefold():
                                pass  # proceed to regex replacement
                            elif _has_regex_lib_for_candidate:
                                # Slow path: FULLCASE regex covers İ↔i etc.
                                try:
                                    if not _candidate_regex_mod.search(  # type: ignore[attr-defined]
                                        _candidate_regex_mod.escape(pii),
                                        updated,
                                        _candidate_regex_mod.IGNORECASE | _candidate_regex_mod.FULLCASE,
                                    ):
                                        continue
                                except Exception:
                                    continue
                            else:
                                continue
                        if meta.get("exclude_from_prefilter", False):
                            continue
                        token = scrub_map.get(pii, "")
                        if not token or token == pii:
                            continue
                        # Build search pattern respecting word_boundary
                        # and case_sensitive.  For case-insensitive
                        # matching we prefer the third-party ``regex``
                        # module (a hard dependency) because its
                        # ``IGNORECASE | FULLCASE`` flag combination
                        # implements full Unicode case folding — the
                        # stdlib ``re.IGNORECASE`` does not (it only
                        # does simple case folding, which leaves
                        # German ß ↔ SS and Turkish İ ↔ i as silent
                        # leaks).  We fall back to ``re`` only if the
                        # third-party module is unavailable.
                        _wb = meta.get("word_boundary", False)
                        _cs = meta.get("case_sensitive", True)
                        try:
                            import regex as _regex_mod  # type: ignore
                            _has_regex_lib = True
                        except ImportError:  # pragma: no cover
                            import re as _regex_mod  # type: ignore[no-redef]
                            _has_regex_lib = False
                        escaped = _regex_mod.escape(pii)
                        pattern_str = rf"\b{escaped}\b" if _wb else escaped
                        if _cs:
                            _flags = 0
                        elif _has_regex_lib:
                            _flags = _regex_mod.IGNORECASE | _regex_mod.FULLCASE  # type: ignore[attr-defined]
                        else:  # pragma: no cover
                            _flags = _regex_mod.IGNORECASE
                        # R65-4 fix: per-PII try/except so a single
                        # corrupted PII string (regex lib internal
                        # limit, NUL bytes, etc.) only skips THIS
                        # PII rather than aborting the entire
                        # second-pass scrub for the request — which
                        # would leave SUBSEQUENT PII unprotected.
                        try:
                            pii_re = _regex_mod.compile(pattern_str, _flags)
                        except Exception:
                            logger.exception(
                                "Second-pass scrub: failed to compile pattern "
                                "for PII (len=%d); skipping this entry",
                                len(pii),
                            )
                            continue
                        # Position-based replacement with occupied-range checks
                        result_parts: list[str] = []
                        search_start = 0
                        replaced_any = False
                        while True:
                            m = pii_re.search(updated, search_start)
                            if m is None:
                                result_parts.append(updated[search_start:])
                                break
                            idx = m.start()
                            pii_end = m.end()
                            overlaps_token = _overlaps_any(idx, pii_end, occupied)
                            if overlaps_token:
                                result_parts.append(updated[search_start:pii_end])
                                search_start = pii_end
                            else:
                                result_parts.append(updated[search_start:idx])
                                result_parts.append(token)
                                search_start = pii_end
                                replaced_any = True
                        if replaced_any:
                            updated = "".join(result_parts)
                            # R69-2 fix: insert the new token into the
                            # already-sorted protected list (length-
                            # descending) via bisect-style scan instead
                            # of re-sorting the whole set.  Then
                            # rebuild ``occupied`` ONCE with the
                            # already-sorted list — same cost as before
                            # but no extra ``sorted()`` per iteration.
                            protected_tokens.add(token)
                            if token not in sorted_protected:
                                # Find insertion point so list stays sorted.
                                tlen = len(token)
                                _ins = 0
                                for _ins, _t in enumerate(sorted_protected):
                                    if len(_t) <= tlen:
                                        break
                                else:
                                    _ins = len(sorted_protected)
                                sorted_protected.insert(_ins, token)
                            occupied = _build_occupied_ranges(updated, sorted_protected)
                            rescrub_count += 1
                            if pii not in entity_pii:
                                prefilter_reused_pii.add(pii)
                    if updated != scrubbed_text:
                        replacements[json_path] = updated
                if rescrub_count:
                    logger.info("Second-pass scrub: %d additional replacements across fields", rescrub_count)

        # R61-4 fix: avoid the doubled JSON round-trip.  The R59-6
        # fix added the round-trip here AND in every provider's
        # ``replace_text_fields`` — about ~100 MB of redundant
        # serialize/deserialize work on a 50 MB body.  Each provider
        # is now responsible for its own deep-copy strategy
        # (Anthropic / OpenAI / YAML providers all do JSON
        # round-trip with deepcopy fallback after R60-3).  Pass the
        # body through directly so providers don't deepcopy a copy.
        scrubbed_body = provider.replace_text_fields(body, replacements)

        # Attach stage_timings to the result for callers that want it.
        stage_timings = [
            {"stage": v["stage"], "ms": round(v["ms"], 2), "count": v["entities"]}
            for v in _stage_timings_accum.values()
        ]
        return scrubbed_body, all_entities, stage_timings, prefilter_reused_pii
