"""Merge and deduplicate overlapping PII entity spans."""
from __future__ import annotations

from scruxy.plugin.base import PiiEntity


def merge_and_deduplicate(entities: list[PiiEntity]) -> list[PiiEntity]:
    """Merge overlapping PII entities, keeping the highest-confidence spans.

    Logic:
        1. Sort entities by start position.
        2. Walk through sorted entities, resolving overlapping spans:
           - When two entities overlap (entity B starts before entity A ends),
             keep the one with higher confidence score.
           - If scores are equal, prefer the longer span.
        3. Return a non-overlapping, sorted list.

    Args:
        entities: Detected PII entities, potentially with overlapping spans.

    Returns:
        A deduplicated list of non-overlapping PII entities sorted by start position.
    """
    if not entities:
        return []

    sorted_entities = sorted(entities, key=lambda e: (e.start, -e.end))

    result: list[PiiEntity] = [sorted_entities[0]]

    for current in sorted_entities[1:]:
        previous = result[-1]

        # No overlap: current starts at or after previous ends
        if current.start >= previous.end:
            result.append(current)
            continue

        # Overlap detected — resolve by keeping the better entity
        winner = _pick_winner(previous, current)
        if winner is current:
            # Extend winner to cover the full span of both entities
            # to prevent PII leakage from the non-overlapping prefix.
            if previous.start < current.start:
                current = PiiEntity(
                    entity_type=current.entity_type,
                    start=previous.start,
                    end=max(current.end, previous.end),
                    score=current.score,
                    source=current.source,
                    use_word_boundary=current.use_word_boundary,
                    case_sensitive=current.case_sensitive,
                )
            result[-1] = current
        else:
            # Previous won — extend it to cover current's span too
            if current.end > previous.end:
                result[-1] = PiiEntity(
                    entity_type=previous.entity_type,
                    start=previous.start,
                    end=current.end,
                    score=previous.score,
                    source=previous.source,
                    use_word_boundary=previous.use_word_boundary,
                    case_sensitive=previous.case_sensitive,
                )

    return result


def _pick_winner(a: PiiEntity, b: PiiEntity) -> PiiEntity:
    """Choose the better entity when two spans overlap.

    Preference order:
        1. Higher confidence score wins.
        2. On tie, longer span wins.
        3. On tie, the first entity (earlier or already-selected) wins.

    Args:
        a: The currently selected (previous) entity.
        b: The challenger (current) entity.

    Returns:
        The entity that should be kept.
    """
    if a.score != b.score:
        return a if a.score > b.score else b

    len_a = a.end - a.start
    len_b = b.end - b.start
    if len_a != len_b:
        return a if len_a > len_b else b

    # True tie — keep the already-selected entity (stable)
    return a
