"""Apply token replacements to text (anonymize PII spans)."""
from __future__ import annotations

from scruxy.plugin.base import PiiEntity
from scruxy.tokenmap.token_map import TokenMap


def anonymize_text(text: str, entities: list[PiiEntity], token_map: TokenMap) -> str:
    """Replace each detected PII span in *text* with a deterministic token.

    Entities are processed **right-to-left** (highest offset first) so that
    replacing a span does not shift the indices of earlier spans.

    Args:
        text: The original text to anonymize.
        entities: Detected PII entities with start/end character offsets.
        token_map: The session's :class:`TokenMap` used for deterministic token
            assignment.

    Returns:
        The text with all PII spans replaced by ``REDACTED_{TYPE}_{N}`` tokens.
    """
    if not entities:
        return text

    # Sort by start descending so we can replace right-to-left safely.
    sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)

    result = text
    for entity in sorted_entities:
        pii_text = text[entity.start : entity.end]
        token = token_map.get_or_create_token(
            pii=pii_text,
            entity_type=entity.entity_type,
            source=entity.source,
        )
        if token is None:
            continue
        result = result[: entity.start] + token + result[entity.end :]

    return result
