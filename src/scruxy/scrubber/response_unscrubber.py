"""Unscrub (deanonymize) tokens in LLM API responses."""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from scruxy.providers.base import TextField
from scruxy.tokenmap.deanonymizer import Deanonymizer


@runtime_checkable
class ResponseProviderLike(Protocol):  # pragma: no cover
    """Minimal provider interface consumed by ResponseUnscrubber."""

    def extract_response_text_fields(self, body: dict) -> list[TextField]: ...
    def replace_text_fields(self, body: dict, replacements: dict[str, str]) -> dict: ...


def deanonymize_text(text: str, token_map: Any) -> str:
    """Replace all redaction tokens in *text* with their original PII values.

    Uses a single-pass approach: builds a sorted token list and replaces
    longest-first.  Uses the thread-safe ``unscrub_map`` property (which
    returns a snapshot) to avoid concurrent-modification issues.
    """
    if hasattr(token_map, "unscrub_map"):
        unscrub: dict[str, str] = token_map.unscrub_map
    elif hasattr(token_map, "_unscrub"):
        unscrub = dict(token_map._unscrub)
    else:
        unscrub = getattr(token_map, "unscrub", {})

    if not unscrub:
        return text

    # Build a combined regex for all tokens (longest first to avoid partial matches).
    # This is O(N + M) where N = number of tokens and M = text length,
    # compared to the previous O(N * M) sequential str.replace approach.
    import re as _re_mod
    sorted_tokens = sorted(unscrub.keys(), key=len, reverse=True)
    pattern = _re_mod.compile("|".join(_re_mod.escape(t) for t in sorted_tokens))
    return pattern.sub(lambda m: unscrub[m.group(0)], text)


class ResponseUnscrubber:
    """Unscrub (deanonymize) redaction tokens in an LLM API response body.

    Mirrors the scrubbing path: the provider extracts text fields from the
    response, each field is deanonymized using the session's token map, and
    the provider replaces the fields back into the body.
    """

    def unscrub_response(
        self,
        body: dict,
        provider: ResponseProviderLike,
        token_map: Any,
    ) -> dict:
        """Unscrub a response body.

        Steps
        -----
        1. ``provider.extract_response_text_fields(body)`` -- get text fields.
        2. For each field, ``deanonymize_text(text, token_map)``.
        3. Build a ``{json_path: unscrubbed_text}`` replacement map.
        4. ``provider.replace_text_fields(body, replacements)`` -- apply.
        5. Return the unscrubbed body.
        """
        text_fields: list[TextField] = provider.extract_response_text_fields(body)

        replacements: dict[str, str] = {}
        for tf in text_fields:
            replacements[tf.json_path] = deanonymize_text(tf.text_value, token_map)

        return provider.replace_text_fields(body, replacements)
