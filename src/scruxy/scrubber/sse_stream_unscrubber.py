"""Unscrub redaction tokens in Server-Sent Event (SSE) streams.

Redaction tokens may be split across SSE chunk boundaries.  A rolling buffer
of configurable size (default 40 chars -- the maximum token length defined
in the config) is used to detect and reassemble partial tokens before
deanonymization.

Supports any token format (``REDACTED_*``, UUIDs, script-generated, etc.)
by building a trie from the actual token map.
"""
from __future__ import annotations

import json as _json
from collections.abc import AsyncGenerator
from typing import Any, Protocol, runtime_checkable

from scruxy.providers.base import SSETextField
from scruxy.scrubber.response_unscrubber import deanonymize_text
from scruxy.tokenmap.deanonymizer import _Trie


_DEEP_JSON_MAX_DEPTH = 200


def _deanonymize_json_deep(data: Any, token_map: Any, _depth: int = 0) -> Any:
    """Iteratively deanonymize all string values in a JSON structure.

    Safely handles nested dicts/lists and preserves JSON encoding (unlike
    raw ``str.replace`` on a serialized JSON string).

    R59-2 fix: was recursive with a fail-OPEN depth-200 cap that
    silently leaked REDACTED tokens through to the client at deeper
    nesting (sibling of R58-2 on the request side).  Iteration removes
    the cap entirely — every string at every depth is deanonymized.
    The ``_depth`` parameter is kept for backward compat but is no
    longer consulted; ``_DEEP_JSON_MAX_DEPTH`` is retained for
    callers that read it as a tuning hint.
    """
    if isinstance(data, str):
        return deanonymize_text(data, token_map)
    if not isinstance(data, (dict, list)):
        return data

    # Create the result root mirroring the input container type.
    if isinstance(data, dict):
        result: Any = {}
    else:
        result = []

    # Stack of (source_container, destination_container) pairs.  We
    # pre-create empty containers in the destination so children can
    # reference the future-final structure without recursion.
    stack: list[tuple[Any, Any]] = [(data, result)]
    while stack:
        src, dst = stack.pop()
        if isinstance(src, dict):
            for k, v in src.items():
                if isinstance(v, str):
                    dst[k] = deanonymize_text(v, token_map)
                elif isinstance(v, dict):
                    new_child: Any = {}
                    dst[k] = new_child
                    stack.append((v, new_child))
                elif isinstance(v, list):
                    new_child = []
                    dst[k] = new_child
                    stack.append((v, new_child))
                else:
                    dst[k] = v
        else:  # list
            for v in src:
                if isinstance(v, str):
                    dst.append(deanonymize_text(v, token_map))
                elif isinstance(v, dict):
                    new_child = {}
                    dst.append(new_child)
                    stack.append((v, new_child))
                elif isinstance(v, list):
                    new_child = []
                    dst.append(new_child)
                    stack.append((v, new_child))
                else:
                    dst.append(v)
    return result


@runtime_checkable
class SSEProviderLike(Protocol):  # pragma: no cover
    """Minimal provider interface consumed by SSEStreamUnscrubber."""

    def parse_sse_event(self, event_data: str) -> SSETextField | None: ...
    def rebuild_sse_event(self, event_data: str, unscrubbed_text: str) -> str: ...


# ---------------------------------------------------------------------------
# SSEStreamUnscrubber
# ---------------------------------------------------------------------------

class SSEStreamUnscrubber:
    """Process an SSE response stream, deanonymizing redaction tokens.

    Handles token fragments that may be split across consecutive SSE events
    by maintaining a rolling text buffer.
    """

    def __init__(
        self,
        provider: SSEProviderLike,
        token_map: Any,
        buffer_size: int = 40,
    ) -> None:
        self.provider = provider
        self.token_map = token_map
        self.buffer = ""
        # Ensure buffer_size covers the longest token in the map
        max_token_len = buffer_size
        try:
            unscrub = token_map.unscrub_map if hasattr(token_map, "unscrub_map") else {}
            if unscrub:
                max_token_len = max(max_token_len, max(len(t) for t in unscrub))
        except Exception:
            pass
        self.buffer_size = max_token_len
        self._trie = self._build_trie(token_map)
        # Track the token_map version when the trie was last built so we
        # can skip unnecessary rebuilds across calls to process_sse_stream.
        self._trie_version: int = getattr(token_map, "_token_version", -1)

    @staticmethod
    def _build_trie(token_map: Any) -> _Trie:
        """Build a trie from the token map's unscrub dictionary."""
        trie = _Trie()
        if hasattr(token_map, "unscrub_map"):
            unscrub: dict[str, str] = token_map.unscrub_map
        elif hasattr(token_map, "_unscrub"):
            unscrub = token_map._unscrub
        else:
            unscrub = getattr(token_map, "unscrub", {})
        for token, pii in unscrub.items():
            trie.insert(token, pii)
        return trie

    # -- public API --------------------------------------------------------

    async def process_sse_stream(
        self, response_stream: AsyncGenerator[bytes, None],
    ) -> AsyncGenerator[bytes, None]:
        """Consume *response_stream*, yielding unscrubbed SSE lines.

        For each SSE event line:

        1. Parse SSE format (``data: ...``).
        2. ``provider.parse_sse_event(event_data)`` to extract text.
        3. Feed text through the rolling buffer for boundary handling.
        4. Deanonymize the safe-to-emit portion.
        5. ``provider.rebuild_sse_event(event_data, unscrubbed_text)``
           to reconstruct the SSE line.
        6. Yield the rebuilt line as ``bytes``.

        Non-data lines (comments, empty keep-alive lines, event/id/retry
        fields) are passed through unchanged.
        """
        # Rebuild the trie only if the token map has gained new tokens
        # since we last built it.  This avoids redundant work when the
        # same unscrubber is reused across requests in the same session.
        current_version: int = getattr(self.token_map, "_token_version", -1)
        if current_version != self._trie_version:
            self._trie = self._build_trie(self.token_map)
            self._trie_version = current_version
            # Recalculate buffer_size for any new longer tokens
            try:
                unscrub = self.token_map.unscrub_map if hasattr(self.token_map, "unscrub_map") else {}
                if unscrub:
                    self.buffer_size = max(self.buffer_size, max(len(t) for t in unscrub))
            except Exception:
                pass

        # Track the last event_data that contained text, so we can rebuild
        # a proper SSE event when flushing the buffer at end-of-stream.
        last_event_data: str | None = None

        async for raw_line in response_stream:
            line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line

            # Process "data:" lines (with or without space after colon per SSE spec).
            if line.startswith("data: "):
                event_data = line[6:]
            elif line.startswith("data:"):
                event_data = line[5:]
            else:
                yield line.encode("utf-8") if isinstance(line, str) else raw_line
                continue

            # Terminal [DONE] marker — flush the rolling buffer BEFORE
            # yielding the marker so the client receives all text data
            # before it sees [DONE] and stops reading.
            if event_data.strip() == "[DONE]":
                if self.buffer and last_event_data is not None:
                    flushed = self._flush_buffer()
                    unscrubbed = deanonymize_text(flushed, self.token_map)
                    if unscrubbed:
                        rebuilt = self.provider.rebuild_sse_event(
                            last_event_data, unscrubbed,
                        )
                        yield f"data: {rebuilt}".encode("utf-8")
                        # SSE events MUST be terminated by a blank line
                        # ("\n\n").  Both proxy callers append a single
                        # "\n" to each yielded chunk, so we need an extra
                        # empty chunk here to produce the second newline
                        # between the synthesized flush event and the
                        # [DONE] sentinel.  Without this, EventSource and
                        # OpenAI's Python Stream parser treat the two
                        # data: lines as one un-dispatched event whose
                        # data field becomes "{flushed}\n[DONE]" — the
                        # flushed text is lost and [DONE] is no longer
                        # recognised.
                        yield b""
                yield line.encode("utf-8") if isinstance(line, str) else raw_line
                continue

            # Let the provider parse the SSE event.
            sse_field = self.provider.parse_sse_event(event_data)
            if sse_field is None:
                # Provider couldn't extract a specific text field (e.g. a
                # "done" or "completed" event that carries accumulated text).
                # Parse as JSON, recursively deanonymize all string values,
                # and re-serialize.  This is safe for JSON encoding and
                # covers deeply nested response objects.
                try:
                    data_obj = _json.loads(event_data)
                    data_obj = _deanonymize_json_deep(data_obj, self.token_map)
                    rebuilt_line = f"data: {_json.dumps(data_obj, ensure_ascii=False)}"
                except (_json.JSONDecodeError, TypeError):
                    # Not valid JSON — deanonymize the raw text to replace
                    # any tokens that may be present in non-JSON events.
                    raw_line = line if isinstance(line, str) else line.decode("utf-8")
                    try:
                        from scruxy.scrubber.response_unscrubber import deanonymize_text as _deanon_text
                        rebuilt_line = _deanon_text(raw_line, self.token_map)
                    except Exception:
                        rebuilt_line = raw_line
                yield rebuilt_line.encode("utf-8")
                continue

            last_event_data = event_data

            # Feed text through rolling buffer.
            safe_text = self._feed_buffer(sse_field.text_value)

            # Deanonymize the safe portion.
            unscrubbed = deanonymize_text(safe_text, self.token_map)

            # Rebuild the SSE event with the unscrubbed text.
            rebuilt_event_data = self.provider.rebuild_sse_event(event_data, unscrubbed)
            rebuilt_line = f"data: {rebuilt_event_data}"
            yield rebuilt_line.encode("utf-8")

        # Flush remaining buffer content at end of stream.  Wrap the
        # flushed text in a proper SSE event so the client can parse it.
        # See the [DONE] branch above: emit a blank chunk after the
        # synthesized event so callers' "chunk + b'\n'" framing produces
        # the spec-required "\n\n" event terminator.
        if self.buffer and last_event_data is not None:
            flushed = self._flush_buffer()
            unscrubbed = deanonymize_text(flushed, self.token_map)
            if unscrubbed:
                rebuilt = self.provider.rebuild_sse_event(
                    last_event_data, unscrubbed,
                )
                yield f"data: {rebuilt}".encode("utf-8")
                yield b""

    # -- buffer management -------------------------------------------------

    def _feed_buffer(self, text: str) -> str:
        """Feed *text* into the rolling buffer and return the safe-to-emit portion.

        The buffer retains up to ``buffer_size`` trailing characters that
        *might* be part of an incomplete redaction token.  Everything before
        that window is considered safe and returned immediately.
        """
        self.buffer += text
        safe = self._extract_safe()
        return safe

    def _flush_buffer(self) -> str:
        """Return and clear whatever remains in the buffer."""
        remaining = self.buffer
        self.buffer = ""
        return remaining

    def _extract_safe(self) -> str:
        """Determine how much of ``self.buffer`` is safe to emit.

        Uses the trie built from the actual token map to detect partial
        token prefixes at the end of the buffer, supporting any token
        format (REDACTED_*, UUIDs, script-generated, etc.).

        The strategy:
        1. Scan backwards from the end of the buffer looking for a position
           where the tail is a prefix of some token in the trie.
        2. Everything before that position is safe to emit.
        3. If no prefix match is found but the buffer exceeds
           ``buffer_size``, emit everything up to the last
           ``buffer_size`` characters.
        """
        trie_starts = self._trie.root.children
        if not trie_starts:
            # No tokens at all — emit everything.
            safe = self.buffer
            self.buffer = ""
            return safe

        # Scan backwards through the tail of the buffer looking for a
        # position that could be the start of a partial token.
        # Check buffer_size + 1 characters from the end to avoid splitting
        # a token that starts exactly at the scan boundary.
        search_start = max(0, len(self.buffer) - self.buffer_size - 1)
        partial_start: int | None = None

        for i in range(len(self.buffer) - 1, search_start - 1, -1):
            if self.buffer[i] not in trie_starts:
                continue
            tail = self.buffer[i:]
            # Check if this tail is a complete token match.
            replacement, length = self._trie.search_prefix(self.buffer, i)
            if replacement is not None and length == len(tail):
                # Complete token at the very end. Only hold it back if the
                # trie contains a strictly longer token starting with this
                # one — use the trie structure directly for a generic check
                # that works with any token format (REDACTED_*, UUIDs, etc.)
                if self._trie.has_longer_match(tail):
                    partial_start = i
                    continue
                # No longer token possible — let it emit normally
                break
            # Check if this tail is a prefix of some token.
            if self._trie.has_prefix(tail):
                partial_start = i
                # Keep scanning backwards — an earlier position might
                # also be a prefix, and we want the earliest one.

        if partial_start is not None:
            safe = self.buffer[:partial_start]
            self.buffer = self.buffer[partial_start:]
            return safe

        # No partial token detected.
        if len(self.buffer) > self.buffer_size:
            split_at = len(self.buffer) - self.buffer_size
            safe = self.buffer[:split_at]
            self.buffer = self.buffer[split_at:]
            return safe

        # Buffer is short and has no partial token — emit it.
        safe = self.buffer
        self.buffer = ""
        return safe
