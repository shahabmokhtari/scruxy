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
        # a proper SSE event when flushing the buffer.
        last_event_data: str | None = None
        # ``event:`` line of the last TEXT event.  A flush before a
        # terminal/structural event reproduces a complete, correctly-typed
        # event using this line.  Anthropic pairs ``event:`` + ``data:``; a
        # bare ``data:`` content_block_delta emitted AFTER ``message_stop``
        # corrupts framing and the client rejects the whole response as a
        # "server error".
        last_text_event_line: str | None = None
        # ``event:`` line awaiting its ``data:`` line.  Deferred so a buffer
        # flush can be injected BEFORE a structural event's own event line.
        pending_event_line: str | None = None

        async for raw_line in response_stream:
            line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line

            # Defer ``event:`` lines until the following ``data:`` line is
            # classified, so held-back text can be flushed (as a complete
            # text event) ahead of a terminal/structural event.
            if line.startswith("event:"):
                if pending_event_line is not None:
                    # Two event lines with no data between (malformed
                    # upstream) — emit the first so it isn't dropped.
                    yield pending_event_line.encode("utf-8")
                pending_event_line = line
                continue

            # Process "data:" lines (with or without space after colon per SSE spec).
            if line.startswith("data: "):
                event_data = line[6:]
            elif line.startswith("data:"):
                event_data = line[5:]
            else:
                # Blank separator / comment / id / retry — emit any pending
                # event line first so framing order is preserved.
                if pending_event_line is not None:
                    yield pending_event_line.encode("utf-8")
                    pending_event_line = None
                yield line.encode("utf-8") if isinstance(line, str) else raw_line
                continue

            # Terminal [DONE] marker — flush the rolling buffer BEFORE
            # yielding the marker so the client receives all text data
            # before it sees [DONE] and stops reading.
            if event_data.strip() == "[DONE]":
                for chunk in self._build_flush_chunks(last_text_event_line, last_event_data):
                    yield chunk
                if pending_event_line is not None:
                    yield pending_event_line.encode("utf-8")
                    pending_event_line = None
                yield line.encode("utf-8") if isinstance(line, str) else raw_line
                continue

            # Let the provider parse the SSE event.
            sse_field = self.provider.parse_sse_event(event_data)
            if sse_field is None:
                # Structural / non-text event.  Flush held-back text ONLY
                # before a genuinely TERMINAL event (end of a content block
                # or message: content_block_stop, message_stop,
                # response.completed, response.output_text.done, ...), so
                # deferred token fragments are delivered BEFORE the terminal
                # event — never after it (which corrupts SSE framing and
                # makes the client reject the whole response as a server
                # error).  TRANSIENT structural events MUST NOT trigger a
                # flush: Anthropic sends ``ping`` keep-alives BETWEEN
                # ``content_block_delta`` events, and a redaction token split
                # across two deltas (e.g. ``REDACTED`` + ``_PERSON_1``) would
                # otherwise be flushed half-formed and leak unreplaced.
                if self._is_terminal_sse_event(event_data):
                    for chunk in self._build_flush_chunks(last_text_event_line, last_event_data):
                        yield chunk
                # Emit this event's own (deferred) event line, then its data.
                if pending_event_line is not None:
                    yield pending_event_line.encode("utf-8")
                    pending_event_line = None
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

            # Text event: emit its (deferred) event line and remember it so a
            # later flush can reproduce a correctly-typed event.
            if pending_event_line is not None:
                yield pending_event_line.encode("utf-8")
                last_text_event_line = pending_event_line
                pending_event_line = None

            last_event_data = event_data

            # Feed text through rolling buffer.
            safe_text = self._feed_buffer(sse_field.text_value)

            # Deanonymize the safe portion.
            unscrubbed = deanonymize_text(safe_text, self.token_map)

            # Rebuild the SSE event with the unscrubbed text.
            rebuilt_event_data = self.provider.rebuild_sse_event(event_data, unscrubbed)
            rebuilt_line = f"data: {rebuilt_event_data}"
            yield rebuilt_line.encode("utf-8")

        # Flush remaining buffer content at end of stream (e.g. OpenAI with
        # no [DONE], or a stream that ended without a terminal event).  Wrap
        # the flushed text in a proper SSE event so the client can parse it.
        for chunk in self._build_flush_chunks(last_text_event_line, last_event_data):
            yield chunk
        if pending_event_line is not None:
            yield pending_event_line.encode("utf-8")

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

    def _build_flush_chunks(
        self, event_line: str | None, last_event_data: str | None
    ) -> list[bytes]:
        """Return SSE chunks delivering any held-back buffer text.

        The held-back text is emitted as a *complete* event: an optional
        ``event:`` line (required by Anthropic, which pairs ``event:`` +
        ``data:``), the rebuilt ``data:`` line, then an empty chunk so the
        caller's ``chunk + b"\\n"`` framing produces the spec-required
        ``\\n\\n`` terminator.  Returns ``[]`` (and leaves the buffer
        untouched) when there is nothing to flush.  Clears the buffer
        otherwise, so repeated calls are idempotent.
        """
        if not self.buffer or last_event_data is None:
            return []
        flushed = self._flush_buffer()
        unscrubbed = deanonymize_text(flushed, self.token_map)
        if not unscrubbed:
            return []
        rebuilt = self.provider.rebuild_sse_event(last_event_data, unscrubbed)
        chunks: list[bytes] = []
        if event_line is not None:
            chunks.append(event_line.encode("utf-8"))
        chunks.append(f"data: {rebuilt}".encode("utf-8"))
        chunks.append(b"")
        return chunks

    # Event ``type`` values that mark the end of a content block or message,
    # after which no further text deltas arrive for the current block.  The
    # rolling buffer is flushed before these (but NOT before transient
    # structural events such as Anthropic ``ping`` keep-alives).
    _TERMINAL_EVENT_TYPES = frozenset({
        "message_stop",            # Anthropic: end of message
        "content_block_stop",      # Anthropic: end of a content block
        "response.completed",      # OpenAI Responses: stream done
        "response.incomplete",
        "response.failed",
    })

    def _is_terminal_sse_event(self, event_data: str) -> bool:
        """Return whether *event_data* is a content/message-terminating event.

        Terminal events end a content block or the whole message, so it is
        safe (and necessary) to flush any held-back token text before them.
        Transient structural events (keep-alive ``ping``, ``*_start``,
        ``*.delta`` control frames, ``*.added`` …) return ``False`` so the
        rolling buffer survives and a token split across deltas still
        reassembles.
        """
        try:
            obj = _json.loads(event_data)
        except (_json.JSONDecodeError, TypeError, ValueError):
            return False
        if not isinstance(obj, dict):
            return False
        etype = obj.get("type")
        if not isinstance(etype, str):
            return False
        if etype in self._TERMINAL_EVENT_TYPES:
            return True
        # Anthropic ``signature_delta`` is a non-text ``content_block_delta``
        # carrying the thinking-block signature; it terminates that block's
        # thinking text (no more thinking deltas follow).  Held thinking text
        # must flush BEFORE it so content is never reordered after its
        # signature.
        delta = obj.get("delta")
        if isinstance(delta, dict) and delta.get("type") == "signature_delta":
            return True
        # Generic terminators: ``*_stop`` (Anthropic content_block_stop /
        # message_stop) and ``*.done`` (OpenAI Responses output_text /
        # content_part / output_item / refusal terminators).
        #
        # A generic ``.completed`` rule is intentionally NOT used: OpenAI
        # Responses emits non-terminal tool-status events that end in
        # ``.completed`` (``response.web_search_call.completed``,
        # ``response.file_search_call.completed``, ``response.mcp_call
        # .completed``) which could land BETWEEN text deltas and would flush
        # a half-formed split token, leaking it unreplaced.  The only
        # terminal ``.completed`` event — ``response.completed`` — is covered
        # explicitly by ``_TERMINAL_EVENT_TYPES`` above.
        return etype.endswith("_stop") or etype.endswith(".done")

    def _extract_safe(self) -> str:
        """Determine how much of ``self.buffer`` is safe to emit.

        Uses the trie built from the actual token map to detect partial
        token prefixes at the end of the buffer, supporting any token
        format (REDACTED_*, UUIDs, script-generated, etc.).

        The strategy:
        1. Scan backwards from the end of the buffer looking for a position
           where the tail is a prefix of some token in the trie.
        2. Everything before that position is safe to emit.
        3. If no trailing partial token is found, the whole buffer is safe to
           emit (the scan window of ``buffer_size + 1`` chars covers every
           possible incomplete token, since tokens are <= ``buffer_size``).
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

        # No trailing partial token exists.  The backward scan above covers
        # the last ``buffer_size + 1`` characters, and every token is at most
        # ``buffer_size`` characters long, so a ``None`` result guarantees
        # there is no incomplete token at the buffer tail.  The ENTIRE buffer
        # is therefore safe to emit: ``deanonymize_text`` resolves any
        # complete tokens, and none can extend into a future chunk.
        #
        # We must NOT blindly split at ``len - buffer_size`` here.  A
        # COMPLETE token straddling that offset (start before it, end after
        # it) is not flagged as a partial — its form plus the trailing text
        # is not a token prefix — so the split would cut it in half.  Each
        # half then fails to match and the client visually reassembles the
        # raw token (a PII-token leak, e.g. ``REDACTED_PERSON_11`` shown to
        # the user).  Emitting the whole buffer avoids that, and memory stays
        # bounded because the retain path above only ever holds back a single
        # partial token (<= ``buffer_size`` chars).
        safe = self.buffer
        self.buffer = ""
        return safe
