"""Tests for the SSEStreamUnscrubber module."""
from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any

import pytest

from scruxy.providers.base import SSETextField
from scruxy.scrubber.response_unscrubber import deanonymize_text
from scruxy.scrubber.sse_stream_unscrubber import SSEStreamUnscrubber


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class _FakeTokenMap:
    """Minimal token map with an ``unscrub`` dict."""

    def __init__(self, unscrub: dict[str, str]) -> None:
        self.unscrub = unscrub


def _make_provider(
    parse_fn: Any | None = None,
    rebuild_fn: Any | None = None,
) -> Any:
    """Build a mock provider with parse_sse_event / rebuild_sse_event."""

    class _MockSSEProvider:
        def parse_sse_event(self, event_data: str) -> SSETextField | None:
            if parse_fn is not None:
                return parse_fn(event_data)
            # Default: treat the whole event_data as text.
            return SSETextField(text_value=event_data)

        def rebuild_sse_event(self, event_data: str, unscrubbed_text: str) -> str:
            if rebuild_fn is not None:
                return rebuild_fn(event_data, unscrubbed_text)
            # Default: replace the original text with unscrubbed text.
            return unscrubbed_text

    return _MockSSEProvider()


async def _async_lines(lines: list[str | bytes]) -> AsyncGenerator[bytes, None]:
    """Helper to create an async generator from a list of lines."""
    for line in lines:
        if isinstance(line, str):
            yield line.encode("utf-8")
        else:
            yield line


async def _collect(gen: AsyncGenerator[bytes, None]) -> list[str]:
    """Collect all items from an async generator, decoding bytes to str."""
    result: list[str] = []
    async for item in gen:
        result.append(item.decode("utf-8") if isinstance(item, bytes) else item)
    return result


# ---------------------------------------------------------------------------
# SSEStreamUnscrubber tests
# ---------------------------------------------------------------------------

class TestSSEStreamUnscrubber:
    """Tests for SSEStreamUnscrubber.process_sse_stream."""

    @pytest.mark.asyncio
    async def test_basic_unscrub_sse(self) -> None:
        """A complete token in a single SSE event is unscrubbed."""
        token_map = _FakeTokenMap({"REDACTED_EMAIL_1": "alice@example.com"})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map)
        stream = _async_lines(["data: Hello REDACTED_EMAIL_1"])
        result = await _collect(unscrubber.process_sse_stream(stream))

        # The result should contain the unscrubbed text.
        combined = "".join(result)
        assert "alice@example.com" in combined
        assert "REDACTED_EMAIL_1" not in combined

    @pytest.mark.asyncio
    async def test_long_text_token_straddling_buffer_split_not_leaked(self) -> None:
        """Regression: a COMPLETE token positioned past the ``buffer_size``
        split point in long text must not be bisected and leaked.

        Previously ``_extract_safe`` blindly split the buffer at
        ``len - buffer_size`` whenever it exceeded ``buffer_size`` (40) and
        no trailing partial token was found.  A complete token straddling
        that offset was cut in half — each half failed to match and the
        client visually reassembled the raw token (e.g. the real leak of
        ``REDACTED_PERSON_11`` / ``REDACTED_PERSON_10`` to the CLI).
        """
        from scruxy.providers.anthropic import AnthropicProvider

        class _ViewLikeMap:
            def __init__(self, unscrub: dict[str, str]) -> None:
                self._u = dict(unscrub)
                self._token_version = 1

            @property
            def unscrub_map(self) -> dict[str, str]:
                return dict(self._u)

            def get_pii(self, token: str) -> str | None:
                return self._u.get(token)

        # Full prefix-ambiguous PERSON set (REDACTED_PERSON_1 is a prefix of
        # _10.._19), matching the real session's token map.
        um = {f"REDACTED_PERSON_{i}": f"Person{i}Name" for i in range(1, 20)}
        um["REDACTED_PERSON_11"] = "Alice Smith"
        um["REDACTED_PERSON_10"] = "Contoso Corp"
        token_map = _ViewLikeMap(um)

        import json as _json

        # Long text (> buffer_size 40) with tokens embedded well past the
        # len-buffer_size offset, and a token split across two deltas too.
        # Single delta constructed so a COMPLETE token straddles the old
        # ``len - buffer_size`` split offset (this is what the old code cut in
        # half). buffer_size = 40; text length 62 => split_at = 22;
        # ``REDACTED_PERSON_10`` occupies [10, 28) which crosses 22.  This
        # scenario LEAKS on the pre-fix code and resolves on the fixed code.
        straddle_text = "Note: org REDACTED_PERSON_10 was removed from the chat roster."
        _tok_start = straddle_text.index("REDACTED_PERSON_10")
        _split_at = len(straddle_text) - 40  # old blind-split offset
        assert _tok_start < _split_at < _tok_start + len("REDACTED_PERSON_10"), (
            "test no longer straddles the split offset; it would not catch the bug"
        )
        deltas = [
            straddle_text,
            # Also exercise a token split across two deltas (retain path).
            " Also (REDAC",
            "TED_PERSON_11) joined.",
        ]

        lines: list[bytes] = [
            b"event: content_block_start",
            b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
            b"",
        ]
        for d in deltas:
            lines.append(b"event: content_block_delta")
            lines.append(b"data: " + _json.dumps({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": d}}).encode("utf-8"))
            lines.append(b"")
        lines += [
            b"event: content_block_stop",
            b'data: {"type":"content_block_stop","index":0}',
            b"",
            b"event: message_stop",
            b'data: {"type":"message_stop"}',
            b"",
        ]

        unscrubber = SSEStreamUnscrubber(AnthropicProvider(), token_map)
        out = b""
        async for chunk in unscrubber.process_sse_stream(_async_lines(lines)):
            out += b"\n" if not chunk else chunk + b"\n"
        decoded = out.decode("utf-8")
        text = "".join(
            _json.loads(line[6:])["delta"]["text"]
            for line in decoded.split("\n")
            if line.startswith("data: ") and '"text_delta"' in line
        )
        # No raw REDACTED token leaks, and both PII values are restored
        # (the straddling token AND the split-across-deltas token).
        import re as _re
        assert not _re.search(r"REDACTED_[A-Z]+_[0-9A-Za-z]+", text), f"token leaked: {text!r}"
        assert "Contoso Corp" in text
        assert "Alice Smith" in text

    @pytest.mark.asyncio
    async def test_anthropic_held_back_token_flushed_before_terminal_events(self) -> None:
        """Regression: held-back token text must be flushed as a complete,
        correctly-typed ``content_block_delta`` BEFORE ``content_block_stop`` /
        ``message_stop`` — never as a bare ``data:`` event after the stream
        ends.  A trailing out-of-order delta corrupts Anthropic SSE framing
        and the Claude client rejects the whole response as a server error.
        """
        from scruxy.providers.anthropic import AnthropicProvider

        class _ViewLikeMap:
            def __init__(self, unscrub: dict[str, str]) -> None:
                self._u = dict(unscrub)
                self._token_version = 1

            @property
            def unscrub_map(self) -> dict[str, str]:
                return dict(self._u)

            def get_pii(self, token: str) -> str | None:
                return self._u.get(token)

        # >=10 person tokens so REDACTED_PERSON_1 is a prefix of a longer
        # token and the rolling buffer holds it back until end-of-text.
        um = {f"REDACTED_PERSON_{i}": f"name{i}" for i in range(1, 13)}
        um["REDACTED_PERSON_1"] = "shahab"
        token_map = _ViewLikeMap(um)

        import json as _json

        def _ev(event: str, data: dict) -> list[bytes]:
            return [
                f"event: {event}".encode("utf-8"),
                b"data: " + _json.dumps(data).encode("utf-8"),
                b"",
            ]

        lines: list[bytes] = []
        lines += _ev("message_start", {"type": "message_start", "message": {"id": "m"}})
        lines += _ev("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
        lines += _ev("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hi "}})
        lines += _ev("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "REDACTED"}})
        lines += _ev("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "_PERSON_1"}})
        lines += _ev("content_block_stop", {"type": "content_block_stop", "index": 0})
        lines += _ev("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}})
        lines += _ev("message_stop", {"type": "message_stop"})

        unscrubber = SSEStreamUnscrubber(AnthropicProvider(), token_map)
        # Mirror the proxy's downstream framing: each chunk + "\n", empty -> "\n".
        out = b""
        async for chunk in unscrubber.process_sse_stream(_async_lines(lines)):
            out += b"\n" if not chunk else chunk + b"\n"

        # The unscrubbed name is delivered.
        assert b"shahab" in out
        assert b"REDACTED_PERSON_1" not in out
        # No content_block_delta is emitted after message_stop (the bug).
        tail = out[out.index(b'"message_stop"'):]
        assert b"content_block_delta" not in tail
        # The flushed delta carries its own event line (no bare data delta).
        assert b"data: {" in out
        decoded = out.decode("utf-8")
        for block in decoded.split("\n\n"):
            if '"content_block_delta"' in block:
                assert block.lstrip().startswith("event: content_block_delta"), (
                    f"content_block_delta without event line: {block!r}"
                )

    @pytest.mark.asyncio
    async def test_anthropic_ping_between_split_token_deltas_reassembles(self) -> None:
        """Regression: a transient ``ping`` keep-alive landing BETWEEN the two
        halves of a redaction token split across deltas must NOT trigger a
        buffer flush.  Flushing there would emit the partial prefix and leak
        the token unreplaced.  Anthropic sends ``ping`` between
        ``content_block_delta`` events during streaming lulls.
        """
        from scruxy.providers.anthropic import AnthropicProvider

        class _ViewLikeMap:
            def __init__(self, unscrub: dict[str, str]) -> None:
                self._u = dict(unscrub)
                self._token_version = 1

            @property
            def unscrub_map(self) -> dict[str, str]:
                return dict(self._u)

            def get_pii(self, token: str) -> str | None:
                return self._u.get(token)

        um = {f"REDACTED_PERSON_{i}": f"name{i}" for i in range(1, 13)}
        um["REDACTED_PERSON_1"] = "shahab"
        token_map = _ViewLikeMap(um)

        import json as _json

        def _ev(event: str, data: dict) -> list[bytes]:
            return [
                f"event: {event}".encode("utf-8"),
                b"data: " + _json.dumps(data).encode("utf-8"),
                b"",
            ]

        def _delta(text: str) -> list[bytes]:
            return _ev("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}})

        lines: list[bytes] = []
        lines += _ev("message_start", {"type": "message_start", "message": {"id": "m"}})
        lines += _ev("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
        lines += _delta("Hi ")
        lines += _delta("REDACTED")
        # ping keep-alive lands mid-token (between the two halves).
        lines += _ev("ping", {"type": "ping"})
        lines += _delta("_PERSON_1!")
        lines += _ev("content_block_stop", {"type": "content_block_stop", "index": 0})
        lines += _ev("message_stop", {"type": "message_stop"})

        unscrubber = SSEStreamUnscrubber(AnthropicProvider(), token_map)
        out = b""
        async for chunk in unscrubber.process_sse_stream(_async_lines(lines)):
            out += b"\n" if not chunk else chunk + b"\n"

        decoded = out.decode("utf-8")
        # The split token reassembled and deanonymized despite the ping.
        assert "REDACTED_PERSON_1" not in decoded
        # Reconstruct the visible text from text_delta events.
        text = "".join(
            _json.loads(line[6:])["delta"]["text"]
            for line in decoded.split("\n")
            if line.startswith("data: ") and '"text_delta"' in line
        )
        assert text == "Hi shahab!", f"token not reassembled: {text!r}"
        # ping still passes through, with its event line preserved.
        assert "event: ping" in decoded

    @pytest.mark.asyncio
    async def test_openai_responses_tool_completed_event_is_not_terminal(self) -> None:
        """Regression: OpenAI Responses tool-status events ending in
        ``.completed`` (e.g. ``response.web_search_call.completed``) are NOT
        terminal and must NOT flush the rolling buffer.  A token split across
        ``response.output_text.delta`` events with a tool ``.completed`` event
        in between must still reassemble."""
        import json as _json

        def _parse(d: str):
            obj = _json.loads(d)
            if obj.get("type") == "response.output_text.delta" and isinstance(obj.get("delta"), str):
                return SSETextField(text_value=obj["delta"])
            return None

        def _rebuild(d: str, txt: str) -> str:
            obj = _json.loads(d)
            obj["delta"] = txt
            return _json.dumps(obj)

        token_map = _FakeTokenMap({"REDACTED_PERSON_1": "shahab"})
        provider = _make_provider(parse_fn=_parse, rebuild_fn=_rebuild)
        unscrubber = SSEStreamUnscrubber(provider, token_map)

        lines = [
            'data: {"type":"response.output_text.delta","delta":"Hi REDACTED"}',
            # Non-terminal tool-status event lands mid-token.
            'data: {"type":"response.web_search_call.completed","item_id":"w1"}',
            'data: {"type":"response.output_text.delta","delta":"_PERSON_1!"}',
            'data: {"type":"response.output_text.done","text":"..."}',
            'data: {"type":"response.completed"}',
        ]
        items = await _collect(unscrubber.process_sse_stream(_async_lines(lines)))
        combined = "".join(items)
        assert "REDACTED_PERSON_1" not in combined
        # Reconstruct the visible text from output_text.delta events.
        text = "".join(
            _json.loads(item[6:])["delta"]
            for item in items
            if item.startswith("data: ") and '"response.output_text.delta"' in item
        )
        assert text == "Hi shahab!", f"token not reassembled across tool event: {text!r}"

    @pytest.mark.asyncio
    async def test_anthropic_signature_delta_flushes_thinking_before_signature(self) -> None:
        """Regression: Anthropic ``signature_delta`` terminates a thinking
        block's text, so held thinking text must be flushed BEFORE the
        signature event (never reordered after it)."""
        from scruxy.providers.anthropic import AnthropicProvider

        class _ViewLikeMap:
            def __init__(self, unscrub: dict[str, str]) -> None:
                self._u = dict(unscrub)
                self._token_version = 1

            @property
            def unscrub_map(self) -> dict[str, str]:
                return dict(self._u)

            def get_pii(self, token: str) -> str | None:
                return self._u.get(token)

        um = {f"REDACTED_PERSON_{i}": f"name{i}" for i in range(1, 13)}
        um["REDACTED_PERSON_1"] = "shahab"
        token_map = _ViewLikeMap(um)

        import json as _json

        def _ev(event: str, data: dict) -> list[bytes]:
            return [
                f"event: {event}".encode("utf-8"),
                b"data: " + _json.dumps(data).encode("utf-8"),
                b"",
            ]

        def _think(text: str) -> list[bytes]:
            return _ev("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": text}})

        lines: list[bytes] = []
        lines += _ev("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}})
        lines += _think("Pondering ")
        lines += _think("REDACTED")
        lines += _think("_PERSON_1")
        lines += _ev("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "sig=="}})
        lines += _ev("content_block_stop", {"type": "content_block_stop", "index": 0})

        unscrubber = SSEStreamUnscrubber(AnthropicProvider(), token_map)
        out = b""
        async for chunk in unscrubber.process_sse_stream(_async_lines(lines)):
            out += b"\n" if not chunk else chunk + b"\n"
        decoded = out.decode("utf-8")

        assert "REDACTED_PERSON_1" not in decoded
        assert "shahab" in decoded
        # The flushed thinking text ("shahab") must appear BEFORE the
        # signature_delta, not after it.
        assert decoded.index("shahab") < decoded.index("signature_delta"), (
            "thinking text reordered after its signature"
        )

    @pytest.mark.asyncio
    async def test_non_data_lines_passed_through(self) -> None:
        """Non-data SSE lines (comments, keep-alive) pass through unchanged."""
        token_map = _FakeTokenMap({})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map)
        stream = _async_lines([": comment", "event: ping", "data: hello"])
        result = await _collect(unscrubber.process_sse_stream(stream))

        assert result[0] == ": comment"
        assert result[1] == "event: ping"

    @pytest.mark.asyncio
    async def test_provider_returns_none(self) -> None:
        """When the provider returns None, the line passes through unchanged."""
        token_map = _FakeTokenMap({})
        provider = _make_provider(parse_fn=lambda _: None)

        unscrubber = SSEStreamUnscrubber(provider, token_map)
        stream = _async_lines(["data: [DONE]"])
        result = await _collect(unscrubber.process_sse_stream(stream))

        assert result[0] == "data: [DONE]"

    @pytest.mark.asyncio
    async def test_token_split_across_chunks(self) -> None:
        """A token split across two SSE events is correctly reassembled."""
        token_map = _FakeTokenMap({"REDACTED_EMAIL_1": "bob@test.com"})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map, buffer_size=40)
        # Token "REDACTED_EMAIL_1" split across two events.
        stream = _async_lines([
            "data: Hello REDACTED_EMA",
            "data: IL_1 bye",
        ])
        result = await _collect(unscrubber.process_sse_stream(stream))

        combined = "".join(result)
        assert "bob@test.com" in combined
        assert "REDACTED_EMAIL_1" not in combined

    @pytest.mark.asyncio
    async def test_buffer_flush_at_end(self) -> None:
        """Remaining buffer content is flushed at end of stream."""
        token_map = _FakeTokenMap({"REDACTED_NAME_1": "Carol"})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map, buffer_size=40)
        # The token sits at the end and may be buffered.
        stream = _async_lines(["data: Hi REDACTED_NAME_1"])
        result = await _collect(unscrubber.process_sse_stream(stream))

        combined = "".join(result)
        assert "Carol" in combined
        assert "REDACTED_NAME_1" not in combined

    @pytest.mark.asyncio
    async def test_buffer_flush_yields_sse_event(self) -> None:
        """Flushed buffer content is wrapped in a proper SSE 'data: ' event."""
        token_map = _FakeTokenMap({"REDACTED_NAME_1": "Carol"})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map, buffer_size=40)
        stream = _async_lines(["data: Hi REDACTED_NAME_1"])
        result = await _collect(unscrubber.process_sse_stream(stream))

        # Every yielded chunk must be a valid SSE line (data: prefix)
        # or a non-data passthrough.  The flushed buffer must NOT be raw text.
        for line in result:
            stripped = line.strip()
            if stripped:
                assert stripped.startswith("data: ") or stripped.startswith(":") or stripped.startswith("event:"), (
                    f"Flushed content is not a valid SSE line: {stripped!r}"
                )

    @pytest.mark.asyncio
    async def test_buffer_flush_no_token_map_entries(self) -> None:
        """With no tokens in the map, buffered text at end is still properly emitted."""
        token_map = _FakeTokenMap({})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map, buffer_size=40)
        stream = _async_lines(["data: hello world"])
        result = await _collect(unscrubber.process_sse_stream(stream))

        combined = "".join(result)
        assert "hello world" in combined

    @pytest.mark.asyncio
    async def test_no_tokens_in_stream(self) -> None:
        """SSE stream with no redaction tokens passes through cleanly."""
        token_map = _FakeTokenMap({})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map)
        stream = _async_lines(["data: plain text", "data: more text"])
        result = await _collect(unscrubber.process_sse_stream(stream))

        combined = "".join(result)
        assert "plain text" in combined
        assert "more text" in combined

    @pytest.mark.asyncio
    async def test_multiple_tokens_in_single_event(self) -> None:
        """Multiple complete tokens in one SSE event are all unscrubbed."""
        token_map = _FakeTokenMap({
            "REDACTED_EMAIL_1": "a@b.com",
            "REDACTED_PERSON_1": "Alice",
        })
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map)
        stream = _async_lines(["data: REDACTED_PERSON_1 at REDACTED_EMAIL_1"])
        result = await _collect(unscrubber.process_sse_stream(stream))

        combined = "".join(result)
        assert "Alice" in combined
        assert "a@b.com" in combined
        assert "REDACTED_PERSON_1" not in combined
        assert "REDACTED_EMAIL_1" not in combined

    @pytest.mark.asyncio
    async def test_empty_stream(self) -> None:
        """An empty stream produces no output."""
        token_map = _FakeTokenMap({})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map)
        stream = _async_lines([])
        result = await _collect(unscrubber.process_sse_stream(stream))

        assert result == []


# ---------------------------------------------------------------------------
# Buffer logic unit tests
# ---------------------------------------------------------------------------

class TestBufferLogic:
    """Direct tests for _feed_buffer and _flush_buffer."""

    def test_feed_buffer_no_partial(self) -> None:
        """Text with no partial token potential is returned immediately."""
        token_map = _FakeTokenMap({})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map, buffer_size=40)
        # Short text with no 'R' or 'REDACTED' prefix -- should come through.
        safe = unscrubber._feed_buffer("hello world")
        # Short non-token text: may be fully returned or buffered.
        # After flush, we should get everything back.
        flushed = unscrubber._flush_buffer()
        assert safe + flushed == "hello world"

    def test_feed_buffer_partial_token_held(self) -> None:
        """A partial REDACTED prefix at end of text is held back in the buffer."""
        token_map = _FakeTokenMap({"REDACTED_EMAIL_1": "test@example.com"})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map, buffer_size=40)
        safe = unscrubber._feed_buffer("Hello REDACT")
        # "REDACT" is a partial token prefix -- should be held in buffer.
        assert "REDACT" not in safe
        # Complete the token.
        safe2 = unscrubber._feed_buffer("ED_EMAIL_1 end")
        flushed = unscrubber._flush_buffer()
        combined = safe + safe2 + flushed
        assert "REDACTED_EMAIL_1" in combined
        assert "Hello" in combined

    def test_flush_buffer_returns_remaining(self) -> None:
        """_flush_buffer returns whatever is in the buffer and clears it."""
        token_map = _FakeTokenMap({})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map, buffer_size=40)
        unscrubber.buffer = "leftover"
        flushed = unscrubber._flush_buffer()
        assert flushed == "leftover"
        assert unscrubber.buffer == ""

    def test_flush_empty_buffer(self) -> None:
        """Flushing an empty buffer returns an empty string."""
        token_map = _FakeTokenMap({})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map)
        flushed = unscrubber._flush_buffer()
        assert flushed == ""
        assert unscrubber.buffer == ""

    def test_feed_buffer_long_text_without_token(self) -> None:
        """Text longer than buffer_size with no partial token emits most of it."""
        token_map = _FakeTokenMap({})
        provider = _make_provider()

        unscrubber = SSEStreamUnscrubber(provider, token_map, buffer_size=10)
        text = "a" * 50
        safe = unscrubber._feed_buffer(text)
        flushed = unscrubber._flush_buffer()
        assert safe + flushed == text
