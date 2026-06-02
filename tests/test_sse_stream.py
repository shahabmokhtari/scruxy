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
