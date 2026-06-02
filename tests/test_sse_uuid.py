"""Tests for SSE deanonymization with non-REDACTED token formats (UUID, arbitrary)."""
from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest

from scruxy.tokenmap.deanonymizer import Deanonymizer, SSEChunkBuffer
from scruxy.tokenmap.token_map import TokenMap
from scruxy.tokenmap.replacer import UuidReplacement


# ---------------------------------------------------------------------------
# Deanonymizer with UUID tokens
# ---------------------------------------------------------------------------


class TestDeanonymizerUuid:
    def test_uuid_token_replaced(self) -> None:
        """Deanonymizer replaces UUID tokens in text."""
        tm = TokenMap(replacements={"GUID": UuidReplacement()})
        token = tm.get_or_create_token("abc-123-def", "GUID")
        text = f"The ID is {token}."
        result = Deanonymizer.deanonymize_text(text, tm)
        assert result == "The ID is abc-123-def."

    def test_mixed_uuid_and_redacted_tokens(self) -> None:
        """Deanonymizer handles a mix of UUID and REDACTED tokens."""
        tm = TokenMap(replacements={"GUID": UuidReplacement()})
        uuid_token = tm.get_or_create_token("abc-123", "GUID")
        tm.get_or_create_token("john@co.com", "EMAIL")  # default
        text = f"User {uuid_token} email REDACTED_EMAIL_1"
        result = Deanonymizer.deanonymize_text(text, tm)
        assert result == "User abc-123 email john@co.com"

    def test_unknown_token_left_as_is(self) -> None:
        tm = TokenMap()
        text = "Token UNKNOWN_99 stays."
        result = Deanonymizer.deanonymize_text(text, tm)
        assert result == text


# ---------------------------------------------------------------------------
# SSEChunkBuffer with UUID tokens
# ---------------------------------------------------------------------------


class TestSSEChunkBufferUuid:
    def test_uuid_token_in_single_chunk(self) -> None:
        """A complete UUID token in a single chunk is deanonymized."""
        tm = TokenMap(replacements={"GUID": UuidReplacement()})
        token = tm.get_or_create_token("my-guid-value", "GUID")
        buf = SSEChunkBuffer(tm)
        result = buf.feed(f"ID: {token} done") + buf.flush()
        assert "my-guid-value" in result
        assert token not in result

    def test_uuid_token_split_across_chunks(self) -> None:
        """A UUID token split across two chunks is reassembled and deanonymized."""
        tm = TokenMap(replacements={"GUID": UuidReplacement()})
        token = tm.get_or_create_token("my-guid-value", "GUID")
        # Split the UUID token roughly in the middle.
        mid = len(token) // 2
        chunk1 = f"ID: {token[:mid]}"
        chunk2 = f"{token[mid:]} done"
        buf = SSEChunkBuffer(tm)
        part1 = buf.feed(chunk1)
        part2 = buf.feed(chunk2)
        part3 = buf.flush()
        combined = part1 + part2 + part3
        assert "my-guid-value" in combined
        assert token not in combined

    def test_mixed_token_types_in_stream(self) -> None:
        """Both UUID and REDACTED tokens in a stream are deanonymized."""
        tm = TokenMap(replacements={"GUID": UuidReplacement()})
        uuid_token = tm.get_or_create_token("guid-val", "GUID")
        tm.get_or_create_token("alice@co.com", "EMAIL")
        buf = SSEChunkBuffer(tm)
        text = f"{uuid_token} sent to REDACTED_EMAIL_1"
        result = buf.feed(text) + buf.flush()
        assert "guid-val" in result
        assert "alice@co.com" in result
        assert uuid_token not in result
        assert "REDACTED_EMAIL_1" not in result

    def test_rebuild_trie_picks_up_new_uuid_tokens(self) -> None:
        tm = TokenMap(replacements={"GUID": UuidReplacement()})
        buf = SSEChunkBuffer(tm)
        # Add token after buffer creation.
        token = tm.get_or_create_token("late-guid", "GUID")
        buf.rebuild_trie()
        result = buf.feed(token) + buf.flush()
        assert result == "late-guid"

    def test_arbitrary_script_token(self) -> None:
        """Arbitrary string tokens (like from scripts) are handled."""
        tm = TokenMap()
        # Manually inject a non-REDACTED token.
        tm._scrub["John Doe"] = "EMPLOYEE_42"
        tm._unscrub["EMPLOYEE_42"] = "John Doe"
        buf = SSEChunkBuffer(tm)
        result = buf.feed("Name: EMPLOYEE_42 here") + buf.flush()
        assert "John Doe" in result
        assert "EMPLOYEE_42" not in result


# ---------------------------------------------------------------------------
# SSEStreamUnscrubber with UUID tokens
# ---------------------------------------------------------------------------


class TestSSEStreamUnscrubbUuid:
    """Tests for SSEStreamUnscrubber with non-REDACTED token formats."""

    @pytest.fixture
    def _setup(self):
        """Provide a minimal SSE provider mock and helpers."""
        from scruxy.scrubber.sse_stream_unscrubber import SSEStreamUnscrubber

        class _FakeTokenMap:
            def __init__(self, unscrub: dict[str, str]) -> None:
                self.unscrub = unscrub
                self.unscrub_map = unscrub

        class _MockProvider:
            def parse_sse_event(self, event_data):
                from scruxy.providers.base import SSETextField
                return SSETextField(text_value=event_data)

            def rebuild_sse_event(self, event_data, unscrubbed_text):
                return unscrubbed_text

        return SSEStreamUnscrubber, _FakeTokenMap, _MockProvider

    @staticmethod
    async def _async_lines(lines: list[str]) -> AsyncGenerator[bytes, None]:
        for line in lines:
            yield line.encode("utf-8")

    @staticmethod
    async def _collect(gen: AsyncGenerator[bytes, None]) -> list[str]:
        result = []
        async for item in gen:
            result.append(item.decode("utf-8"))
        return result

    @pytest.mark.asyncio
    async def test_uuid_token_in_sse_stream(self, _setup) -> None:
        SSEStreamUnscrubber, _FakeTokenMap, _MockProvider = _setup
        uuid_token = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        token_map = _FakeTokenMap({uuid_token: "secret-guid"})
        provider = _MockProvider()
        unscrubber = SSEStreamUnscrubber(provider, token_map)
        stream = self._async_lines([f"data: ID is {uuid_token}"])
        result = await self._collect(unscrubber.process_sse_stream(stream))
        combined = "".join(result)
        assert "secret-guid" in combined
        assert uuid_token not in combined

    @pytest.mark.asyncio
    async def test_uuid_token_split_across_sse_events(self, _setup) -> None:
        SSEStreamUnscrubber, _FakeTokenMap, _MockProvider = _setup
        uuid_token = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        token_map = _FakeTokenMap({uuid_token: "my-secret"})
        provider = _MockProvider()
        unscrubber = SSEStreamUnscrubber(provider, token_map, buffer_size=40)
        mid = len(uuid_token) // 2
        stream = self._async_lines([
            f"data: {uuid_token[:mid]}",
            f"data: {uuid_token[mid:]} end",
        ])
        result = await self._collect(unscrubber.process_sse_stream(stream))
        combined = "".join(result)
        assert "my-secret" in combined
        assert uuid_token not in combined

    @pytest.mark.asyncio
    async def test_mixed_token_types_in_sse(self, _setup) -> None:
        SSEStreamUnscrubber, _FakeTokenMap, _MockProvider = _setup
        token_map = _FakeTokenMap({
            "a1b2-uuid": "guid-pii",
            "REDACTED_EMAIL_1": "alice@co.com",
        })
        provider = _MockProvider()
        unscrubber = SSEStreamUnscrubber(provider, token_map)
        stream = self._async_lines(["data: a1b2-uuid emailed REDACTED_EMAIL_1"])
        result = await self._collect(unscrubber.process_sse_stream(stream))
        combined = "".join(result)
        assert "guid-pii" in combined
        assert "alice@co.com" in combined
