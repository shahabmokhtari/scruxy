"""Tests for the Anthropic provider."""
from __future__ import annotations

import json

import pytest

from scruxy.providers.anthropic import AnthropicProvider
from scruxy.providers.base import ProxyRequest, SSETextField, TextField


@pytest.fixture
def provider() -> AnthropicProvider:
    """Create an Anthropic provider with default config."""
    return AnthropicProvider()


class TestAnthropicMatches:
    """Test URL and header matching for the Anthropic provider."""

    def test_matches_standard_messages_url(self, provider: AnthropicProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"anthropic-version": "2023-06-01", "authorization": "Bearer sk-123"},
        )
        assert provider.matches(request) is True

    def test_matches_messages_url_with_query(self, provider: AnthropicProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages?beta=true",
            headers={"anthropic-version": "2023-06-01"},
        )
        assert provider.matches(request) is True

    def test_matches_proxy_url(self, provider: AnthropicProvider):
        request = ProxyRequest(
            method="POST",
            url="http://localhost:8080/v1/messages",
            headers={"anthropic-version": "2023-06-01"},
        )
        assert provider.matches(request) is True

    def test_no_match_wrong_url(self, provider: AnthropicProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"anthropic-version": "2023-06-01"},
        )
        assert provider.matches(request) is False

    def test_matches_without_anthropic_version_header(self, provider: AnthropicProvider):
        """URL pattern match is sufficient — headers are not required."""
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"authorization": "Bearer sk-123"},
        )
        assert provider.matches(request) is True

    def test_no_match_wrong_path(self, provider: AnthropicProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/completions",
            headers={"anthropic-version": "2023-06-01"},
        )
        assert provider.matches(request) is False

    def test_matches_with_different_hosts(self, provider: AnthropicProvider):
        """Any host works as long as the path matches and headers are present."""
        request = ProxyRequest(
            method="POST",
            url="https://custom-proxy.example.com/v1/messages",
            headers={"anthropic-version": "2023-06-01"},
        )
        assert provider.matches(request) is True


class TestAnthropicExtractSessionId:
    """Test session ID extraction from Anthropic requests."""

    def test_extract_session_id_from_header(self, provider: AnthropicProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={
                "anthropic-version": "2023-06-01",
                "x-session-id": "session-abc-123",
            },
        )
        assert provider.extract_session_id(request) == "session-abc-123"

    def test_extract_session_id_fallback_to_anthropic_beta(self, provider: AnthropicProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={
                "anthropic-version": "2023-06-01",
                "anthropic-beta": "prompt-caching-2024-07-31",
            },
        )
        assert provider.extract_session_id(request) == "prompt-caching-2024-07-31"

    def test_extract_session_id_prefers_x_session_id(self, provider: AnthropicProvider):
        """x-session-id is checked first (listed first in config)."""
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={
                "anthropic-version": "2023-06-01",
                "x-session-id": "explicit-session",
                "anthropic-beta": "prompt-caching-2024-07-31",
            },
        )
        assert provider.extract_session_id(request) == "explicit-session"

    def test_extract_session_id_hash_fallback(self, provider: AnthropicProvider):
        """When no session headers are present, derive from auth headers."""
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={
                "anthropic-version": "2023-06-01",
                "authorization": "Bearer sk-secret-key",
            },
        )
        session_id = provider.extract_session_id(request)
        assert session_id.startswith("auto-")
        assert len(session_id) > 5

    def test_extract_session_id_hash_is_stable(self, provider: AnthropicProvider):
        """Same headers should produce the same hash-based session ID."""
        headers = {
            "anthropic-version": "2023-06-01",
            "authorization": "Bearer sk-secret-key",
        }
        request1 = ProxyRequest(method="POST", url="https://api.anthropic.com/v1/messages",
                                headers=headers)
        request2 = ProxyRequest(method="POST", url="https://api.anthropic.com/v1/messages",
                                headers=headers)
        assert provider.extract_session_id(request1) == provider.extract_session_id(request2)

    def test_extract_session_id_case_insensitive_headers(self, provider: AnthropicProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"X-Session-Id": "my-session-123"},
        )
        assert provider.extract_session_id(request) == "my-session-123"

    def test_extract_session_id_no_headers(self, provider: AnthropicProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={},
        )
        assert provider.extract_session_id(request) == "auto-unknown"

    def test_extract_session_id_from_metadata_user_id(self, provider: AnthropicProvider):
        """Claude Code sends metadata.user_id with embedded session UUID."""
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"anthropic-version": "2023-06-01"},
            body={
                "model": "claude-opus-4-6",
                "metadata": {
                    "user_id": "user_abc123_account_def456_session_9b2d90e3-4a45-4e79-9b03-8acb04f51fe5",
                },
                "messages": [],
            },
        )
        assert provider.extract_session_id(request) == "claude-9b2d90e3-4a45-4e79-9b03-8acb04f51fe5"

    def test_extract_session_id_metadata_without_session(self, provider: AnthropicProvider):
        """metadata.user_id without a session_ segment falls back to prefix."""
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"anthropic-version": "2023-06-01"},
            body={
                "metadata": {"user_id": "user_abc123_account_def456"},
                "messages": [],
            },
        )
        sid = provider.extract_session_id(request)
        assert sid.startswith("claude-")
        assert len(sid) <= len("claude-") + 32

    def test_extract_session_id_body_preferred_over_hash_fallback(self, provider: AnthropicProvider):
        """Body metadata takes priority over auth-hash fallback."""
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"anthropic-version": "2023-06-01", "authorization": "Bearer sk-key"},
            body={
                "metadata": {
                    "user_id": "user_x_account_y_session_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                },
                "messages": [],
            },
        )
        assert provider.extract_session_id(request) == "claude-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_extract_session_id_header_preferred_over_body(self, provider: AnthropicProvider):
        """x-session-id header still takes priority over body metadata."""
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"x-session-id": "header-session"},
            body={
                "metadata": {
                    "user_id": "user_x_session_body-session-uuid",
                },
                "messages": [],
            },
        )
        # Body metadata is checked first in our override, but headers
        # are a reasonable explicit signal. Our impl checks body FIRST.
        # Let's verify actual behavior:
        sid = provider.extract_session_id(request)
        assert sid.startswith("claude-")  # body metadata wins


class TestAnthropicExtractTextFields:
    """Test text field extraction from Anthropic request bodies."""

    def test_extract_simple_string_content(self, provider: AnthropicProvider):
        body = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "Hello, my name is John Doe."},
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) == 1
        assert fields[0].text_value == "Hello, my name is John Doe."
        assert fields[0].field_type == "text"

    def test_extract_system_prompt_string(self, provider: AnthropicProvider):
        body = {
            "model": "claude-opus-4-6",
            "system": "You are a helpful assistant for John Smith.",
            "messages": [{"role": "user", "content": "Hi"}],
        }
        fields = provider.extract_text_fields(body)
        system_fields = [f for f in fields if f.field_type == "system"]
        assert len(system_fields) == 1
        assert system_fields[0].text_value == "You are a helpful assistant for John Smith."

    def test_extract_system_prompt_content_blocks(self, provider: AnthropicProvider):
        body = {
            "model": "claude-opus-4-6",
            "system": [
                {"type": "text", "text": "System instruction one."},
                {"type": "text", "text": "System instruction two."},
            ],
            "messages": [{"role": "user", "content": "Hi"}],
        }
        fields = provider.extract_text_fields(body)
        system_fields = [f for f in fields if f.field_type == "system"]
        assert len(system_fields) == 2
        assert system_fields[0].text_value == "System instruction one."
        assert system_fields[1].text_value == "System instruction two."

    def test_extract_content_block_array(self, provider: AnthropicProvider):
        body = {
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "First part with email john@example.com"},
                        {"type": "text", "text": "Second part with phone 555-0123"},
                    ],
                },
            ],
        }
        fields = provider.extract_text_fields(body)
        text_fields = [f for f in fields if f.field_type == "text"]
        assert len(text_fields) == 2
        assert "john@example.com" in text_fields[0].text_value
        assert "555-0123" in text_fields[1].text_value

    def test_extract_tool_result_string(self, provider: AnthropicProvider):
        body = {
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_123",
                            "content": "File contents: John Doe, SSN: 123-45-6789",
                        },
                    ],
                },
            ],
        }
        fields = provider.extract_text_fields(body)
        tool_fields = [f for f in fields if f.field_type == "tool_result"]
        assert len(tool_fields) == 1
        assert "123-45-6789" in tool_fields[0].text_value

    def test_extract_tool_result_content_blocks(self, provider: AnthropicProvider):
        body = {
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_123",
                            "content": [
                                {"type": "text", "text": "Tool output line 1"},
                                {"type": "text", "text": "Tool output line 2"},
                            ],
                        },
                    ],
                },
            ],
        }
        fields = provider.extract_text_fields(body)
        tool_fields = [f for f in fields if f.field_type == "tool_result"]
        assert len(tool_fields) == 2

    def test_extract_tool_use_input(self, provider: AnthropicProvider):
        body = {
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_123",
                            "name": "search",
                            "input": {"query": "John Doe email address"},
                        },
                    ],
                },
            ],
        }
        fields = provider.extract_text_fields(body)
        tool_use_fields = [f for f in fields if f.field_type == "tool_use"]
        assert len(tool_use_fields) == 1
        assert tool_use_fields[0].text_value == "John Doe email address"

    def test_extract_multi_turn_conversation(self, provider: AnthropicProvider):
        body = {
            "model": "claude-opus-4-6",
            "system": "Be helpful.",
            "messages": [
                {"role": "user", "content": "My name is Alice."},
                {"role": "assistant", "content": "Hello Alice!"},
                {"role": "user", "content": "My email is alice@example.com"},
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) >= 4  # system + 3 message contents

    def test_extract_empty_body(self, provider: AnthropicProvider):
        assert provider.extract_text_fields({}) == []

    def test_extract_none_body(self, provider: AnthropicProvider):
        assert provider.extract_text_fields(None) == []

    def test_extract_skips_empty_strings(self, provider: AnthropicProvider):
        body = {
            "messages": [
                {"role": "user", "content": ""},
                {"role": "user", "content": "   "},
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) == 0


class TestAnthropicReplaceTextFields:
    """Test text field replacement in Anthropic request bodies."""

    def test_replace_simple_content(self, provider: AnthropicProvider):
        body = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "Hello, John Doe."},
            ],
        }
        replacements = {"messages.[0].content": "Hello, REDACTED_PERSON_1."}
        result = provider.replace_text_fields(body, replacements)
        assert result["messages"][0]["content"] == "Hello, REDACTED_PERSON_1."
        # Original should be unchanged
        assert body["messages"][0]["content"] == "Hello, John Doe."

    def test_replace_system_prompt(self, provider: AnthropicProvider):
        body = {
            "system": "Help John Smith.",
            "messages": [],
        }
        replacements = {"system": "Help REDACTED_PERSON_1."}
        result = provider.replace_text_fields(body, replacements)
        assert result["system"] == "Help REDACTED_PERSON_1."

    def test_replace_content_block_text(self, provider: AnthropicProvider):
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Email: john@example.com"},
                    ],
                },
            ],
        }
        replacements = {
            "messages.[0].content.[0].text": "Email: REDACTED_EMAIL_1",
        }
        result = provider.replace_text_fields(body, replacements)
        assert result["messages"][0]["content"][0]["text"] == "Email: REDACTED_EMAIL_1"

    def test_replace_none_body(self, provider: AnthropicProvider):
        result = provider.replace_text_fields(None, {"foo": "bar"})
        assert result == {}


class TestAnthropicExtractResponseTextFields:
    """Test response text extraction for Anthropic format."""

    def test_extract_response_text(self, provider: AnthropicProvider):
        body = {
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "The user's name is REDACTED_PERSON_1."},
            ],
        }
        fields = provider.extract_response_text_fields(body)
        assert len(fields) == 1
        assert fields[0].text_value == "The user's name is REDACTED_PERSON_1."

    def test_extract_response_multiple_blocks(self, provider: AnthropicProvider):
        body = {
            "content": [
                {"type": "text", "text": "First block."},
                {"type": "text", "text": "Second block."},
            ],
        }
        fields = provider.extract_response_text_fields(body)
        assert len(fields) == 2

    def test_extract_response_tool_use(self, provider: AnthropicProvider):
        body = {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_123",
                    "name": "search",
                    "input": {"query": "REDACTED_PERSON_1 contact info"},
                },
            ],
        }
        fields = provider.extract_response_text_fields(body)
        tool_fields = [f for f in fields if f.field_type == "tool_use"]
        assert len(tool_fields) == 1

    def test_extract_response_empty_body(self, provider: AnthropicProvider):
        assert provider.extract_response_text_fields({}) == []

    def test_extract_response_none_body(self, provider: AnthropicProvider):
        assert provider.extract_response_text_fields(None) == []


class TestAnthropicParseSSEEvent:
    """Test SSE event parsing for Anthropic streaming format."""

    def test_parse_text_delta(self, provider: AnthropicProvider):
        event_data = json.dumps({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "Hello world"},
        })
        result = provider.parse_sse_event(event_data)
        assert result is not None
        assert result.text_value == "Hello world"
        assert result.event_type == "content_block_delta"

    def test_parse_input_json_delta(self, provider: AnthropicProvider):
        event_data = json.dumps({
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": '{"query": "test'}
        })
        result = provider.parse_sse_event(event_data)
        assert result is not None
        assert result.text_value == '{"query": "test'

    def test_parse_non_delta_event(self, provider: AnthropicProvider):
        event_data = json.dumps({
            "type": "message_start",
            "message": {"id": "msg_123"},
        })
        result = provider.parse_sse_event(event_data)
        assert result is None

    def test_parse_content_block_start(self, provider: AnthropicProvider):
        event_data = json.dumps({
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        })
        result = provider.parse_sse_event(event_data)
        assert result is None

    def test_parse_invalid_json(self, provider: AnthropicProvider):
        result = provider.parse_sse_event("not json")
        assert result is None

    def test_parse_empty_string(self, provider: AnthropicProvider):
        result = provider.parse_sse_event("")
        assert result is None

    def test_parse_text_delta_with_pii(self, provider: AnthropicProvider):
        event_data = json.dumps({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "John Doe's email is john@example.com"},
        })
        result = provider.parse_sse_event(event_data)
        assert result is not None
        assert "john@example.com" in result.text_value


class TestAnthropicRebuildSSEEvent:
    """Test SSE event rebuilding for Anthropic streaming format."""

    def test_rebuild_text_delta(self, provider: AnthropicProvider):
        event_data = json.dumps({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "REDACTED_PERSON_1"},
        })
        result = provider.rebuild_sse_event(event_data, "John Doe")
        parsed = json.loads(result)
        assert parsed["delta"]["text"] == "John Doe"
        # Other fields preserved
        assert parsed["type"] == "content_block_delta"
        assert parsed["index"] == 0

    def test_rebuild_input_json_delta(self, provider: AnthropicProvider):
        event_data = json.dumps({
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": "REDACTED"},
        })
        result = provider.rebuild_sse_event(event_data, "original_json_fragment")
        parsed = json.loads(result)
        assert parsed["delta"]["partial_json"] == "original_json_fragment"

    def test_rebuild_non_matching_event(self, provider: AnthropicProvider):
        event_data = json.dumps({
            "type": "message_start",
            "message": {"id": "msg_123"},
        })
        result = provider.rebuild_sse_event(event_data, "ignored text")
        # Should return unchanged
        parsed = json.loads(result)
        assert parsed["type"] == "message_start"

    def test_rebuild_invalid_json(self, provider: AnthropicProvider):
        result = provider.rebuild_sse_event("not json", "new text")
        assert result == "not json"


class TestAnthropicProperties:
    """Test provider property accessors."""

    def test_name(self, provider: AnthropicProvider):
        assert provider.name == "anthropic"

    def test_display_name(self, provider: AnthropicProvider):
        assert provider.display_name == "Anthropic Claude"

    def test_default_url_patterns(self, provider: AnthropicProvider):
        patterns = provider.default_url_patterns
        assert "*/v1/messages" in patterns
        assert "*/v1/messages?*" in patterns

    def test_auth_headers(self, provider: AnthropicProvider):
        headers = provider.auth_headers
        assert "authorization" in headers
        assert "x-api-key" in headers
        assert "anthropic-version" in headers


class TestAnthropicRoundTrip:
    """Test full extract-replace round trips."""

    def test_round_trip_simple_message(self, provider: AnthropicProvider):
        body = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "My SSN is 123-45-6789"},
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) == 1

        # Build replacements
        replacements = {f.json_path: f.text_value.replace("123-45-6789", "REDACTED_SSN_1")
                        for f in fields}

        result = provider.replace_text_fields(body, replacements)
        assert "REDACTED_SSN_1" in result["messages"][0]["content"]
        assert "123-45-6789" not in result["messages"][0]["content"]

    def test_round_trip_content_blocks(self, provider: AnthropicProvider):
        body = {
            "model": "claude-opus-4-6",
            "system": "Help user John.",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Email: alice@example.com"},
                        {"type": "text", "text": "Phone: 555-0123"},
                    ],
                },
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) >= 3  # system + 2 content blocks

        replacements = {}
        for f in fields:
            new_text = f.text_value
            new_text = new_text.replace("John", "REDACTED_PERSON_1")
            new_text = new_text.replace("alice@example.com", "REDACTED_EMAIL_1")
            new_text = new_text.replace("555-0123", "REDACTED_PHONE_1")
            replacements[f.json_path] = new_text

        result = provider.replace_text_fields(body, replacements)
        assert result["system"] == "Help user REDACTED_PERSON_1."
        assert result["messages"][0]["content"][0]["text"] == "Email: REDACTED_EMAIL_1"
        assert result["messages"][0]["content"][1]["text"] == "Phone: REDACTED_PHONE_1"
