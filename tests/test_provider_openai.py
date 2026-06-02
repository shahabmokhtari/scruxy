"""Tests for the OpenAI-compatible provider."""
from __future__ import annotations

import json

import pytest

from scruxy.providers.base import ProxyRequest, SSETextField, TextField
from scruxy.providers.openai import OpenAIProvider


@pytest.fixture
def provider() -> OpenAIProvider:
    """Create an OpenAI provider with default config."""
    return OpenAIProvider()


class TestOpenAIMatches:
    """Test URL and header matching for the OpenAI provider."""

    def test_matches_standard_completions_url(self, provider: OpenAIProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
        )
        assert provider.matches(request) is True

    def test_matches_short_completions_url(self, provider: OpenAIProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/chat/completions",
            headers={"authorization": "Bearer sk-123"},
        )
        assert provider.matches(request) is True

    def test_matches_azure_url(self, provider: OpenAIProvider):
        request = ProxyRequest(
            method="POST",
            url="https://myresource.openai.azure.com/openai/deployments/gpt-4/chat/completions?api-version=2024-02-15",
            headers={"authorization": "Bearer key"},
        )
        assert provider.matches(request) is True

    def test_matches_proxy_url(self, provider: OpenAIProvider):
        request = ProxyRequest(
            method="POST",
            url="http://localhost:8080/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
        )
        assert provider.matches(request) is True

    def test_no_match_wrong_url(self, provider: OpenAIProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"authorization": "Bearer sk-123"},
        )
        assert provider.matches(request) is False

    def test_matches_without_auth_header(self, provider: OpenAIProvider):
        """URL pattern match is sufficient — headers are not required."""
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"content-type": "application/json"},
        )
        assert provider.matches(request) is True

    def test_no_match_wrong_endpoint(self, provider: OpenAIProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/embeddings",
            headers={"authorization": "Bearer sk-123"},
        )
        assert provider.matches(request) is False

    def test_matches_copilot_url(self, provider: OpenAIProvider):
        """GitHub Copilot uses the same OpenAI-compatible format."""
        request = ProxyRequest(
            method="POST",
            url="https://copilot-proxy.githubusercontent.com/v1/chat/completions",
            headers={"authorization": "Bearer ghu_xxx"},
        )
        assert provider.matches(request) is True


class TestOpenAIExtractSessionId:
    """Test session ID extraction from OpenAI requests."""

    def test_extract_from_x_request_id(self, provider: OpenAIProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={
                "authorization": "Bearer sk-123",
                "x-request-id": "req-abc-123",
            },
        )
        assert provider.extract_session_id(request) == "req-abc-123"

    def test_extract_from_x_session_id(self, provider: OpenAIProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={
                "authorization": "Bearer sk-123",
                "x-session-id": "session-xyz",
            },
        )
        assert provider.extract_session_id(request) == "session-xyz"

    def test_extract_from_openai_conversation_id(self, provider: OpenAIProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={
                "authorization": "Bearer sk-123",
                "openai-conversation-id": "conv-456",
            },
        )
        assert provider.extract_session_id(request) == "conv-456"

    def test_extract_prefers_x_request_id(self, provider: OpenAIProvider):
        """x-request-id is first in the config, so it takes priority."""
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={
                "authorization": "Bearer sk-123",
                "x-request-id": "req-first",
                "x-session-id": "session-second",
                "openai-conversation-id": "conv-third",
            },
        )
        assert provider.extract_session_id(request) == "req-first"

    def test_extract_auth_hash_fallback(self, provider: OpenAIProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-secret"},
        )
        session_id = provider.extract_session_id(request)
        assert session_id.startswith("auto-")

    def test_extract_auth_hash_is_stable(self, provider: OpenAIProvider):
        headers = {"authorization": "Bearer sk-secret"}
        req1 = ProxyRequest(method="POST", url="https://api.openai.com/v1/chat/completions",
                            headers=headers)
        req2 = ProxyRequest(method="POST", url="https://api.openai.com/v1/chat/completions",
                            headers=headers)
        assert provider.extract_session_id(req1) == provider.extract_session_id(req2)

    def test_extract_no_headers(self, provider: OpenAIProvider):
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={},
        )
        assert provider.extract_session_id(request) == "auto-unknown"

    def test_extract_session_id_from_body_user_field(self, provider: OpenAIProvider):
        """Copilot sends a user field in the body with a machine hash."""
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
            body={
                "model": "gpt-4",
                "user": "machine-hash-abc123def456",
                "messages": [],
            },
        )
        sid = provider.extract_session_id(request)
        assert sid.startswith("copilot-")
        assert len(sid) > len("copilot-")

    def test_extract_session_id_body_user_stable(self, provider: OpenAIProvider):
        """Same user field produces the same session ID."""
        body = {"model": "gpt-4", "user": "stable-user-id", "messages": []}
        req1 = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
            body=body,
        )
        req2 = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
            body=body,
        )
        assert provider.extract_session_id(req1) == provider.extract_session_id(req2)

    def test_extract_session_id_header_preferred_over_body(self, provider: OpenAIProvider):
        """Explicit session header takes priority over body user field."""
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={
                "authorization": "Bearer sk-123",
                "x-request-id": "explicit-id",
            },
            body={"model": "gpt-4", "user": "machine-hash", "messages": []},
        )
        assert provider.extract_session_id(request) == "explicit-id"

    def test_extract_session_id_body_fallback_no_header(self, provider: OpenAIProvider):
        """Body user field is used when no session headers are present."""
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={},
            body={"model": "gpt-4", "user": "copilot-machine-xyz", "messages": []},
        )
        sid = provider.extract_session_id(request)
        assert sid.startswith("copilot-")


class TestOpenAIExtractTextFields:
    """Test text field extraction from OpenAI request bodies."""

    def test_extract_simple_string_content(self, provider: OpenAIProvider):
        body = {
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "Hello, my name is John Doe."},
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) == 1
        assert fields[0].text_value == "Hello, my name is John Doe."
        assert fields[0].field_type == "text"

    def test_extract_system_message(self, provider: OpenAIProvider):
        body = {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You help users with PII."},
                {"role": "user", "content": "My email is test@example.com"},
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) == 2
        texts = [f.text_value for f in fields]
        assert "You help users with PII." in texts
        assert "My email is test@example.com" in texts

    def test_extract_content_parts_array(self, provider: OpenAIProvider):
        body = {
            "model": "gpt-4-vision-preview",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "What's in this image? Name: Alice Smith"},
                        {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}},
                    ],
                },
            ],
        }
        fields = provider.extract_text_fields(body)
        text_fields = [f for f in fields if f.field_type == "text"]
        assert len(text_fields) == 1
        assert "Alice Smith" in text_fields[0].text_value

    def test_extract_tool_calls(self, provider: OpenAIProvider):
        body = {
            "model": "gpt-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_abc",
                            "type": "function",
                            "function": {
                                "name": "search",
                                "arguments": '{"query": "John Doe phone number"}',
                            },
                        },
                    ],
                },
            ],
        }
        fields = provider.extract_text_fields(body)
        tc_fields = [f for f in fields if f.field_type == "tool_call"]
        assert len(tc_fields) == 1
        assert "John Doe" in tc_fields[0].text_value

    def test_extract_multi_turn_conversation(self, provider: OpenAIProvider):
        body = {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "Be helpful."},
                {"role": "user", "content": "I'm Alice."},
                {"role": "assistant", "content": "Hello Alice!"},
                {"role": "user", "content": "My email is alice@test.com"},
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) == 4

    def test_extract_empty_body(self, provider: OpenAIProvider):
        assert provider.extract_text_fields({}) == []

    def test_extract_none_body(self, provider: OpenAIProvider):
        assert provider.extract_text_fields(None) == []

    def test_extract_skips_empty_strings(self, provider: OpenAIProvider):
        body = {
            "messages": [
                {"role": "user", "content": ""},
                {"role": "user", "content": "   "},
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) == 0

    def test_extract_skips_none_content(self, provider: OpenAIProvider):
        body = {
            "messages": [
                {"role": "assistant", "content": None},
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) == 0


class TestOpenAIReplaceTextFields:
    """Test text field replacement in OpenAI request bodies."""

    def test_replace_simple_content(self, provider: OpenAIProvider):
        body = {
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "Hello, John Doe."},
            ],
        }
        replacements = {"messages.[0].content": "Hello, REDACTED_PERSON_1."}
        result = provider.replace_text_fields(body, replacements)
        assert result["messages"][0]["content"] == "Hello, REDACTED_PERSON_1."
        # Original unchanged
        assert body["messages"][0]["content"] == "Hello, John Doe."

    def test_replace_content_part_text(self, provider: OpenAIProvider):
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

    def test_replace_tool_call_arguments(self, provider: OpenAIProvider):
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "search",
                                "arguments": '{"name": "John Doe"}',
                            },
                        },
                    ],
                },
            ],
        }
        replacements = {
            "messages.[0].tool_calls.[0].function.arguments":
                '{"name": "REDACTED_PERSON_1"}',
        }
        result = provider.replace_text_fields(body, replacements)
        assert result["messages"][0]["tool_calls"][0]["function"]["arguments"] == \
            '{"name": "REDACTED_PERSON_1"}'

    def test_replace_none_body(self, provider: OpenAIProvider):
        result = provider.replace_text_fields(None, {"foo": "bar"})
        assert result == {}


class TestOpenAIExtractResponseTextFields:
    """Test response text extraction for OpenAI format."""

    def test_extract_response_content(self, provider: OpenAIProvider):
        body = {
            "id": "chatcmpl-123",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "The user's name is REDACTED_PERSON_1.",
                    },
                    "finish_reason": "stop",
                },
            ],
        }
        fields = provider.extract_response_text_fields(body)
        assert len(fields) == 1
        assert fields[0].text_value == "The user's name is REDACTED_PERSON_1."

    def test_extract_response_multiple_choices(self, provider: OpenAIProvider):
        body = {
            "choices": [
                {"index": 0, "message": {"content": "Response A"}},
                {"index": 1, "message": {"content": "Response B"}},
            ],
        }
        fields = provider.extract_response_text_fields(body)
        assert len(fields) == 2

    def test_extract_response_tool_calls(self, provider: OpenAIProvider):
        body = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_abc",
                                "type": "function",
                                "function": {
                                    "name": "lookup",
                                    "arguments": '{"email": "REDACTED_EMAIL_1"}',
                                },
                            },
                        ],
                    },
                },
            ],
        }
        fields = provider.extract_response_text_fields(body)
        tc_fields = [f for f in fields if f.field_type == "tool_call"]
        assert len(tc_fields) == 1

    def test_extract_response_empty_body(self, provider: OpenAIProvider):
        assert provider.extract_response_text_fields({}) == []

    def test_extract_response_none_body(self, provider: OpenAIProvider):
        assert provider.extract_response_text_fields(None) == []


class TestOpenAIParseSSEEvent:
    """Test SSE event parsing for OpenAI streaming format."""

    def test_parse_text_delta(self, provider: OpenAIProvider):
        event_data = json.dumps({
            "id": "chatcmpl-123",
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": "Hello world"},
                    "finish_reason": None,
                },
            ],
        })
        result = provider.parse_sse_event(event_data)
        assert result is not None
        assert result.text_value == "Hello world"

    def test_parse_tool_delta(self, provider: OpenAIProvider):
        event_data = json.dumps({
            "id": "chatcmpl-123",
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "function": {"arguments": '{"query":'},
                            },
                        ],
                    },
                    "finish_reason": None,
                },
            ],
        })
        result = provider.parse_sse_event(event_data)
        assert result is not None
        assert result.text_value == '{"query":'

    def test_parse_done_event(self, provider: OpenAIProvider):
        result = provider.parse_sse_event("[DONE]")
        assert result is None

    def test_parse_empty_delta(self, provider: OpenAIProvider):
        event_data = json.dumps({
            "id": "chatcmpl-123",
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop",
                },
            ],
        })
        result = provider.parse_sse_event(event_data)
        assert result is None

    def test_parse_invalid_json(self, provider: OpenAIProvider):
        result = provider.parse_sse_event("not json")
        assert result is None

    def test_parse_delta_with_pii(self, provider: OpenAIProvider):
        event_data = json.dumps({
            "choices": [
                {"delta": {"content": "John's email is john@test.com"}},
            ],
        })
        result = provider.parse_sse_event(event_data)
        assert result is not None
        assert "john@test.com" in result.text_value


class TestOpenAIRebuildSSEEvent:
    """Test SSE event rebuilding for OpenAI streaming format."""

    def test_rebuild_text_delta(self, provider: OpenAIProvider):
        event_data = json.dumps({
            "id": "chatcmpl-123",
            "choices": [
                {"index": 0, "delta": {"content": "REDACTED_PERSON_1"}},
            ],
        })
        result = provider.rebuild_sse_event(event_data, "John Doe")
        parsed = json.loads(result)
        assert parsed["choices"][0]["delta"]["content"] == "John Doe"
        assert parsed["id"] == "chatcmpl-123"

    def test_rebuild_tool_delta(self, provider: OpenAIProvider):
        event_data = json.dumps({
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {"function": {"arguments": "REDACTED"}},
                        ],
                    },
                },
            ],
        })
        result = provider.rebuild_sse_event(event_data, "original args")
        parsed = json.loads(result)
        assert parsed["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"] == \
            "original args"

    def test_rebuild_non_matching_event(self, provider: OpenAIProvider):
        event_data = json.dumps({"id": "chatcmpl-123", "choices": []})
        result = provider.rebuild_sse_event(event_data, "ignored")
        # choices is empty, so no text path matches
        assert result == event_data

    def test_rebuild_invalid_json(self, provider: OpenAIProvider):
        result = provider.rebuild_sse_event("not json", "new text")
        assert result == "not json"


class TestOpenAIProperties:
    """Test provider property accessors."""

    def test_name(self, provider: OpenAIProvider):
        assert provider.name == "openai"

    def test_display_name(self, provider: OpenAIProvider):
        assert "OpenAI" in provider.display_name

    def test_default_url_patterns(self, provider: OpenAIProvider):
        patterns = provider.default_url_patterns
        assert "*/v1/chat/completions" in patterns
        assert "*/chat/completions" in patterns

    def test_auth_headers(self, provider: OpenAIProvider):
        headers = provider.auth_headers
        assert "authorization" in headers
        assert "api-key" in headers


class TestOpenAIRoundTrip:
    """Test full extract-replace round trips."""

    def test_round_trip_simple_message(self, provider: OpenAIProvider):
        body = {
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "My SSN is 123-45-6789"},
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) == 1

        replacements = {f.json_path: f.text_value.replace("123-45-6789", "REDACTED_SSN_1")
                        for f in fields}
        result = provider.replace_text_fields(body, replacements)
        assert "REDACTED_SSN_1" in result["messages"][0]["content"]
        assert "123-45-6789" not in result["messages"][0]["content"]

    def test_round_trip_multi_message(self, provider: OpenAIProvider):
        body = {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "Help user Alice."},
                {"role": "user", "content": "Email: alice@example.com, Phone: 555-1234"},
            ],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) == 2

        replacements = {}
        for f in fields:
            new_text = f.text_value
            new_text = new_text.replace("Alice", "REDACTED_PERSON_1")
            new_text = new_text.replace("alice@example.com", "REDACTED_EMAIL_1")
            new_text = new_text.replace("555-1234", "REDACTED_PHONE_1")
            replacements[f.json_path] = new_text

        result = provider.replace_text_fields(body, replacements)
        assert result["messages"][0]["content"] == "Help user REDACTED_PERSON_1."
        assert "REDACTED_EMAIL_1" in result["messages"][1]["content"]
        assert "REDACTED_PHONE_1" in result["messages"][1]["content"]

    def test_round_trip_response(self, provider: OpenAIProvider):
        body = {
            "choices": [
                {
                    "message": {"content": "The name REDACTED_PERSON_1 was found."},
                },
            ],
        }
        fields = provider.extract_response_text_fields(body)
        assert len(fields) == 1
        assert "REDACTED_PERSON_1" in fields[0].text_value
