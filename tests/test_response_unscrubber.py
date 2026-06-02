"""Tests for the ResponseUnscrubber module."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

import pytest

from scruxy.scrubber.response_unscrubber import (
    ResponseUnscrubber,
    TextField,
    deanonymize_text,
)


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class _FakeTokenMap:
    """Minimal token map with an ``unscrub`` dict mapping tokens -> PII."""

    def __init__(self, unscrub: dict[str, str]) -> None:
        self.unscrub = unscrub


class _FakeTokenMapPrivate:
    """Token map that exposes the mapping via ``_unscrub`` (fallback path)."""

    def __init__(self, unscrub: dict[str, str]) -> None:
        self._unscrub = unscrub


def _make_provider(
    response_text_fields: list[TextField],
    replace_fn: Any | None = None,
) -> Any:
    """Build a mock provider with extract_response_text_fields / replace_text_fields."""

    class _MockProvider:
        def extract_response_text_fields(self, body: dict) -> list[TextField]:
            return response_text_fields

        def replace_text_fields(
            self, body: dict, replacements: dict[str, str],
        ) -> dict:
            if replace_fn is not None:
                return replace_fn(body, replacements)
            result = copy.deepcopy(body)
            for path, value in replacements.items():
                keys = path.strip("$.").split(".")
                obj = result
                for k in keys[:-1]:
                    obj = obj[k]
                obj[keys[-1]] = value
            return result

    return _MockProvider()


# ---------------------------------------------------------------------------
# deanonymize_text unit tests
# ---------------------------------------------------------------------------

class TestDeanonymizeText:
    """Unit tests for the standalone deanonymize_text helper."""

    def test_single_token(self) -> None:
        tm = _FakeTokenMap({"REDACTED_EMAIL_1": "alice@example.com"})
        result = deanonymize_text("Contact REDACTED_EMAIL_1 for info", tm)
        assert result == "Contact alice@example.com for info"

    def test_multiple_tokens(self) -> None:
        tm = _FakeTokenMap({
            "REDACTED_EMAIL_1": "alice@example.com",
            "REDACTED_PERSON_1": "Alice",
        })
        result = deanonymize_text("REDACTED_PERSON_1 at REDACTED_EMAIL_1", tm)
        assert result == "Alice at alice@example.com"

    def test_overlapping_token_names(self) -> None:
        """Longer tokens must be replaced before shorter ones (REDACTED_EMAIL_10 vs _1)."""
        tm = _FakeTokenMap({
            "REDACTED_EMAIL_1": "a@b.com",
            "REDACTED_EMAIL_10": "x@y.com",
        })
        result = deanonymize_text("REDACTED_EMAIL_10 and REDACTED_EMAIL_1", tm)
        assert result == "x@y.com and a@b.com"

    def test_no_tokens(self) -> None:
        tm = _FakeTokenMap({})
        result = deanonymize_text("No PII here", tm)
        assert result == "No PII here"

    def test_private_unscrub_attribute(self) -> None:
        """Falls back to ``_unscrub`` when ``unscrub`` is missing."""
        tm = _FakeTokenMapPrivate({"REDACTED_PHONE_1": "555-1234"})
        result = deanonymize_text("Call REDACTED_PHONE_1", tm)
        assert result == "Call 555-1234"

    def test_repeated_token(self) -> None:
        """The same token appearing multiple times is replaced everywhere."""
        tm = _FakeTokenMap({"REDACTED_NAME_1": "Bob"})
        result = deanonymize_text("REDACTED_NAME_1 said hi to REDACTED_NAME_1", tm)
        assert result == "Bob said hi to Bob"


# ---------------------------------------------------------------------------
# ResponseUnscrubber integration tests
# ---------------------------------------------------------------------------

class TestResponseUnscrubber:
    """Tests for ResponseUnscrubber.unscrub_response."""

    def test_basic_unscrub(self) -> None:
        body = {
            "choices": [{"message": {"content": "Hello REDACTED_PERSON_1"}}],
        }
        text_fields = [
            TextField("$.choices[0].message.content", "Hello REDACTED_PERSON_1"),
        ]

        def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
            result = copy.deepcopy(body)
            for path, value in replacements.items():
                if path == "$.choices[0].message.content":
                    result["choices"][0]["message"]["content"] = value
            return result

        provider = _make_provider(text_fields, replace_fn=replace_fn)
        token_map = _FakeTokenMap({"REDACTED_PERSON_1": "Alice"})

        unscrubber = ResponseUnscrubber()
        result = unscrubber.unscrub_response(body, provider, token_map)

        assert result["choices"][0]["message"]["content"] == "Hello Alice"

    def test_no_text_fields(self) -> None:
        body = {"id": "resp_123", "object": "chat.completion"}
        provider = _make_provider(response_text_fields=[])
        token_map = _FakeTokenMap({})

        unscrubber = ResponseUnscrubber()
        result = unscrubber.unscrub_response(body, provider, token_map)
        assert result == body

    def test_multiple_fields_unscrubbed(self) -> None:
        body = {
            "choices": [
                {"message": {"content": "Dear REDACTED_PERSON_1"}},
                {"message": {"content": "Email: REDACTED_EMAIL_1"}},
            ],
        }
        text_fields = [
            TextField("$.choices[0].message.content", "Dear REDACTED_PERSON_1"),
            TextField("$.choices[1].message.content", "Email: REDACTED_EMAIL_1"),
        ]

        def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
            result = copy.deepcopy(body)
            for path, value in replacements.items():
                if path == "$.choices[0].message.content":
                    result["choices"][0]["message"]["content"] = value
                elif path == "$.choices[1].message.content":
                    result["choices"][1]["message"]["content"] = value
            return result

        provider = _make_provider(text_fields, replace_fn=replace_fn)
        token_map = _FakeTokenMap({
            "REDACTED_PERSON_1": "Bob",
            "REDACTED_EMAIL_1": "bob@example.com",
        })

        unscrubber = ResponseUnscrubber()
        result = unscrubber.unscrub_response(body, provider, token_map)

        assert result["choices"][0]["message"]["content"] == "Dear Bob"
        assert result["choices"][1]["message"]["content"] == "Email: bob@example.com"

    def test_no_tokens_in_response(self) -> None:
        """When the response text contains no redaction tokens, text is unchanged."""
        body = {"choices": [{"message": {"content": "No PII here"}}]}
        text_fields = [
            TextField("$.choices[0].message.content", "No PII here"),
        ]

        def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
            result = copy.deepcopy(body)
            for path, value in replacements.items():
                if path == "$.choices[0].message.content":
                    result["choices"][0]["message"]["content"] = value
            return result

        provider = _make_provider(text_fields, replace_fn=replace_fn)
        token_map = _FakeTokenMap({"REDACTED_EMAIL_1": "a@b.com"})

        unscrubber = ResponseUnscrubber()
        result = unscrubber.unscrub_response(body, provider, token_map)

        assert result["choices"][0]["message"]["content"] == "No PII here"

    def test_unscrub_preserves_non_text_fields(self) -> None:
        """Non-text fields (model, id, etc.) are not affected."""
        body = {
            "id": "chatcmpl-abc",
            "model": "gpt-4",
            "choices": [{"message": {"content": "Hi REDACTED_PERSON_1"}}],
        }
        text_fields = [
            TextField("$.choices[0].message.content", "Hi REDACTED_PERSON_1"),
        ]

        def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
            result = copy.deepcopy(body)
            for path, value in replacements.items():
                if path == "$.choices[0].message.content":
                    result["choices"][0]["message"]["content"] = value
            return result

        provider = _make_provider(text_fields, replace_fn=replace_fn)
        token_map = _FakeTokenMap({"REDACTED_PERSON_1": "Eve"})

        unscrubber = ResponseUnscrubber()
        result = unscrubber.unscrub_response(body, provider, token_map)

        assert result["id"] == "chatcmpl-abc"
        assert result["model"] == "gpt-4"
        assert result["choices"][0]["message"]["content"] == "Hi Eve"
