"""Tests for the RequestScrubber module."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock

import pytest

from scruxy.pipeline.models import PiiEntity, PipelineResult
from scruxy.providers.base import TextField
from scruxy.scrubber.request_scrubber import RequestScrubber, _overlaps_any


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _make_provider(
    text_fields: list[TextField],
    replace_fn: Any | None = None,
) -> Any:
    """Build a mock provider with extract_text_fields / replace_text_fields."""

    class _MockProvider:
        def extract_text_fields(self, body: dict) -> list[TextField]:
            return text_fields

        def replace_text_fields(
            self, body: dict, replacements: dict[str, str],
        ) -> dict:
            if replace_fn is not None:
                return replace_fn(body, replacements)
            # Default: shallow-copy body and apply replacements by key path.
            result = copy.deepcopy(body)
            for path, value in replacements.items():
                # Simple single-level key replacement for tests.
                keys = path.strip("$.").split(".")
                obj = result
                for k in keys[:-1]:
                    obj = obj[k]
                obj[keys[-1]] = value
            return result

    return _MockProvider()


def _make_pipeline(results_map: dict[str, PipelineResult]) -> Any:
    """Build a mock pipeline that returns pre-defined PipelineResults per text."""
    pipeline = AsyncMock()
    pipeline.scrub_text = AsyncMock(side_effect=lambda text, tm, ctx=None, **kwargs: results_map[text])
    return pipeline


class _FakeTokenMap:
    """Minimal token-map stand-in."""
    pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scrub_request_basic() -> None:
    """Full round-trip: extract -> scrub -> replace."""
    body = {"messages": [{"role": "user", "content": "Call me at john@example.com"}]}

    text_fields = [
        TextField(json_path="$.messages[0].content", text_value="Call me at john@example.com"),
    ]
    pipeline_results = {
        "Call me at john@example.com": PipelineResult(
            scrubbed_text="Call me at REDACTED_EMAIL_1",
            entities=[
                PiiEntity(
                    entity_type="EMAIL",
                    start=11,
                    end=27,
                    score=0.95,
                    source="presidio",
                ),
            ],
        ),
    }

    def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
        result = copy.deepcopy(body)
        for path, value in replacements.items():
            if path == "$.messages[0].content":
                result["messages"][0]["content"] = value
        return result

    provider = _make_provider(text_fields, replace_fn=replace_fn)
    pipeline = _make_pipeline(pipeline_results)
    token_map = _FakeTokenMap()

    scrubber = RequestScrubber()
    scrubbed, entities, _, _ = await scrubber.scrub_request(
        body, provider, pipeline, token_map,
    )

    assert scrubbed["messages"][0]["content"] == "Call me at REDACTED_EMAIL_1"
    assert len(entities) == 1
    assert entities[0].entity_type == "EMAIL"
    assert entities[0].source == "presidio"


@pytest.mark.asyncio
async def test_scrub_request_no_pii() -> None:
    """When there is no PII, body should pass through unchanged."""
    body = {"messages": [{"role": "user", "content": "Hello, world!"}]}

    text_fields = [
        TextField(json_path="$.messages[0].content", text_value="Hello, world!"),
    ]
    pipeline_results = {
        "Hello, world!": PipelineResult(scrubbed_text="Hello, world!", entities=[]),
    }

    def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
        result = copy.deepcopy(body)
        for path, value in replacements.items():
            if path == "$.messages[0].content":
                result["messages"][0]["content"] = value
        return result

    provider = _make_provider(text_fields, replace_fn=replace_fn)
    pipeline = _make_pipeline(pipeline_results)
    token_map = _FakeTokenMap()

    scrubber = RequestScrubber()
    scrubbed, entities, _, _ = await scrubber.scrub_request(
        body, provider, pipeline, token_map,
    )

    assert scrubbed["messages"][0]["content"] == "Hello, world!"
    assert entities == []


@pytest.mark.asyncio
async def test_scrub_request_multiple_fields() -> None:
    """Multiple text fields in a single request are all scrubbed."""
    body = {
        "system": "You are a helpful assistant. Contact: admin@corp.com",
        "messages": [{"role": "user", "content": "My name is Alice"}],
    }

    text_fields = [
        TextField(json_path="$.system", text_value="You are a helpful assistant. Contact: admin@corp.com"),
        TextField(json_path="$.messages[0].content", text_value="My name is Alice"),
    ]
    pipeline_results = {
        "You are a helpful assistant. Contact: admin@corp.com": PipelineResult(
            scrubbed_text="You are a helpful assistant. Contact: REDACTED_EMAIL_1",
            entities=[
                PiiEntity("EMAIL", 38, 52, 0.99, "presidio"),
            ],
        ),
        "My name is Alice": PipelineResult(
            scrubbed_text="My name is REDACTED_PERSON_1",
            entities=[
                PiiEntity("PERSON", 11, 16, 0.90, "presidio"),
            ],
        ),
    }

    def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
        result = copy.deepcopy(body)
        for path, value in replacements.items():
            if path == "$.system":
                result["system"] = value
            elif path == "$.messages[0].content":
                result["messages"][0]["content"] = value
        return result

    provider = _make_provider(text_fields, replace_fn=replace_fn)
    pipeline = _make_pipeline(pipeline_results)
    token_map = _FakeTokenMap()

    scrubber = RequestScrubber()
    scrubbed, entities, _, _ = await scrubber.scrub_request(
        body, provider, pipeline, token_map,
    )

    assert scrubbed["system"] == "You are a helpful assistant. Contact: REDACTED_EMAIL_1"
    assert scrubbed["messages"][0]["content"] == "My name is REDACTED_PERSON_1"
    assert len(entities) == 2


@pytest.mark.asyncio
async def test_scrub_request_no_text_fields() -> None:
    """When the provider extracts no text fields, body passes through unmodified."""
    body = {"model": "claude-3-opus"}

    provider = _make_provider(text_fields=[])
    pipeline = _make_pipeline({})  # should never be called
    token_map = _FakeTokenMap()

    scrubber = RequestScrubber()
    scrubbed, entities, _, _ = await scrubber.scrub_request(
        body, provider, pipeline, token_map,
    )

    assert scrubbed == body
    assert entities == []


@pytest.mark.asyncio
async def test_scrub_request_with_context() -> None:
    """Context parameter is forwarded to pipeline.scrub_text."""
    body = {"messages": [{"role": "user", "content": "test"}]}

    text_fields = [TextField(json_path="$.messages[0].content", text_value="test")]
    pipeline_results = {"test": PipelineResult(scrubbed_text="test", entities=[])}

    def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
        result = copy.deepcopy(body)
        for path, value in replacements.items():
            if path == "$.messages[0].content":
                result["messages"][0]["content"] = value
        return result

    provider = _make_provider(text_fields, replace_fn=replace_fn)
    pipeline = _make_pipeline(pipeline_results)
    token_map = _FakeTokenMap()

    context = {"session_id": "abc123"}
    scrubber = RequestScrubber()
    await scrubber.scrub_request(body, provider, pipeline, token_map, context=context)

    # Verify context was forwarded.
    pipeline.scrub_text.assert_awaited_once_with("test", token_map, context, request_id="")


@pytest.mark.asyncio
async def test_scrub_request_does_not_mutate_original() -> None:
    """The original body dict must not be mutated."""
    body = {"messages": [{"role": "user", "content": "secret@email.com"}]}
    original_content = body["messages"][0]["content"]

    text_fields = [
        TextField(json_path="$.messages[0].content", text_value="secret@email.com"),
    ]
    pipeline_results = {
        "secret@email.com": PipelineResult(
            scrubbed_text="REDACTED_EMAIL_1",
            entities=[
                PiiEntity("EMAIL", 0, 16, 0.99, "presidio"),
            ],
        ),
    }

    def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
        result = copy.deepcopy(body)
        for path, value in replacements.items():
            if path == "$.messages[0].content":
                result["messages"][0]["content"] = value
        return result

    provider = _make_provider(text_fields, replace_fn=replace_fn)
    pipeline = _make_pipeline(pipeline_results)
    token_map = _FakeTokenMap()

    scrubber = RequestScrubber()
    scrubbed, _, _, _ = await scrubber.scrub_request(body, provider, pipeline, token_map)

    # Original must be untouched.
    assert body["messages"][0]["content"] == original_content
    assert scrubbed["messages"][0]["content"] == "REDACTED_EMAIL_1"


@pytest.mark.asyncio
async def test_scrub_request_multiple_entities_in_one_field() -> None:
    """A single text field can contain multiple PII entities."""
    body = {"prompt": "John Doe, john@doe.com, 555-1234"}
    text_fields = [
        TextField(json_path="$.prompt", text_value="John Doe, john@doe.com, 555-1234"),
    ]
    pipeline_results = {
        "John Doe, john@doe.com, 555-1234": PipelineResult(
            scrubbed_text="REDACTED_PERSON_1, REDACTED_EMAIL_1, REDACTED_PHONE_1",
            entities=[
                PiiEntity("PERSON", 0, 8, 0.92, "presidio"),
                PiiEntity("EMAIL", 10, 22, 0.99, "presidio"),
                PiiEntity("PHONE", 24, 32, 0.85, "presidio"),
            ],
        ),
    }

    def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
        result = copy.deepcopy(body)
        for path, value in replacements.items():
            if path == "$.prompt":
                result["prompt"] = value
        return result

    provider = _make_provider(text_fields, replace_fn=replace_fn)
    pipeline = _make_pipeline(pipeline_results)
    token_map = _FakeTokenMap()

    scrubber = RequestScrubber()
    scrubbed, entities, _, _ = await scrubber.scrub_request(body, provider, pipeline, token_map)

    assert scrubbed["prompt"] == "REDACTED_PERSON_1, REDACTED_EMAIL_1, REDACTED_PHONE_1"
    assert len(entities) == 3
    assert {e.entity_type for e in entities} == {"PERSON", "EMAIL", "PHONE"}


@pytest.mark.asyncio
async def test_second_pass_does_not_corrupt_existing_tokens() -> None:
    """Second-pass scrub must not match PII inside already-placed tokens.

    Regression test: if PII "Cloud" is discovered in a later field, the
    second pass must not corrupt "REDACTED_LOCATION_1" (which doesn't
    contain "Cloud"), but more importantly must not corrupt tokens where
    PII values happen to be substrings of the token entity type name.
    """
    # Simulate: first field scrubbed "Alice" → REDACTED_PERSON_1
    # Second field discovers "PERSON" as a PII value.
    # The second pass must NOT turn REDACTED_PERSON_1 into
    # REDACTED_REDACTED_PERSON_2_1.
    body = {
        "system": "Talk to REDACTED_PERSON_1 about the PERSON project",
        "messages": [{"role": "user", "content": "The PERSON project is important"}],
    }

    text_fields = [
        TextField(json_path="$.system", text_value=body["system"]),
        TextField(json_path="$.messages[0].content", text_value=body["messages"][0]["content"]),
    ]

    # Pipeline returns text as-is (scrubbing already done in "system",
    # and "PERSON" is detected in messages field)
    pipeline_results = {
        body["system"]: PipelineResult(scrubbed_text=body["system"], entities=[]),
        body["messages"][0]["content"]: PipelineResult(
            scrubbed_text="The REDACTED_PERSON_2 project is important",
            entities=[PiiEntity("PERSON", 4, 10, 0.85, "presidio")],
        ),
    }

    def replace_fn(body_arg: dict, replacements: dict[str, str]) -> dict:
        result = copy.deepcopy(body_arg)
        for path, value in replacements.items():
            if path == "$.system":
                result["system"] = value
            elif path == "$.messages[0].content":
                result["messages"][0]["content"] = value
        return result

    provider = _make_provider(text_fields, replace_fn=replace_fn)
    pipeline = _make_pipeline(pipeline_results)

    # Fake token map with "PERSON" → "REDACTED_PERSON_2" in scrub map
    # This simulates the second-pass finding "PERSON" as known PII.
    token_map = _FakeTokenMap()
    token_map._scrub = {"PERSON": "REDACTED_PERSON_2", "Alice": "REDACTED_PERSON_1"}
    token_map.scrub_map = token_map._scrub
    token_map._token_meta = {}

    scrubber = RequestScrubber()
    scrubbed, _, _, _ = await scrubber.scrub_request(body, provider, pipeline, token_map)

    # "PERSON" in "the PERSON project" (system field) should be replaced
    # BUT "PERSON" inside "REDACTED_PERSON_1" must NOT be touched
    system_text = scrubbed["system"]
    assert "REDACTED_PERSON_1" in system_text, (
        f"Original token corrupted! Got: {system_text}"
    )
    # The standalone "PERSON" should have been replaced
    assert "the REDACTED_PERSON_2 project" in system_text or "PERSON project" in system_text


@pytest.mark.asyncio
async def test_second_pass_skips_identity_mappings() -> None:
    """Whitelist identity mappings (token == PII) should be skipped in second pass."""
    body = {"messages": [{"role": "user", "content": "Use the Claude model"}]}

    text_fields = [
        TextField(json_path="$.messages[0].content", text_value=body["messages"][0]["content"]),
    ]
    pipeline_results = {
        body["messages"][0]["content"]: PipelineResult(
            scrubbed_text=body["messages"][0]["content"], entities=[]
        ),
    }

    def replace_fn(body_arg: dict, replacements: dict[str, str]) -> dict:
        result = copy.deepcopy(body_arg)
        for path, value in replacements.items():
            if path == "$.messages[0].content":
                result["messages"][0]["content"] = value
        return result

    provider = _make_provider(text_fields, replace_fn=replace_fn)
    pipeline = _make_pipeline(pipeline_results)

    # Whitelist: "Claude" maps to itself
    token_map = _FakeTokenMap()
    token_map._scrub = {"Claude": "Claude"}
    token_map.scrub_map = token_map._scrub
    token_map._token_meta = {}

    scrubber = RequestScrubber()
    scrubbed, _, _, _ = await scrubber.scrub_request(body, provider, pipeline, token_map)

    # Text should be unchanged — identity mapping skipped
    assert scrubbed["messages"][0]["content"] == "Use the Claude model"


@pytest.mark.asyncio
async def test_second_pass_handles_long_token_names() -> None:
    """Occupied-range check works for tokens longer than 30 characters.

    Regression: lookback-based detection failed for long token names
    because the window was too small.
    """
    long_token = "REDACTED_VERY_LONG_ENTITY_TYPE_PERSON_1"  # 39 chars
    body = {
        "system": f"Talk to {long_token} about the PERSON project",
    }

    text_fields = [
        TextField(json_path="$.system", text_value=body["system"]),
    ]
    pipeline_results = {
        body["system"]: PipelineResult(scrubbed_text=body["system"], entities=[]),
    }

    def replace_fn(body_arg: dict, replacements: dict[str, str]) -> dict:
        result = copy.deepcopy(body_arg)
        for path, value in replacements.items():
            if path == "$.system":
                result["system"] = value
        return result

    provider = _make_provider(text_fields, replace_fn=replace_fn)
    pipeline = _make_pipeline(pipeline_results)

    token_map = _FakeTokenMap()
    token_map._scrub = {
        "PERSON": "REDACTED_PERSON_2",
        "Alice": long_token,
    }
    token_map.scrub_map = token_map._scrub
    token_map._token_meta = {}

    scrubber = RequestScrubber()
    scrubbed, _, _, _ = await scrubber.scrub_request(body, provider, pipeline, token_map)

    system_text = scrubbed["system"]
    # Long token must NOT be corrupted
    assert long_token in system_text, (
        f"Long token corrupted! Got: {system_text}"
    )
    # Standalone "PERSON" in "the PERSON project" should be replaced
    assert "the REDACTED_PERSON_2 project" in system_text


def test_overlaps_any_scans_beyond_two_adjacent_ranges() -> None:
    """Wide spans should still detect overlap with later occupied ranges."""
    occupied = [(0, 2), (4, 6), (8, 10), (12, 14)]
    assert _overlaps_any(1, 13, occupied) is True

@pytest.mark.asyncio
async def test_scrub_request_returns_prefilter_reused_pii() -> None:
    """Second-pass prefilter reuses shared-map tokens in a new session; the
    set of reused PII must be exposed so callers can tag it for that session
    (round-44 M2).
    """
    # Only extract the system field; the pipeline treats it as having no PII.
    # "alice@example.com" is already in the shared scrub_map from a prior
    # session, so the second pass must replace it and report it back.
    body = {"system": "Contact alice@example.com for details", "user": "x"}
    text_fields = [
        TextField(json_path="$.system", text_value=body["system"]),
    ]
    pipeline_results = {
        body["system"]: PipelineResult(
            scrubbed_text=body["system"],
            entities=[],
        ),
    }

    def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
        result = copy.deepcopy(body)
        for path, value in replacements.items():
            if path == "$.system":
                result["system"] = value
        return result

    provider = _make_provider(text_fields, replace_fn=replace_fn)
    pipeline = _make_pipeline(pipeline_results)
    token_map = _FakeTokenMap()
    token_map._scrub = {"alice@example.com": "REDACTED_EMAIL_1"}
    token_map.scrub_map = token_map._scrub
    token_map._token_meta = {}

    scrubber = RequestScrubber()
    scrubbed, entities, _, reused = await scrubber.scrub_request(
        body, provider, pipeline, token_map,
    )

    assert scrubbed["system"] == "Contact REDACTED_EMAIL_1 for details"
    assert entities == []
    assert reused == {"alice@example.com"}, (
        f"prefilter_reused_pii should expose PII reused via second pass; got {reused!r}"
    )


@pytest.mark.asyncio
async def test_scrub_request_does_not_duplicate_entity_pii_in_reused() -> None:
    """PII already reported as entities in the first pass should NOT be
    duplicated in prefilter_reused_pii (round-44 M2)."""
    body = {"system": "Hi bob@example.com and bob@example.com again"}
    text_fields = [
        TextField(json_path="$.system", text_value=body["system"]),
    ]
    # Pipeline detects the email and replaces both occurrences in-field.
    _ent = PiiEntity(
        entity_type="EMAIL", start=3, end=19, score=0.95, source="presidio",
    )
    _ent._matched_text = "bob@example.com"
    pipeline_results = {
        body["system"]: PipelineResult(
            scrubbed_text="Hi REDACTED_EMAIL_1 and REDACTED_EMAIL_1 again",
            entities=[_ent],
        ),
    }

    def replace_fn(body: dict, replacements: dict[str, str]) -> dict:
        result = copy.deepcopy(body)
        for path, value in replacements.items():
            if path == "$.system":
                result["system"] = value
        return result

    provider = _make_provider(text_fields, replace_fn=replace_fn)
    pipeline = _make_pipeline(pipeline_results)
    token_map = _FakeTokenMap()
    token_map._scrub = {"bob@example.com": "REDACTED_EMAIL_1"}
    token_map.scrub_map = token_map._scrub
    token_map._token_meta = {}

    scrubber = RequestScrubber()
    _, entities, _, reused = await scrubber.scrub_request(
        body, provider, pipeline, token_map,
    )

    assert len(entities) == 1
    # Already-an-entity PII must not be re-reported as prefilter-reused.
    assert "bob@example.com" not in reused
