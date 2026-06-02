"""Tests for the pipeline engine — PipelineEngine orchestrator."""
from __future__ import annotations

from typing import Any

import pytest

from scruxy.pipeline.engine import PipelineEngine
from scruxy.pipeline.merger import merge_and_deduplicate
from scruxy.pipeline.models import PiiEntity, PipelineContext, PipelineResult
from scruxy.tokenmap.anonymizer import anonymize_text
from scruxy.tokenmap.replacer import ScriptReplacement
from scruxy.tokenmap.token_map import TokenMap


# ---------------------------------------------------------------------------
# Helpers: mock stages and token maps
# ---------------------------------------------------------------------------

class MockStage:
    """A configurable mock detection stage."""

    def __init__(
        self,
        entities: list[PiiEntity] | None = None,
        enabled: bool = True,
        name: str = "mock",
    ) -> None:
        self.entities = entities or []
        self.enabled = enabled
        self.name = name
        self.detect_called = False

    async def detect(
        self, text: str, language: str = "en",
    ) -> list[PiiEntity]:
        self.detect_called = True
        return self.entities


class FailingStage:
    """A stage that always raises an exception."""

    enabled: bool = True

    async def detect(
        self, text: str, language: str = "en",
    ) -> list[PiiEntity]:
        raise RuntimeError("stage exploded")


class MockTokenMap:
    """Minimal token map stub implementing get_or_create_token."""

    def __init__(self) -> None:
        self._counter: dict[str, int] = {}
        self._map: dict[str, str] = {}

    def get_or_create_token(self, pii: str, entity_type: str, source: str = "", **kwargs: Any) -> str:
        key = (pii, entity_type)
        if key not in self._map:
            count = self._counter.get(entity_type, 0) + 1
            self._counter[entity_type] = count
            self._map[key] = f"REDACTED_{entity_type}_{count}"
        return self._map[key]


# ---------------------------------------------------------------------------
# Tests: PipelineEngine.scrub_text
# ---------------------------------------------------------------------------

class TestScrubTextEmptyInput:
    """scrub_text should handle empty / whitespace text gracefully."""

    async def test_empty_string_returns_empty_result(self) -> None:
        engine = PipelineEngine(stages=[])
        result = await engine.scrub_text("", MockTokenMap())

        assert result.scrubbed_text == ""
        assert result.entities == []
        assert result.latency_ms >= 0

    async def test_whitespace_only_returns_unchanged(self) -> None:
        engine = PipelineEngine(stages=[])
        result = await engine.scrub_text("   \n\t  ", MockTokenMap())

        assert result.scrubbed_text == "   \n\t  "
        assert result.entities == []

    async def test_none_text_treated_as_empty(self) -> None:
        """Passing an empty string (falsy) should still return a result."""
        engine = PipelineEngine(stages=[])
        result = await engine.scrub_text("", MockTokenMap())

        assert isinstance(result, PipelineResult)
        assert result.scrubbed_text == ""


class TestScrubTextSingleStage:
    """Pipeline with a single stage producing entities."""

    async def test_single_entity_is_anonymized(self) -> None:
        entity = PiiEntity(
            entity_type="EMAIL",
            start=10,
            end=25,
            score=0.95,
            source="presidio",
        )
        stage = MockStage(entities=[entity])
        engine = PipelineEngine(stages=[stage])
        token_map = MockTokenMap()

        text = "Contact: john@example.com please."
        # "john@example.com" starts at index 9, ends at 25  -- let's be precise
        entity.start = 9
        entity.end = 25

        result = await engine.scrub_text(text, token_map)

        assert "REDACTED_EMAIL_1" in result.scrubbed_text
        assert "john@example.com" not in result.scrubbed_text
        assert len(result.entities) == 1
        assert result.entities[0].entity_type == "EMAIL"

    async def test_stage_returning_no_entities(self) -> None:
        stage = MockStage(entities=[])
        engine = PipelineEngine(stages=[stage])

        text = "No PII in this text."
        result = await engine.scrub_text(text, MockTokenMap())

        assert result.scrubbed_text == text
        assert result.entities == []


class TestScrubTextMultipleStages:
    """Pipeline with multiple stages whose results are combined."""

    async def test_entities_from_all_stages_combined(self) -> None:
        email_entity = PiiEntity(
            entity_type="EMAIL", start=0, end=16, score=0.9, source="presidio"
        )
        phone_entity = PiiEntity(
            entity_type="PHONE", start=20, end=32, score=0.85, source="regex"
        )
        stage_a = MockStage(entities=[email_entity], name="presidio")
        stage_b = MockStage(entities=[phone_entity], name="regex")
        engine = PipelineEngine(stages=[stage_a, stage_b])
        token_map = MockTokenMap()

        text = "john@example.com -- 555-123-4567 end"
        result = await engine.scrub_text(text, token_map)

        assert len(result.entities) == 2
        assert "REDACTED_EMAIL_1" in result.scrubbed_text
        assert "REDACTED_PHONE_1" in result.scrubbed_text
        assert "john@example.com" not in result.scrubbed_text
        assert "555-123-4567" not in result.scrubbed_text

    async def test_first_stage_has_priority_in_sequential_model(self) -> None:
        """With sequential processing, the first stage claims the span.

        Stage A (regex) detects "John Doe" first and replaces it with a
        placeholder.  Stage B (presidio) sees placeholder text, so its
        hardcoded entity at [0,8] now covers the placeholder — but real
        detectors wouldn't fire on a placeholder.  The first stage's
        detection takes priority.
        """
        low = PiiEntity(
            entity_type="PERSON", start=0, end=8, score=0.6, source="regex"
        )
        stage_a = MockStage(entities=[low], name="regex")
        stage_b = MockStage(entities=[], name="presidio")  # doesn't detect (placeholder)
        engine = PipelineEngine(stages=[stage_a, stage_b])
        token_map = MockTokenMap()

        text = "John Doe said hello"
        result = await engine.scrub_text(text, token_map)

        # First stage's detection survives
        assert len(result.entities) >= 1
        assert result.entities[0].source == "regex"


class TestDisabledStage:
    """Disabled stages should be skipped entirely."""

    async def test_disabled_stage_is_not_called(self) -> None:
        disabled_stage = MockStage(
            entities=[
                PiiEntity(
                    entity_type="SSN", start=0, end=11, score=1.0, source="disabled"
                )
            ],
            enabled=False,
        )
        enabled_stage = MockStage(entities=[], enabled=True)

        engine = PipelineEngine(stages=[disabled_stage, enabled_stage])
        result = await engine.scrub_text("123-45-6789", MockTokenMap())

        assert disabled_stage.detect_called is False
        assert enabled_stage.detect_called is True
        assert result.entities == []

    async def test_all_stages_disabled_returns_original_text(self) -> None:
        s1 = MockStage(
            entities=[
                PiiEntity(entity_type="X", start=0, end=3, score=1.0, source="s1")
            ],
            enabled=False,
        )
        s2 = MockStage(
            entities=[
                PiiEntity(entity_type="Y", start=0, end=3, score=1.0, source="s2")
            ],
            enabled=False,
        )

        engine = PipelineEngine(stages=[s1, s2])
        text = "foo bar baz"
        result = await engine.scrub_text(text, MockTokenMap())

        assert result.scrubbed_text == text
        assert result.entities == []


class TestLatencyMeasurement:
    """The engine should report total latency in milliseconds."""

    async def test_latency_is_non_negative(self) -> None:
        engine = PipelineEngine(stages=[MockStage()])
        result = await engine.scrub_text("hello", MockTokenMap())

        assert result.latency_ms >= 0

    async def test_latency_measured_for_empty_input(self) -> None:
        engine = PipelineEngine(stages=[])
        result = await engine.scrub_text("", MockTokenMap())

        assert isinstance(result.latency_ms, float)
        assert result.latency_ms >= 0


class TestStageExceptionHandling:
    """A failing stage should not crash the pipeline."""

    async def test_failing_stage_is_skipped(self) -> None:
        good_entity = PiiEntity(
            entity_type="EMAIL", start=0, end=16, score=0.9, source="good"
        )
        good_stage = MockStage(entities=[good_entity])
        bad_stage = FailingStage()

        engine = PipelineEngine(stages=[bad_stage, good_stage])
        token_map = MockTokenMap()

        text = "john@example.com"
        result = await engine.scrub_text(text, token_map)

        # Good stage results still processed
        assert len(result.entities) == 1
        assert "REDACTED_EMAIL_1" in result.scrubbed_text


class TestPipelineContext:
    """Context language should be forwarded to stages."""

    async def test_language_from_context_passed_to_stage(self) -> None:
        received_languages: list[str] = []

        class CapturingStage:
            enabled = True

            async def detect(
                self, text: str, language: str = "en",
            ) -> list[PiiEntity]:
                received_languages.append(language)
                return []

        ctx = PipelineContext(
            session_id="sess-1",
            provider_name="anthropic",
            language="de",
        )
        engine = PipelineEngine(stages=[CapturingStage()])
        await engine.scrub_text("hello", MockTokenMap(), context=ctx)

        assert len(received_languages) == 1
        assert received_languages[0] == "de"

    async def test_default_language_when_no_context(self) -> None:
        received_languages: list[str] = []

        class CapturingStage:
            enabled = True

            async def detect(
                self, text: str, language: str = "en",
            ) -> list[PiiEntity]:
                received_languages.append(language)
                return []

        engine = PipelineEngine(stages=[CapturingStage()])
        await engine.scrub_text("hello", MockTokenMap(), context=None)

        assert len(received_languages) == 1
        assert received_languages[0] == "en"


class TestNoStages:
    """An engine with no stages should return text unmodified."""

    async def test_no_stages_returns_original(self) -> None:
        engine = PipelineEngine(stages=[])
        text = "My SSN is 123-45-6789"
        result = await engine.scrub_text(text, MockTokenMap())

        assert result.scrubbed_text == text
        assert result.entities == []


# ---------------------------------------------------------------------------
# Tests: merge_and_deduplicate (unit tests for the stub helper)
# ---------------------------------------------------------------------------

class TestMergeAndDeduplicate:
    """Unit tests for the merge_and_deduplicate stub."""

    def test_empty_list(self) -> None:
        assert merge_and_deduplicate([]) == []

    def test_single_entity(self) -> None:
        e = PiiEntity(entity_type="X", start=0, end=5, score=0.9, source="a")
        result = merge_and_deduplicate([e])
        assert result == [e]

    def test_non_overlapping_preserved(self) -> None:
        e1 = PiiEntity(entity_type="A", start=0, end=5, score=0.9, source="a")
        e2 = PiiEntity(entity_type="B", start=10, end=15, score=0.8, source="b")
        result = merge_and_deduplicate([e2, e1])  # out of order
        assert len(result) == 2
        assert result[0].start == 0
        assert result[1].start == 10

    def test_overlapping_keeps_higher_score(self) -> None:
        low = PiiEntity(entity_type="A", start=0, end=10, score=0.5, source="a")
        high = PiiEntity(entity_type="B", start=5, end=12, score=0.95, source="b")
        result = merge_and_deduplicate([low, high])
        assert len(result) == 1
        assert result[0].score == 0.95
        assert result[0].source == "b"

    def test_exact_same_span_keeps_higher_score(self) -> None:
        low = PiiEntity(entity_type="A", start=0, end=10, score=0.5, source="a")
        high = PiiEntity(entity_type="A", start=0, end=10, score=0.9, source="b")
        result = merge_and_deduplicate([low, high])
        assert len(result) == 1
        assert result[0].score == 0.9

    def test_adjacent_spans_not_merged(self) -> None:
        """Spans that are adjacent (end == start) should NOT be merged."""
        e1 = PiiEntity(entity_type="A", start=0, end=5, score=0.9, source="a")
        e2 = PiiEntity(entity_type="B", start=5, end=10, score=0.8, source="b")
        result = merge_and_deduplicate([e1, e2])
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Tests: anonymize_text (unit tests for the stub helper)
# ---------------------------------------------------------------------------

class TestAnonymizeText:
    """Unit tests for the anonymize_text stub."""

    def test_no_entities_returns_original(self) -> None:
        token_map = MockTokenMap()
        assert anonymize_text("hello world", [], token_map) == "hello world"

    def test_single_replacement(self) -> None:
        token_map = MockTokenMap()
        entity = PiiEntity(
            entity_type="EMAIL", start=0, end=16, score=0.9, source="t"
        )
        result = anonymize_text("john@example.com is here", [entity], token_map)
        assert result == "REDACTED_EMAIL_1 is here"

    def test_multiple_non_overlapping_replacements(self) -> None:
        token_map = MockTokenMap()
        e1 = PiiEntity(entity_type="EMAIL", start=0, end=16, score=0.9, source="t")
        e2 = PiiEntity(entity_type="PHONE", start=20, end=32, score=0.8, source="t")
        text = "john@example.com -- 555-123-4567 end"
        result = anonymize_text(text, [e1, e2], token_map)
        assert "REDACTED_EMAIL_1" in result
        assert "REDACTED_PHONE_1" in result
        assert "john@example.com" not in result
        assert "555-123-4567" not in result

    def test_deterministic_tokens_for_same_value(self) -> None:
        """Same original text + entity_type should produce the same token."""
        token_map = MockTokenMap()
        e1 = PiiEntity(entity_type="EMAIL", start=0, end=3, score=0.9, source="t")
        e2 = PiiEntity(entity_type="EMAIL", start=4, end=7, score=0.9, source="t")
        # Both spans contain "foo"
        result = anonymize_text("foo foo", [e1, e2], token_map)
        # Both should map to the same token
        assert result == "REDACTED_EMAIL_1 REDACTED_EMAIL_1"


# ---------------------------------------------------------------------------
# Tests: PipelineResult / PiiEntity / PipelineContext data classes
# ---------------------------------------------------------------------------

class TestDataclasses:
    def test_pii_entity_fields(self) -> None:
        e = PiiEntity(
            entity_type="PERSON", start=0, end=8, score=0.85, source="presidio"
        )
        assert e.entity_type == "PERSON"
        assert e.start == 0
        assert e.end == 8
        assert e.score == 0.85
        assert e.source == "presidio"

    def test_pipeline_result_fields(self) -> None:
        r = PipelineResult(entities=[], scrubbed_text="hello", latency_ms=1.5)
        assert r.scrubbed_text == "hello"
        assert r.latency_ms == 1.5
        assert r.entities == []

    def test_pipeline_context_defaults(self) -> None:
        ctx = PipelineContext(session_id="test", provider_name="test")
        assert ctx.session_id == "test"
        assert ctx.provider_name == "test"
        assert ctx.language == "en"

    def test_pipeline_context_custom(self) -> None:
        ctx = PipelineContext(
            session_id="abc", provider_name="openai", language="de"
        )
        assert ctx.session_id == "abc"
        assert ctx.provider_name == "openai"
        assert ctx.language == "de"


# ---------------------------------------------------------------------------
# Synchronous stage: exercises asyncio.to_thread path
# ---------------------------------------------------------------------------

class SyncMockStage:
    """A synchronous detection stage (like real Presidio/spaCy)."""

    def __init__(
        self,
        entities: list[PiiEntity] | None = None,
        enabled: bool = True,
    ) -> None:
        self.entities = entities or []
        self.enabled = enabled
        self.detect_called = False

    def detect(self, text: str, language: str = "en") -> list[PiiEntity]:
        self.detect_called = True
        return self.entities


class SyncFailingStage:
    """A sync stage that raises an exception."""

    enabled: bool = True

    def detect(self, text: str, language: str = "en") -> list[PiiEntity]:
        raise RuntimeError("sync stage exploded")


class TestSyncStageExecution:
    """Verify that synchronous stages are dispatched via asyncio.to_thread."""

    async def test_sync_stage_entities_detected(self) -> None:
        entity = PiiEntity("EMAIL", 0, 15, 0.95, "sync_stage")
        stage = SyncMockStage(entities=[entity])
        engine = PipelineEngine(stages=[stage])

        result = await engine.scrub_text("john@example.com", MockTokenMap())
        assert stage.detect_called
        assert len(result.entities) == 1
        assert result.entities[0].entity_type == "EMAIL"

    async def test_sync_stage_scrubs_text(self) -> None:
        entity = PiiEntity("EMAIL", 0, 16, 0.95, "sync")
        stage = SyncMockStage(entities=[entity])
        engine = PipelineEngine(stages=[stage])

        result = await engine.scrub_text("john@example.com", MockTokenMap())
        assert "REDACTED_EMAIL_1" in result.scrubbed_text
        assert "john@example.com" not in result.scrubbed_text

    async def test_sync_failing_stage_skipped(self) -> None:
        engine = PipelineEngine(stages=[SyncFailingStage()])
        result = await engine.scrub_text("test text", MockTokenMap())
        assert result.entities == []
        assert result.scrubbed_text == "test text"

    async def test_mixed_sync_and_async_stages(self) -> None:
        email_entity = PiiEntity("EMAIL", 0, 16, 0.95, "sync")
        phone_entity = PiiEntity("PHONE", 17, 29, 0.90, "async")
        sync_stage = SyncMockStage(entities=[email_entity])
        async_stage = MockStage(entities=[phone_entity])
        engine = PipelineEngine(stages=[sync_stage, async_stage])

        result = await engine.scrub_text("john@example.com 555-123-4567", MockTokenMap())
        assert sync_stage.detect_called
        assert async_stage.detect_called
        assert len(result.entities) == 2

    async def test_script_replacement_token_generation_runs_in_worker_thread(self) -> None:
        """Blocking script-based token generation should not run on the event loop."""
        entity = PiiEntity("PERSON", 0, 5, 0.95, "mock")
        stage = MockStage(entities=[entity])
        engine = PipelineEngine(stages=[stage])
        token_map = TokenMap(
            replacements={
                "PERSON": ScriptReplacement(command="/nonexistent/binary", timeout_ms=1)
            }
        )

        async def tracking_to_thread(func, *args, **kwargs):
            tracking_to_thread.calls.append(getattr(func, "__name__", repr(func)))
            return func(*args, **kwargs)

        tracking_to_thread.calls = []

        from unittest.mock import patch

        with patch("scruxy.pipeline.engine.asyncio.to_thread", side_effect=tracking_to_thread):
            result = await engine.scrub_text("Alice", token_map)

        assert "get_or_create_token" in tracking_to_thread.calls
        assert "REDACTED_PERSON_1" in result.scrubbed_text

    async def test_default_token_generation_also_runs_in_worker_thread(self) -> None:
        """All token generation should use the worker-thread path to avoid lock contention."""
        entity = PiiEntity("EMAIL", 0, 16, 0.95, "mock")
        stage = MockStage(entities=[entity])
        engine = PipelineEngine(stages=[stage])
        token_map = TokenMap()

        async def tracking_to_thread(func, *args, **kwargs):
            tracking_to_thread.calls.append(getattr(func, "__name__", repr(func)))
            return func(*args, **kwargs)

        tracking_to_thread.calls = []

        from unittest.mock import patch

        with patch("scruxy.pipeline.engine.asyncio.to_thread", side_effect=tracking_to_thread):
            result = await engine.scrub_text("john@example.com", token_map)

        assert "get_or_create_token" in tracking_to_thread.calls
        assert "REDACTED_EMAIL_1" in result.scrubbed_text


# ======================================================================
# PII span cleaning tests
# ======================================================================


class TestCleanPiiSpan:
    """Test _clean_pii_span: edge control char stripping and newline splitting."""

    def test_trailing_newlines_stripped(self) -> None:
        from scruxy.pipeline.engine import _clean_pii_span
        result = _clean_pii_span("John Smith\r\n", 0, 12)
        assert len(result) == 1
        assert result[0][0] == "John Smith"

    def test_leading_control_chars_stripped(self) -> None:
        from scruxy.pipeline.engine import _clean_pii_span
        result = _clean_pii_span("\n\tJane Doe\r\n", 5, 17)
        assert len(result) == 1
        assert result[0][0] == "Jane Doe"

    def test_internal_newline_splits(self) -> None:
        from scruxy.pipeline.engine import _clean_pii_span
        result = _clean_pii_span("John Smith\nJane Doe", 0, 19)
        assert len(result) == 2
        assert result[0][0] == "John Smith"
        assert result[1][0] == "Jane Doe"

    def test_all_control_chars_returns_empty(self) -> None:
        from scruxy.pipeline.engine import _clean_pii_span
        assert _clean_pii_span("\r\n\t", 0, 3) == []

    def test_clean_text_unchanged(self) -> None:
        from scruxy.pipeline.engine import _clean_pii_span
        result = _clean_pii_span("John Smith", 10, 20)
        assert result == [("John Smith", 10, 20)]

    def test_single_char_after_trim_skipped(self) -> None:
        from scruxy.pipeline.engine import _clean_pii_span
        assert _clean_pii_span("\nX\n", 0, 3) == []

    def test_offsets_correct_after_trim(self) -> None:
        from scruxy.pipeline.engine import _clean_pii_span
        # "\r\nJohn\r\n" at offset 100 → "John" at 102..106
        result = _clean_pii_span("\r\nJohn\r\n", 100, 108)
        assert len(result) == 1
        assert result[0] == ("John", 102, 106)


class TestPipelineWhitespaceHandling:
    """Integration tests: pipeline preserves whitespace in scrubbed text."""

    async def test_trailing_newline_preserved_in_output(self) -> None:
        """Trailing \\n stays in scrubbed text — only PII portion is replaced."""
        text = "Contact John Smith\r\n for details."
        entity = PiiEntity("PERSON", 8, 20, 0.9, "test")
        stage = MockStage(entities=[entity])
        engine = PipelineEngine(stages=[stage])
        result = await engine.scrub_text(text, MockTokenMap())
        # The \r\n should still be in the output
        assert "\r\n" in result.scrubbed_text
        assert "REDACTED_PERSON_1" in result.scrubbed_text
        assert "John Smith" not in result.scrubbed_text

    async def test_internal_newline_splits_into_two_tokens(self) -> None:
        """PII span containing internal \\n becomes two separate tokens."""
        text = "Names: John Smith\nJane Doe end"
        entity = PiiEntity("PERSON", 7, 26, 0.9, "test")
        stage = MockStage(entities=[entity])
        engine = PipelineEngine(stages=[stage])
        result = await engine.scrub_text(text, MockTokenMap())
        assert "REDACTED_PERSON_1" in result.scrubbed_text
        assert "REDACTED_PERSON_2" in result.scrubbed_text
        assert "\n" in result.scrubbed_text
        assert "John Smith" not in result.scrubbed_text
        assert "Jane Doe" not in result.scrubbed_text
