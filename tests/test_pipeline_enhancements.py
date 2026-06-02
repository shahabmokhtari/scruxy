"""Tests for plugin pipeline enhancements: word boundaries, case sensitivity,
word-count replacement, and pre-filter exclusion."""
from __future__ import annotations

import re
import uuid

import pytest

from scruxy.tokenmap.replacer import (
    DefaultReplacement,
    UuidReplacement,
    _suffix_letter,
    _word_count,
)
from scruxy.pipeline.engine import PipelineEngine, _PlaceholderEntry
from scruxy.plugin.base import PiiEntity
from scruxy.tokenmap.token_map import TokenMap


# =====================================================================
# _word_count helper
# =====================================================================

class TestWordCount:
    def test_single_word(self):
        assert _word_count("Alice") == 1

    def test_two_words(self):
        assert _word_count("Alice Johnson") == 2

    def test_three_words(self):
        assert _word_count("John De Cruz") == 3

    def test_four_words(self):
        assert _word_count("John De La Cruz") == 4

    def test_empty_string(self):
        assert _word_count("") == 0  # "".split() returns [], len == 0

    def test_whitespace_only(self):
        # "   ".split() returns [], len == 0
        assert _word_count("   ") == 0

    def test_extra_spaces(self):
        # str.split() collapses multiple spaces
        assert _word_count("  John   Doe  ") == 2


# =====================================================================
# _suffix_letter helper
# =====================================================================

class TestSuffixLetter:
    def test_index_0_is_A(self):
        assert _suffix_letter(0) == "A"

    def test_index_1_is_B(self):
        assert _suffix_letter(1) == "B"

    def test_index_25_is_Z(self):
        assert _suffix_letter(25) == "Z"

    def test_index_26_is_AA(self):
        assert _suffix_letter(26) == "AA"

    def test_index_27_is_AB(self):
        assert _suffix_letter(27) == "AB"

    def test_index_51_is_AZ(self):
        assert _suffix_letter(51) == "AZ"

    def test_index_52_is_BA(self):
        assert _suffix_letter(52) == "BA"


# =====================================================================
# DefaultReplacement word-count preservation
# =====================================================================

class TestDefaultReplacementWordCount:
    def setup_method(self):
        self.strategy = DefaultReplacement()

    def test_single_word_no_suffix(self):
        token = self.strategy.generate("PERSON", "Alice", 1)
        assert token == "REDACTED_PERSON_1"

    def test_two_words_two_suffixed_tokens(self):
        token = self.strategy.generate("PERSON", "Alice Johnson", 1)
        assert token == "REDACTED_PERSON_1A REDACTED_PERSON_1B"

    def test_three_words_three_suffixed_tokens(self):
        token = self.strategy.generate("PERSON", "John De Cruz", 2)
        assert token == "REDACTED_PERSON_2A REDACTED_PERSON_2B REDACTED_PERSON_2C"

    def test_four_words_four_suffixed_tokens(self):
        token = self.strategy.generate("PERSON", "John De La Cruz", 1)
        parts = token.split()
        assert len(parts) == 4
        assert parts[0] == "REDACTED_PERSON_1A"
        assert parts[1] == "REDACTED_PERSON_1B"
        assert parts[2] == "REDACTED_PERSON_1C"
        assert parts[3] == "REDACTED_PERSON_1D"

    def test_word_count_preserved_for_email_type(self):
        # Emails are typically single-word, but test that the strategy works
        token = self.strategy.generate("EMAIL", "john@example.com", 5)
        assert token == "REDACTED_EMAIL_5"

    def test_multi_word_different_entity_type(self):
        token = self.strategy.generate("ORG", "Acme Corp", 3)
        assert token == "REDACTED_ORG_3A REDACTED_ORG_3B"


# =====================================================================
# UuidReplacement word-count preservation
# =====================================================================

class TestUuidReplacementWordCount:
    def setup_method(self):
        self.strategy = UuidReplacement()

    def test_single_word_one_uuid(self):
        token = self.strategy.generate("PERSON", "Alice", 1)
        # Should be a single valid UUID
        uuid.UUID(token)  # raises ValueError if not valid
        assert " " not in token

    def test_two_words_two_uuids(self):
        token = self.strategy.generate("PERSON", "Alice Johnson", 1)
        parts = token.split()
        assert len(parts) == 2
        for part in parts:
            uuid.UUID(part)  # validate each is a UUID

    def test_three_words_three_uuids(self):
        token = self.strategy.generate("PERSON", "John De Cruz", 1)
        parts = token.split()
        assert len(parts) == 3
        for part in parts:
            uuid.UUID(part)

    def test_uuids_are_unique(self):
        token = self.strategy.generate("PERSON", "A B C D", 1)
        parts = token.split()
        assert len(parts) == len(set(parts))


# =====================================================================
# PiiEntity new fields
# =====================================================================

class TestPiiEntityNewFields:
    def test_defaults(self):
        entity = PiiEntity(
            entity_type="PERSON", start=0, end=5, score=0.9, source="test"
        )
        assert entity.use_word_boundary is False
        assert entity.case_sensitive is True

    def test_word_boundary_true(self):
        entity = PiiEntity(
            entity_type="PATH_SEGMENT", start=0, end=4, score=0.95,
            source="file_path", use_word_boundary=True,
        )
        assert entity.use_word_boundary is True

    def test_case_insensitive(self):
        entity = PiiEntity(
            entity_type="PERSON", start=0, end=4, score=0.8,
            source="test", case_sensitive=False,
        )
        assert entity.case_sensitive is False

    def test_both_custom_values(self):
        entity = PiiEntity(
            entity_type="PERSON", start=0, end=5, score=0.85,
            source="test", use_word_boundary=True, case_sensitive=False,
        )
        assert entity.use_word_boundary is True
        assert entity.case_sensitive is False


# =====================================================================
# TokenMap metadata (get_or_create_token kwargs + round-trip)
# =====================================================================

class TestTokenMapMetadata:
    def test_metadata_stored_on_create(self):
        tm = TokenMap()
        tm.get_or_create_token(
            "repo", "PATH_SEGMENT", "file_path",
            use_word_boundary=True, case_sensitive=True,
            exclude_from_prefilter=False,
        )
        meta = tm._token_meta["repo"]
        assert meta["word_boundary"] is True
        assert meta["case_sensitive"] is True
        assert meta["exclude_from_prefilter"] is False

    def test_metadata_exclude_from_prefilter(self):
        tm = TokenMap()
        tm.get_or_create_token(
            "secret", "CUSTOM", "plugin",
            exclude_from_prefilter=True,
        )
        meta = tm._token_meta["secret"]
        assert meta["exclude_from_prefilter"] is True

    def test_metadata_case_insensitive(self):
        tm = TokenMap()
        tm.get_or_create_token(
            "John", "PERSON", "test",
            case_sensitive=False,
        )
        meta = tm._token_meta["John"]
        assert meta["case_sensitive"] is False

    def test_to_dict_includes_token_meta(self):
        tm = TokenMap()
        tm.get_or_create_token(
            "repo", "PATH_SEGMENT", "file_path",
            use_word_boundary=True,
        )
        d = tm.to_dict()
        assert "token_meta" in d
        assert "repo" in d["token_meta"]
        assert d["token_meta"]["repo"]["word_boundary"] is True

    def test_from_dict_restores_token_meta(self):
        tm = TokenMap()
        tm.get_or_create_token(
            "repo", "PATH_SEGMENT", "file_path",
            use_word_boundary=True, case_sensitive=True,
            exclude_from_prefilter=False,
        )
        tm.get_or_create_token(
            "secret", "CUSTOM", "plugin",
            exclude_from_prefilter=True, case_sensitive=False,
        )
        d = tm.to_dict()

        restored = TokenMap.from_dict(d)
        assert restored._token_meta["repo"]["word_boundary"] is True
        assert restored._token_meta["repo"]["case_sensitive"] is True
        assert restored._token_meta["secret"]["exclude_from_prefilter"] is True
        assert restored._token_meta["secret"]["case_sensitive"] is False

    def test_round_trip_preserves_scrub_unscrub(self):
        tm = TokenMap()
        token = tm.get_or_create_token(
            "john@test.com", "EMAIL", "presidio",
            use_word_boundary=False, case_sensitive=True,
        )
        d = tm.to_dict()
        restored = TokenMap.from_dict(d)
        assert restored.get_token("john@test.com") == token
        assert restored.get_pii(token) == "john@test.com"


# =====================================================================
# Pre-filter: word boundary matching
# =====================================================================

class TestPreFilterWordBoundary:
    """Tests for _pre_filter_to_placeholders with word_boundary metadata."""

    def _make_token_map_with(self, pii: str, entity_type: str, token: str,
                             word_boundary: bool = False,
                             case_sensitive: bool = True,
                             exclude: bool = False) -> TokenMap:
        """Build a TokenMap with a single pre-populated entry and metadata."""
        tm = TokenMap()
        tm._scrub[pii] = token
        tm._unscrub[token] = pii
        tm._entity_types[pii] = entity_type
        tm._token_meta[pii] = {
            "word_boundary": word_boundary,
            "case_sensitive": case_sensitive,
            "exclude_from_prefilter": exclude,
        }
        return tm

    def test_word_boundary_does_not_match_substring(self):
        """'repo' with word_boundary=True should NOT match inside 'repositories'."""
        tm = self._make_token_map_with(
            "repo", "PATH_SEGMENT", "REDACTED_PATH_SEGMENT_1",
            word_boundary=True,
        )
        text = "Check the repositories folder"
        result, matches, _ = PipelineEngine._pre_filter_to_placeholders(
            text, tm, 0, [],
        )
        # "repo" should NOT be replaced inside "repositories"
        assert "repositories" in result
        assert len(matches) == 0

    def test_word_boundary_matches_standalone_word(self):
        """'repo' with word_boundary=True should match standalone 'repo'."""
        tm = self._make_token_map_with(
            "repo", "PATH_SEGMENT", "REDACTED_PATH_SEGMENT_1",
            word_boundary=True,
        )
        text = "Clone the repo now"
        result, matches, _ = PipelineEngine._pre_filter_to_placeholders(
            text, tm, 0, [],
        )
        assert "repo" not in result
        assert len(matches) == 1
        assert matches[0].pii_text == "repo"

    def test_no_word_boundary_matches_substring(self):
        """'repo' with word_boundary=False SHOULD match inside 'repositories'."""
        tm = self._make_token_map_with(
            "repo", "PATH_SEGMENT", "REDACTED_PATH_SEGMENT_1",
            word_boundary=False,
        )
        text = "Check the repositories folder"
        result, matches, _ = PipelineEngine._pre_filter_to_placeholders(
            text, tm, 0, [],
        )
        # "repo" should be replaced (substring match)
        assert "repo" not in result
        assert len(matches) == 1

    def test_word_boundary_multiple_standalone_occurrences(self):
        """Word boundary matching should replace all standalone occurrences."""
        tm = self._make_token_map_with(
            "data", "PATH_SEGMENT", "REDACTED_PATH_SEGMENT_1",
            word_boundary=True,
        )
        text = "The data is in data folder, not database"
        result, matches, counter = PipelineEngine._pre_filter_to_placeholders(
            text, tm, 0, [],
        )
        # "data" standalone should be replaced (twice), but not inside "database"
        assert "database" in result
        assert len(matches) == 1  # one PreFilterMatch entry (deduped by PII text)
        assert counter == 2  # two placeholder entries created


# =====================================================================
# Pre-filter: case sensitivity
# =====================================================================

class TestPreFilterCaseSensitivity:
    def _make_token_map_with(self, pii: str, entity_type: str, token: str,
                             word_boundary: bool = False,
                             case_sensitive: bool = True,
                             exclude: bool = False) -> TokenMap:
        tm = TokenMap()
        tm._scrub[pii] = token
        tm._unscrub[token] = pii
        tm._entity_types[pii] = entity_type
        tm._token_meta[pii] = {
            "word_boundary": word_boundary,
            "case_sensitive": case_sensitive,
            "exclude_from_prefilter": exclude,
        }
        return tm

    def test_case_insensitive_matches_different_case(self):
        """'John' with case_sensitive=False should match 'john' and 'JOHN'."""
        tm = self._make_token_map_with(
            "John", "PERSON", "REDACTED_PERSON_1",
            case_sensitive=False,
        )
        text = "Talk to john or JOHN about it"
        result, matches, counter = PipelineEngine._pre_filter_to_placeholders(
            text, tm, 0, [],
        )
        # Both "john" and "JOHN" should be replaced
        assert "john" not in result.lower() or "§§§" in result
        assert len(matches) == 1
        assert counter == 2  # two occurrences

    def test_case_sensitive_does_not_match_different_case(self):
        """Default case_sensitive=True should NOT match different case."""
        tm = self._make_token_map_with(
            "John", "PERSON", "REDACTED_PERSON_1",
            case_sensitive=True,
        )
        text = "Talk to john about it"
        result, matches, _ = PipelineEngine._pre_filter_to_placeholders(
            text, tm, 0, [],
        )
        # "john" (lowercase) should NOT match "John" (case sensitive)
        assert "john" in result
        assert len(matches) == 0

    def test_case_sensitive_matches_exact_case(self):
        """case_sensitive=True should match the exact cased string."""
        tm = self._make_token_map_with(
            "John", "PERSON", "REDACTED_PERSON_1",
            case_sensitive=True,
        )
        text = "Talk to John about it"
        result, matches, _ = PipelineEngine._pre_filter_to_placeholders(
            text, tm, 0, [],
        )
        assert "John" not in result
        assert len(matches) == 1

    def test_case_insensitive_with_word_boundary(self):
        """Combined case_sensitive=False + word_boundary=True."""
        tm = self._make_token_map_with(
            "Data", "PATH_SEGMENT", "REDACTED_PATH_SEGMENT_1",
            word_boundary=True, case_sensitive=False,
        )
        text = "The data is in DATA folder, not database"
        result, matches, counter = PipelineEngine._pre_filter_to_placeholders(
            text, tm, 0, [],
        )
        # "data" and "DATA" standalone should match, but not "database"
        assert "database" in result
        assert len(matches) == 1
        assert counter == 2


# =====================================================================
# Pre-filter: exclude_from_prefilter
# =====================================================================

class TestPreFilterExclusion:
    def _make_token_map_with(self, pii: str, entity_type: str, token: str,
                             exclude: bool = False) -> TokenMap:
        tm = TokenMap()
        tm._scrub[pii] = token
        tm._unscrub[token] = pii
        tm._entity_types[pii] = entity_type
        tm._token_meta[pii] = {
            "word_boundary": False,
            "case_sensitive": True,
            "exclude_from_prefilter": exclude,
        }
        return tm

    def test_excluded_token_not_replaced(self):
        """Token with exclude_from_prefilter=True should be skipped."""
        tm = self._make_token_map_with(
            "secret_value", "CUSTOM", "REDACTED_CUSTOM_1",
            exclude=True,
        )
        text = "The secret_value is here"
        result, matches, _ = PipelineEngine._pre_filter_to_placeholders(
            text, tm, 0, [],
        )
        # Should NOT be replaced
        assert "secret_value" in result
        assert len(matches) == 0

    def test_non_excluded_token_is_replaced(self):
        """Token without exclude should be replaced normally."""
        tm = self._make_token_map_with(
            "secret_value", "CUSTOM", "REDACTED_CUSTOM_1",
            exclude=False,
        )
        text = "The secret_value is here"
        result, matches, _ = PipelineEngine._pre_filter_to_placeholders(
            text, tm, 0, [],
        )
        assert "secret_value" not in result
        assert len(matches) == 1


# =====================================================================
# _PlaceholderEntry new fields
# =====================================================================

class TestPlaceholderEntryFields:
    def test_defaults(self):
        entry = _PlaceholderEntry(
            placeholder="§§§SCRX0001§§§",
            pii_text="John",
            entity_type="PERSON",
            score=0.9,
            source="presidio",
        )
        assert entry.use_word_boundary is False
        assert entry.case_sensitive is True
        assert entry.exclude_from_prefilter is False

    def test_custom_values(self):
        entry = _PlaceholderEntry(
            placeholder="§§§SCRX0002§§§",
            pii_text="repo",
            entity_type="PATH_SEGMENT",
            score=0.95,
            source="file_path",
            use_word_boundary=True,
            case_sensitive=False,
            exclude_from_prefilter=True,
        )
        assert entry.use_word_boundary is True
        assert entry.case_sensitive is False
        assert entry.exclude_from_prefilter is True


# =====================================================================
# Pipeline engine: stage-level flags propagation
# =====================================================================

class _FakeStage:
    """Minimal stage that returns canned detections."""

    def __init__(self, entities, *, use_word_boundary=False,
                 case_sensitive=True, exclude_from_prefilter=False):
        self._entities = entities
        self.enabled = True
        self.use_word_boundary = use_word_boundary
        self.case_sensitive = case_sensitive
        self.exclude_from_prefilter = exclude_from_prefilter

    async def detect(self, text: str, language: str) -> list[PiiEntity]:
        return self._entities


class TestEngineStagePropagation:
    @pytest.mark.asyncio
    async def test_stage_word_boundary_propagated_to_token_map(self):
        """When a stage has use_word_boundary=True and the entity object lacks
        the attribute, the stage default should propagate to the token map."""

        # Use a bare entity-like object without use_word_boundary / case_sensitive
        # so getattr falls through to stage defaults.
        class _BareEntity:
            def __init__(self):
                self.entity_type = "PATH_SEGMENT"
                self.start = 0
                self.end = 4
                self.score = 0.95
                self.source = "file_path"

        class _BareStage:
            enabled = True
            use_word_boundary = True
            case_sensitive = True
            exclude_from_prefilter = False

            async def detect(self, text, language):
                return [_BareEntity()]

        engine = PipelineEngine(stages=[_BareStage()])
        engine.pre_filter_enabled = False
        tm = TokenMap()

        await engine.scrub_text("repo", tm, context=None)
        assert "repo" in tm._token_meta
        assert tm._token_meta["repo"]["word_boundary"] is True

    @pytest.mark.asyncio
    async def test_stage_exclude_propagated_to_token_map(self):
        """When a stage has exclude_from_prefilter=True, tokens stored in the
        map should have exclude_from_prefilter metadata set."""
        entity = PiiEntity(
            entity_type="CUSTOM", start=0, end=6, score=0.8,
            source="plugin",
        )
        stage = _FakeStage(
            [entity],
            exclude_from_prefilter=True,
        )

        engine = PipelineEngine(stages=[stage])
        engine.pre_filter_enabled = False
        tm = TokenMap()

        result = await engine.scrub_text("secret", tm, context=None)
        assert "secret" in tm._token_meta
        assert tm._token_meta["secret"]["exclude_from_prefilter"] is True

    @pytest.mark.asyncio
    async def test_entity_level_overrides_stage_defaults(self):
        """Entity-level use_word_boundary should override the stage default."""
        entity = PiiEntity(
            entity_type="PERSON", start=0, end=4, score=0.9,
            source="test", use_word_boundary=True,
        )
        # Stage default is False, but entity says True
        stage = _FakeStage(
            [entity],
            use_word_boundary=False,
        )

        engine = PipelineEngine(stages=[stage])
        engine.pre_filter_enabled = False
        tm = TokenMap()

        await engine.scrub_text("John", tm, context=None)
        assert tm._token_meta["John"]["word_boundary"] is True

    @pytest.mark.asyncio
    async def test_scrub_replaces_pii_with_token(self):
        """Basic integration: PII text should be replaced in scrubbed output."""
        entity = PiiEntity(
            entity_type="PERSON", start=10, end=14, score=0.9,
            source="test",
        )
        stage = _FakeStage([entity])

        engine = PipelineEngine(stages=[stage])
        engine.pre_filter_enabled = False
        tm = TokenMap()

        result = await engine.scrub_text("Hello Mr. John!", tm, context=None)
        assert "REDACTED_PERSON_1" in result.scrubbed_text
        assert "John" not in result.scrubbed_text


# =====================================================================
# FilePathDetector use_word_boundary attribute
# =====================================================================

class TestFilePathDetectorWordBoundary:
    def test_has_use_word_boundary_true(self):
        from scruxy.plugin.file_path import FilePathDetector
        assert FilePathDetector.use_word_boundary is True

    def test_has_case_sensitive_true(self):
        from scruxy.plugin.file_path import FilePathDetector
        assert FilePathDetector.case_sensitive is True
