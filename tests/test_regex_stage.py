"""Tests for the regex-based PII detection plugin."""
from __future__ import annotations

import pytest

from scruxy.plugin.regex import PiiEntity, RegexPlugin, RegexStage


def _make_regex_plugin(patterns: list[dict]) -> RegexPlugin:
    """Create a RegexPlugin and set it up with the given patterns."""
    plugin = RegexPlugin()
    plugin.setup({"patterns": patterns})
    return plugin


class TestRegexPluginSetup:
    """Test RegexPlugin setup and configuration via setup(config)."""

    def test_compiles_valid_patterns(self):
        """Valid patterns are compiled and stored."""
        patterns = [
            {
                "name": "ssn",
                "entity_type": "US_SSN",
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "score": 0.8,
            },
            {
                "name": "email",
                "entity_type": "EMAIL_ADDRESS",
                "pattern": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
                "score": 0.9,
            },
        ]
        plugin = _make_regex_plugin(patterns)
        assert len(plugin._patterns) == 2

    def test_skips_invalid_regex(self):
        """Patterns with invalid regex are skipped with a warning."""
        patterns = [
            {
                "name": "bad_pattern",
                "entity_type": "UNKNOWN",
                "pattern": r"[invalid",
                "score": 0.5,
            },
            {
                "name": "good_pattern",
                "entity_type": "US_SSN",
                "pattern": r"\d{3}-\d{2}-\d{4}",
                "score": 0.8,
            },
        ]
        plugin = _make_regex_plugin(patterns)
        assert len(plugin._patterns) == 1
        assert plugin._patterns[0].name == "good_pattern"

    def test_empty_patterns_list(self):
        """Empty patterns list results in no compiled patterns."""
        plugin = _make_regex_plugin([])
        assert len(plugin._patterns) == 0

    def test_patterns_with_context_words(self):
        """Context words are stored on compiled patterns."""
        patterns = [
            {
                "name": "phone",
                "entity_type": "PHONE_NUMBER",
                "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
                "score": 0.6,
                "context_words": ["phone", "call", "tel"],
            },
        ]
        plugin = _make_regex_plugin(patterns)
        assert plugin._patterns[0].context_words == ["phone", "call", "tel"]

    def test_patterns_without_context_words_defaults_to_empty(self):
        """Patterns without context_words default to an empty list."""
        patterns = [
            {
                "name": "ssn",
                "entity_type": "US_SSN",
                "pattern": r"\d{3}-\d{2}-\d{4}",
                "score": 0.8,
            },
        ]
        plugin = _make_regex_plugin(patterns)
        assert plugin._patterns[0].context_words == []

    def test_setup_from_patterns_file(self, tmp_path):
        """setup() loads patterns from a YAML file."""
        patterns_file = tmp_path / "patterns.yaml"
        patterns_file.write_text(
            "regex_patterns:\n"
            "  - name: ssn\n"
            "    entity_type: US_SSN\n"
            '    pattern: "\\\\d{3}-\\\\d{2}-\\\\d{4}"\n'
            "    score: 0.8\n"
        )
        plugin = RegexPlugin()
        plugin.setup({"patterns_file": str(patterns_file)})
        assert len(plugin._patterns) == 1


class TestRegexPluginDetect:
    """Test RegexPlugin.detect() method."""

    def test_detect_single_match(self):
        """Detects a single regex match and returns correct PiiEntity."""
        plugin = _make_regex_plugin([
            {
                "name": "ssn",
                "entity_type": "US_SSN",
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "score": 0.8,
            },
        ])
        results = plugin.detect("My SSN is 123-45-6789 thanks.", "en")
        assert len(results) == 1
        entity = results[0]
        assert entity.entity_type == "US_SSN"
        assert entity.start == 10
        assert entity.end == 21
        assert entity.score == 0.8
        assert entity.source == "regex"

    def test_detect_multiple_matches_same_pattern(self):
        """Detects multiple matches from the same pattern."""
        plugin = _make_regex_plugin([
            {
                "name": "ssn",
                "entity_type": "US_SSN",
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "score": 0.8,
            },
        ])
        results = plugin.detect("SSNs: 123-45-6789 and 987-65-4321.", "en")
        assert len(results) == 2
        assert results[0].entity_type == "US_SSN"
        assert results[1].entity_type == "US_SSN"

    def test_detect_multiple_patterns(self):
        """Detects matches from multiple patterns."""
        plugin = _make_regex_plugin([
            {
                "name": "ssn",
                "entity_type": "US_SSN",
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "score": 0.8,
            },
            {
                "name": "email",
                "entity_type": "EMAIL_ADDRESS",
                "pattern": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
                "score": 0.9,
            },
        ])
        results = plugin.detect("SSN 123-45-6789 email test@example.com", "en")
        entity_types = {e.entity_type for e in results}
        assert "US_SSN" in entity_types
        assert "EMAIL_ADDRESS" in entity_types

    def test_detect_no_match(self):
        """Returns empty list when no pattern matches."""
        plugin = _make_regex_plugin([
            {
                "name": "ssn",
                "entity_type": "US_SSN",
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "score": 0.8,
            },
        ])
        results = plugin.detect("No PII data here.", "en")
        assert results == []

    def test_detect_empty_text(self):
        """Returns empty list for empty text."""
        plugin = _make_regex_plugin([
            {
                "name": "ssn",
                "entity_type": "US_SSN",
                "pattern": r"\d{3}-\d{2}-\d{4}",
                "score": 0.8,
            },
        ])
        results = plugin.detect("", "en")
        assert results == []

    def test_detect_entity_positions_are_correct(self):
        """Start and end offsets accurately reflect the match position."""
        text = "Contact: 555-12-3456"
        plugin = _make_regex_plugin([
            {
                "name": "ssn",
                "entity_type": "US_SSN",
                "pattern": r"\d{3}-\d{2}-\d{4}",
                "score": 0.8,
            },
        ])
        results = plugin.detect(text, "en")
        assert len(results) == 1
        assert text[results[0].start : results[0].end] == "555-12-3456"


class TestContextWordBoosting:
    """Test context-word score boosting behavior."""

    def test_context_word_boosts_score(self):
        """Score is boosted by 0.1 when a context word is found within 50 chars."""
        plugin = _make_regex_plugin([
            {
                "name": "phone",
                "entity_type": "PHONE_NUMBER",
                "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
                "score": 0.6,
                "context_words": ["phone", "call", "tel"],
            },
        ])
        results = plugin.detect("Please phone us at 555-123-4567 today.", "en")
        assert len(results) == 1
        assert results[0].score == pytest.approx(0.7)

    def test_context_word_case_insensitive(self):
        """Context word matching is case-insensitive."""
        plugin = _make_regex_plugin([
            {
                "name": "phone",
                "entity_type": "PHONE_NUMBER",
                "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
                "score": 0.6,
                "context_words": ["phone"],
            },
        ])
        results = plugin.detect("PHONE: 555-123-4567", "en")
        assert len(results) == 1
        assert results[0].score == pytest.approx(0.7)

    def test_no_boost_without_context_word(self):
        """Score is not boosted when no context word is found nearby."""
        plugin = _make_regex_plugin([
            {
                "name": "phone",
                "entity_type": "PHONE_NUMBER",
                "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
                "score": 0.6,
                "context_words": ["phone", "call", "tel"],
            },
        ])
        results = plugin.detect("Number is 555-123-4567 for you.", "en")
        assert len(results) == 1
        assert results[0].score == pytest.approx(0.6)

    def test_context_word_outside_window_no_boost(self):
        """Context word beyond 50 chars from match does not boost score."""
        # 'phone' is placed > 50 chars before the match
        padding = "x" * 60
        text = f"phone {padding} 555-123-4567"
        plugin = _make_regex_plugin([
            {
                "name": "phone",
                "entity_type": "PHONE_NUMBER",
                "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
                "score": 0.6,
                "context_words": ["phone"],
            },
        ])
        results = plugin.detect(text, "en")
        assert len(results) == 1
        assert results[0].score == pytest.approx(0.6)

    def test_context_word_within_window_boosts(self):
        """Context word within 50 chars before or after the match boosts score."""
        # 'phone' placed within 50 chars after the match
        text = "Call 555-123-4567 phone number"
        plugin = _make_regex_plugin([
            {
                "name": "phone",
                "entity_type": "PHONE_NUMBER",
                "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
                "score": 0.6,
                "context_words": ["phone"],
            },
        ])
        results = plugin.detect(text, "en")
        assert len(results) == 1
        assert results[0].score == pytest.approx(0.7)

    def test_score_capped_at_1_0(self):
        """Boosted score is capped at 1.0."""
        plugin = _make_regex_plugin([
            {
                "name": "phone",
                "entity_type": "PHONE_NUMBER",
                "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
                "score": 0.95,
                "context_words": ["phone"],
            },
        ])
        results = plugin.detect("phone 555-123-4567", "en")
        assert len(results) == 1
        assert results[0].score == pytest.approx(1.0)

    def test_score_exactly_1_0_not_boosted_beyond(self):
        """Score of 1.0 remains at 1.0 after context boost attempt."""
        plugin = _make_regex_plugin([
            {
                "name": "phone",
                "entity_type": "PHONE_NUMBER",
                "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
                "score": 1.0,
                "context_words": ["phone"],
            },
        ])
        results = plugin.detect("phone 555-123-4567", "en")
        assert len(results) == 1
        assert results[0].score == pytest.approx(1.0)

    def test_no_context_words_means_no_boost(self):
        """Patterns without context_words never get score boosted."""
        plugin = _make_regex_plugin([
            {
                "name": "ssn",
                "entity_type": "US_SSN",
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "score": 0.8,
            },
        ])
        results = plugin.detect("phone SSN 123-45-6789 call tel", "en")
        assert len(results) == 1
        assert results[0].score == pytest.approx(0.8)

    def test_multiple_context_words_only_one_boost(self):
        """Even if multiple context words match, score is only boosted once (+0.1)."""
        plugin = _make_regex_plugin([
            {
                "name": "phone",
                "entity_type": "PHONE_NUMBER",
                "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
                "score": 0.6,
                "context_words": ["phone", "call", "tel"],
            },
        ])
        results = plugin.detect("phone call tel 555-123-4567", "en")
        assert len(results) == 1
        # Only one boost of 0.1, not 0.3
        assert results[0].score == pytest.approx(0.7)


class TestRegexPluginInlineYaml:
    """Test the patterns_yaml inline text field."""

    def test_inline_yaml_patterns_parsed(self):
        """patterns_yaml YAML text is parsed and patterns are compiled."""
        yaml_text = (
            "regex_patterns:\n"
            "  - name: test_id\n"
            "    entity_type: TEST_ID\n"
            '    pattern: "T-\\\\d{4}"\n'
            "    score: 0.85\n"
        )
        plugin = RegexPlugin()
        plugin.setup({"patterns_yaml": yaml_text})
        assert len(plugin._patterns) == 1
        assert plugin._patterns[0].entity_type == "TEST_ID"

    def test_inline_yaml_merged_with_file(self, tmp_path):
        """Patterns from file and inline YAML are merged (file first)."""
        patterns_file = tmp_path / "patterns.yaml"
        patterns_file.write_text(
            "regex_patterns:\n"
            "  - name: file_pat\n"
            "    entity_type: FILE_TYPE\n"
            '    pattern: "F-\\\\d{3}"\n'
            "    score: 0.7\n"
        )
        inline_yaml = (
            "regex_patterns:\n"
            "  - name: inline_pat\n"
            "    entity_type: INLINE_TYPE\n"
            '    pattern: "I-\\\\d{3}"\n'
            "    score: 0.8\n"
        )
        plugin = RegexPlugin()
        plugin.setup({
            "patterns_file": str(patterns_file),
            "patterns_yaml": inline_yaml,
        })
        assert len(plugin._patterns) == 2
        types = {p.entity_type for p in plugin._patterns}
        assert "FILE_TYPE" in types
        assert "INLINE_TYPE" in types

    def test_inline_yaml_merged_with_raw_patterns(self):
        """Inline YAML patterns merge with raw patterns list."""
        inline_yaml = (
            "regex_patterns:\n"
            "  - name: inline_pat\n"
            "    entity_type: INLINE_TYPE\n"
            '    pattern: "I-\\\\d{3}"\n'
            "    score: 0.8\n"
        )
        raw_patterns = [
            {
                "name": "raw_pat",
                "entity_type": "RAW_TYPE",
                "pattern": r"R-\d{3}",
                "score": 0.9,
            },
        ]
        plugin = RegexPlugin()
        plugin.setup({
            "patterns_yaml": inline_yaml,
            "patterns": raw_patterns,
        })
        assert len(plugin._patterns) == 2

    def test_invalid_inline_yaml_skipped(self):
        """Invalid YAML in patterns_yaml is logged as warning and skipped."""
        plugin = RegexPlugin()
        plugin.setup({"patterns_yaml": "invalid: yaml: [: broken"})
        assert len(plugin._patterns) == 0

    def test_inline_yaml_non_dict_skipped(self):
        """Non-dict YAML result in patterns_yaml is skipped."""
        plugin = RegexPlugin()
        plugin.setup({"patterns_yaml": "just a string"})
        assert len(plugin._patterns) == 0

    def test_inline_yaml_empty_string(self):
        """Empty string patterns_yaml is handled gracefully."""
        plugin = RegexPlugin()
        plugin.setup({"patterns_yaml": ""})
        assert len(plugin._patterns) == 0

    def test_inline_yaml_with_comments_only(self):
        """YAML with only comments parses to None, handled gracefully."""
        plugin = RegexPlugin()
        plugin.setup({"patterns_yaml": "# just a comment\n# another comment\n"})
        assert len(plugin._patterns) == 0

    def test_config_schema_patterns_file_has_file_type(self):
        """RegexPlugin.config_schema patterns_file uses file field type."""
        schema = RegexPlugin.config_schema
        pf_field = next(f for f in schema if f.name == "patterns_file")
        assert pf_field.field_type == "file"
        assert pf_field.label == "Patterns File"
        assert pf_field.details != ""


class TestRegexPluginAttributes:
    """Test RegexPlugin class attributes and DetectorPlugin compliance."""

    def test_class_attributes(self):
        """RegexPlugin has correct class attributes."""
        assert RegexPlugin.name == "regex"
        assert RegexPlugin.plugin_type == "builtin"
        assert RegexPlugin.version == "built-in"
        assert RegexPlugin.enabled is True

    def test_config_schema_fields(self):
        """RegexPlugin.config_schema declares expected fields."""
        schema = RegexPlugin.config_schema
        field_names = [f.name for f in schema]
        assert "patterns_file" in field_names

        pf_field = next(f for f in schema if f.name == "patterns_file")
        assert pf_field.field_type == "file"

    def test_inherits_detector_plugin(self):
        """RegexPlugin is a subclass of DetectorPlugin."""
        from scruxy.plugin.base import DetectorPlugin

        assert issubclass(RegexPlugin, DetectorPlugin)


class TestBackwardCompatAlias:
    """Test that the RegexStage backward-compatibility alias works."""

    def test_regex_stage_alias(self):
        """RegexStage is an alias for RegexPlugin."""
        assert RegexStage is RegexPlugin


class TestRegexPluginPiiEntity:
    """Test PiiEntity dataclass from regex_stage module."""

    def test_source_is_regex(self):
        """All entities from RegexPlugin have source='regex'."""
        plugin = _make_regex_plugin([
            {
                "name": "email",
                "entity_type": "EMAIL_ADDRESS",
                "pattern": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
                "score": 0.9,
            },
        ])
        results = plugin.detect("email: user@test.com", "en")
        for entity in results:
            assert entity.source == "regex"
