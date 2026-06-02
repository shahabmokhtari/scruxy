"""Tests for plugin base (DetectorPlugin ABC, PiiEntity) and pipeline models."""
from __future__ import annotations

import re
from abc import ABC

import pytest

from scruxy.pipeline.models import PipelineContext, PipelineResult
from scruxy.plugin.base import ConfigField, DetectorPlugin, PiiEntity


# ---------------------------------------------------------------------------
# Concrete plugin for testing (minimal implementation)
# ---------------------------------------------------------------------------


class _StubDetector(DetectorPlugin):
    """Minimal concrete detector for testing the ABC contract."""

    name = "stub_detector"
    version = "0.1"

    def setup(self, config: dict) -> None:
        self.configured = True
        self.config = config

    def detect(self, text: str, language: str) -> list[PiiEntity]:
        return []

    def teardown(self) -> None:
        self.configured = False


class _KeywordDetector(DetectorPlugin):
    """Detector that finds exact keyword occurrences."""

    name = "keyword_detector"
    version = "1.0"

    def setup(self, config: dict) -> None:
        self.keywords: list[str] = config.get("keywords", [])

    def detect(self, text: str, language: str) -> list[PiiEntity]:
        results: list[PiiEntity] = []
        for kw in self.keywords:
            start = 0
            while True:
                idx = text.find(kw, start)
                if idx == -1:
                    break
                results.append(
                    PiiEntity(
                        entity_type="KEYWORD",
                        start=idx,
                        end=idx + len(kw),
                        score=0.9,
                        source=self.name,
                    )
                )
                start = idx + 1
        return results


# ===========================================================================
# PiiEntity tests
# ===========================================================================


class TestPiiEntity:
    """Tests for the PiiEntity dataclass."""

    def test_basic_creation(self):
        entity = PiiEntity(
            entity_type="EMAIL",
            start=0,
            end=15,
            score=0.99,
            source="presidio",
        )
        assert entity.entity_type == "EMAIL"
        assert entity.start == 0
        assert entity.end == 15
        assert entity.score == 0.99
        assert entity.source == "presidio"

    def test_span_length(self):
        entity = PiiEntity(
            entity_type="PERSON", start=5, end=15, score=0.8, source="test"
        )
        assert entity.span_length == 10

    def test_overlaps_true(self):
        a = PiiEntity(entity_type="A", start=0, end=10, score=0.9, source="s")
        b = PiiEntity(entity_type="B", start=5, end=15, score=0.9, source="s")
        assert a.overlaps(b) is True
        assert b.overlaps(a) is True

    def test_overlaps_contained(self):
        outer = PiiEntity(entity_type="A", start=0, end=20, score=0.9, source="s")
        inner = PiiEntity(entity_type="B", start=5, end=10, score=0.9, source="s")
        assert outer.overlaps(inner) is True
        assert inner.overlaps(outer) is True

    def test_no_overlap_adjacent(self):
        a = PiiEntity(entity_type="A", start=0, end=5, score=0.9, source="s")
        b = PiiEntity(entity_type="B", start=5, end=10, score=0.9, source="s")
        assert a.overlaps(b) is False
        assert b.overlaps(a) is False

    def test_no_overlap_disjoint(self):
        a = PiiEntity(entity_type="A", start=0, end=5, score=0.9, source="s")
        b = PiiEntity(entity_type="B", start=10, end=15, score=0.9, source="s")
        assert a.overlaps(b) is False
        assert b.overlaps(a) is False

    def test_equality(self):
        e1 = PiiEntity(entity_type="X", start=0, end=5, score=0.5, source="s")
        e2 = PiiEntity(entity_type="X", start=0, end=5, score=0.5, source="s")
        assert e1 == e2

    def test_inequality_different_type(self):
        e1 = PiiEntity(entity_type="X", start=0, end=5, score=0.5, source="s")
        e2 = PiiEntity(entity_type="Y", start=0, end=5, score=0.5, source="s")
        assert e1 != e2

    # --- Validation ---

    def test_negative_start_raises(self):
        with pytest.raises(ValueError, match="start must be >= 0"):
            PiiEntity(entity_type="X", start=-1, end=5, score=0.5, source="s")

    def test_end_not_greater_than_start_raises(self):
        with pytest.raises(ValueError, match="end.*must be greater than start"):
            PiiEntity(entity_type="X", start=5, end=5, score=0.5, source="s")

    def test_end_before_start_raises(self):
        with pytest.raises(ValueError, match="end.*must be greater than start"):
            PiiEntity(entity_type="X", start=10, end=5, score=0.5, source="s")

    def test_score_below_zero_raises(self):
        with pytest.raises(ValueError, match="score must be in"):
            PiiEntity(entity_type="X", start=0, end=5, score=-0.1, source="s")

    def test_score_above_one_raises(self):
        with pytest.raises(ValueError, match="score must be in"):
            PiiEntity(entity_type="X", start=0, end=5, score=1.01, source="s")

    def test_empty_entity_type_raises(self):
        with pytest.raises(ValueError, match="entity_type must be a non-empty"):
            PiiEntity(entity_type="", start=0, end=5, score=0.5, source="s")

    def test_empty_source_raises(self):
        with pytest.raises(ValueError, match="source must be a non-empty"):
            PiiEntity(entity_type="X", start=0, end=5, score=0.5, source="")

    def test_boundary_score_zero(self):
        entity = PiiEntity(entity_type="X", start=0, end=1, score=0.0, source="s")
        assert entity.score == 0.0

    def test_boundary_score_one(self):
        entity = PiiEntity(entity_type="X", start=0, end=1, score=1.0, source="s")
        assert entity.score == 1.0

    def test_start_zero_end_one(self):
        entity = PiiEntity(entity_type="X", start=0, end=1, score=0.5, source="s")
        assert entity.span_length == 1


# ===========================================================================
# DetectorPlugin ABC tests
# ===========================================================================


class TestDetectorPluginABC:
    """Tests for the DetectorPlugin abstract base class."""

    def test_is_abstract(self):
        assert issubclass(DetectorPlugin, ABC)

    def test_cannot_instantiate_abc_directly(self):
        with pytest.raises(TypeError):
            DetectorPlugin()  # type: ignore[abstract]

    def test_must_implement_setup(self):
        """A subclass missing setup() cannot be instantiated."""

        class _NoSetup(DetectorPlugin):
            name = "bad"
            version = "1.0"

            def detect(self, text: str, language: str) -> list[PiiEntity]:
                return []

        with pytest.raises(TypeError):
            _NoSetup()  # type: ignore[abstract]

    def test_must_implement_detect(self):
        """A subclass missing detect() cannot be instantiated."""

        class _NoDetect(DetectorPlugin):
            name = "bad"
            version = "1.0"

            def setup(self, config: dict) -> None:
                pass

        with pytest.raises(TypeError):
            _NoDetect()  # type: ignore[abstract]

    def test_teardown_has_default(self):
        """teardown() has a default no-op implementation."""
        plugin = _StubDetector()
        # Should not raise
        plugin.teardown()

    def test_stub_setup_and_detect(self):
        plugin = _StubDetector()
        plugin.setup({"key": "value"})
        assert plugin.configured is True
        assert plugin.config == {"key": "value"}
        result = plugin.detect("hello world", "en")
        assert result == []

    def test_stub_teardown(self):
        plugin = _StubDetector()
        plugin.setup({})
        assert plugin.configured is True
        plugin.teardown()
        assert plugin.configured is False

    def test_name_and_version_attributes(self):
        plugin = _StubDetector()
        assert plugin.name == "stub_detector"
        assert plugin.version == "0.1"

    def test_keyword_detector_finds_matches(self):
        plugin = _KeywordDetector()
        plugin.setup({"keywords": ["secret", "password"]})
        entities = plugin.detect("my secret password is secret", "en")
        assert len(entities) == 3  # "secret" x2 + "password" x1
        types = {e.entity_type for e in entities}
        assert types == {"KEYWORD"}

    def test_keyword_detector_no_match(self):
        plugin = _KeywordDetector()
        plugin.setup({"keywords": ["classified"]})
        entities = plugin.detect("nothing special here", "en")
        assert entities == []

    def test_keyword_detector_positions(self):
        plugin = _KeywordDetector()
        plugin.setup({"keywords": ["PII"]})
        text = "PII at start, PII in middle"
        entities = plugin.detect(text, "en")
        assert len(entities) == 2
        assert entities[0].start == 0
        assert entities[0].end == 3
        assert entities[1].start == 14
        assert entities[1].end == 17
        # Verify the text slices match
        for e in entities:
            assert text[e.start : e.end] == "PII"


# ===========================================================================
# ConfigField tests
# ===========================================================================


class TestConfigField:
    """Tests for the ConfigField dataclass."""

    def test_basic_creation(self):
        field = ConfigField(name="pattern", field_type="string")
        assert field.name == "pattern"
        assert field.field_type == "string"
        assert field.default is None
        assert field.description == ""
        assert field.choices is None
        assert field.min_value is None
        assert field.max_value is None

    def test_string_field(self):
        field = ConfigField(
            name="pattern",
            field_type="string",
            default=r"BADGE-\d{4}",
            description="Regex for badge numbers",
        )
        assert field.field_type == "string"
        assert field.default == r"BADGE-\d{4}"
        assert field.description == "Regex for badge numbers"

    def test_number_field_with_bounds(self):
        field = ConfigField(
            name="threshold",
            field_type="number",
            default=0.5,
            min_value=0.0,
            max_value=1.0,
            description="Confidence threshold",
        )
        assert field.field_type == "number"
        assert field.default == 0.5
        assert field.min_value == 0.0
        assert field.max_value == 1.0

    def test_boolean_field(self):
        field = ConfigField(
            name="case_sensitive",
            field_type="boolean",
            default=False,
            description="Whether matching is case-sensitive",
        )
        assert field.field_type == "boolean"
        assert field.default is False

    def test_select_field(self):
        field = ConfigField(
            name="mode",
            field_type="select",
            default="strict",
            choices=["strict", "relaxed", "off"],
            description="Detection mode",
        )
        assert field.field_type == "select"
        assert field.default == "strict"
        assert field.choices == ["strict", "relaxed", "off"]

    def test_list_field(self):
        field = ConfigField(
            name="keywords",
            field_type="list",
            default=["alpha", "beta"],
            description="Keywords to detect",
        )
        assert field.field_type == "list"
        assert field.default == ["alpha", "beta"]

    def test_label_defaults_to_empty(self):
        field = ConfigField(name="test", field_type="string")
        assert field.label == ""

    def test_details_defaults_to_empty(self):
        field = ConfigField(name="test", field_type="string")
        assert field.details == ""

    def test_label_and_details_set(self):
        field = ConfigField(
            name="threshold",
            field_type="number",
            label="Confidence Threshold",
            details="Recommended range: 0.3 to 0.7",
        )
        assert field.label == "Confidence Threshold"
        assert field.details == "Recommended range: 0.3 to 0.7"

    def test_text_field_type(self):
        field = ConfigField(
            name="patterns_yaml",
            field_type="text",
            default="# yaml content",
            label="Inline Patterns",
            details="Enter YAML format patterns here",
        )
        assert field.field_type == "text"
        assert field.default == "# yaml content"
        assert field.label == "Inline Patterns"
        assert field.details == "Enter YAML format patterns here"

    def test_backward_compatible_without_label_details(self):
        """Existing ConfigField usage without label/details still works."""
        field = ConfigField(
            name="model",
            field_type="string",
            default="en_core_web_lg",
            description="spaCy model",
        )
        assert field.label == ""
        assert field.details == ""

    def test_all_fields_set(self):
        field = ConfigField(
            name="language",
            field_type="select",
            default="en",
            description="Language code",
            choices=["en", "es", "de"],
            min_value=None,
            max_value=None,
            label="Language",
            details="Select the language for analysis",
        )
        assert field.choices == ["en", "es", "de"]
        assert field.label == "Language"
        assert field.details == "Select the language for analysis"

    def test_equality(self):
        f1 = ConfigField(name="x", field_type="string", default="a")
        f2 = ConfigField(name="x", field_type="string", default="a")
        assert f1 == f2

    def test_inequality(self):
        f1 = ConfigField(name="x", field_type="string")
        f2 = ConfigField(name="y", field_type="string")
        assert f1 != f2

    def test_equality_with_label_details(self):
        f1 = ConfigField(name="x", field_type="string", label="X", details="info")
        f2 = ConfigField(name="x", field_type="string", label="X", details="info")
        assert f1 == f2

    def test_inequality_different_label(self):
        f1 = ConfigField(name="x", field_type="string", label="A")
        f2 = ConfigField(name="x", field_type="string", label="B")
        assert f1 != f2


# ===========================================================================
# DetectorPlugin new attributes tests
# ===========================================================================


class TestDetectorPluginDefaults:
    """Tests for config_schema, enabled, and plugin_type defaults on DetectorPlugin."""

    def test_default_config_schema_is_empty_list(self):
        plugin = _StubDetector()
        assert plugin.config_schema == []

    def test_default_enabled_is_true(self):
        plugin = _StubDetector()
        assert plugin.enabled is True

    def test_default_plugin_type_is_user(self):
        plugin = _StubDetector()
        assert plugin.plugin_type == "user"

    def test_config_schema_independent_between_instances(self):
        """config_schema default list is shared across instances (class attr),
        but setting it on a subclass isolates it."""
        p1 = _StubDetector()
        p2 = _StubDetector()
        # Both point to the same class-level default
        assert p1.config_schema is p2.config_schema
        assert p1.config_schema == []

    def test_subclass_can_override_config_schema(self):
        class _CustomSchema(DetectorPlugin):
            name = "custom_schema"
            version = "1.0"
            config_schema = [
                ConfigField(name="key", field_type="string", default="val"),
            ]

            def setup(self, config: dict) -> None:
                pass

            def detect(self, text: str, language: str) -> list[PiiEntity]:
                return []

        plugin = _CustomSchema()
        assert len(plugin.config_schema) == 1
        assert plugin.config_schema[0].name == "key"

    def test_subclass_can_override_enabled(self):
        class _DisabledPlugin(DetectorPlugin):
            name = "disabled"
            version = "1.0"
            enabled = False

            def setup(self, config: dict) -> None:
                pass

            def detect(self, text: str, language: str) -> list[PiiEntity]:
                return []

        plugin = _DisabledPlugin()
        assert plugin.enabled is False

    def test_subclass_can_set_builtin_type(self):
        class _BuiltinPlugin(DetectorPlugin):
            name = "builtin"
            version = "1.0"
            plugin_type = "builtin"

            def setup(self, config: dict) -> None:
                pass

            def detect(self, text: str, language: str) -> list[PiiEntity]:
                return []

        plugin = _BuiltinPlugin()
        assert plugin.plugin_type == "builtin"


# ===========================================================================
# Example plugin: ProjectCodenameDetector
# ===========================================================================


class TestProjectCodenameDetector:
    """Tests for the project_codename_detector example plugin."""

    def _make_plugin(self, config: dict | None = None):
        from example_plugins.project_codename_detector import (
            ProjectCodenameDetector,
        )

        plugin = ProjectCodenameDetector()
        plugin.setup(config or {})
        return plugin

    def test_detects_codenames(self):
        plugin = self._make_plugin()
        text = "We are working on Project Phoenix and Project Titan."
        entities = plugin.detect(text, "en")
        assert len(entities) == 2
        names = {text[e.start : e.end] for e in entities}
        assert names == {"Project Phoenix", "Project Titan"}

    def test_detects_all_three_defaults(self):
        plugin = self._make_plugin()
        text = "Project Phoenix, Project Titan, and Project Mercury are active."
        entities = plugin.detect(text, "en")
        assert len(entities) == 3

    def test_entity_attributes(self):
        plugin = self._make_plugin()
        text = "Project Phoenix is live."
        entities = plugin.detect(text, "en")
        assert len(entities) == 1
        e = entities[0]
        assert e.entity_type == "PROJECT_CODENAME"
        assert e.score == 0.95
        assert e.source == "project_codename_detector"
        assert text[e.start : e.end] == "Project Phoenix"

    def test_multiple_occurrences(self):
        plugin = self._make_plugin()
        text = "Project Phoenix then Project Phoenix again"
        entities = plugin.detect(text, "en")
        assert len(entities) == 2

    def test_no_match(self):
        plugin = self._make_plugin()
        text = "This text has no project codenames."
        entities = plugin.detect(text, "en")
        assert entities == []

    def test_custom_codenames_from_config(self):
        plugin = self._make_plugin(
            {"codenames": ["Project Apollo", "Project Artemis"]}
        )
        text = "Project Apollo and Project Phoenix"
        entities = plugin.detect(text, "en")
        # Only "Project Apollo" should match; Phoenix is NOT in custom list.
        assert len(entities) == 1
        assert text[entities[0].start : entities[0].end] == "Project Apollo"

    def test_name_and_version(self):
        from example_plugins.project_codename_detector import (
            ProjectCodenameDetector,
        )

        plugin = ProjectCodenameDetector()
        assert plugin.name == "project_codename_detector"
        assert plugin.version == "1.1"

    def test_is_detector_plugin_subclass(self):
        from example_plugins.project_codename_detector import (
            ProjectCodenameDetector,
        )

        assert issubclass(ProjectCodenameDetector, DetectorPlugin)

    def test_teardown_is_noop(self):
        plugin = self._make_plugin()
        # Should not raise
        plugin.teardown()

    def test_config_schema_declared(self):
        from example_plugins.project_codename_detector import (
            ProjectCodenameDetector,
        )

        plugin = ProjectCodenameDetector()
        assert len(plugin.config_schema) == 3
        field_names = [f.name for f in plugin.config_schema]
        assert "codenames" in field_names
        assert "case_sensitive" in field_names
        assert "score" in field_names

    def test_config_schema_has_label_and_details(self):
        from example_plugins.project_codename_detector import (
            ProjectCodenameDetector,
        )

        plugin = ProjectCodenameDetector()
        for field in plugin.config_schema:
            assert field.label != "", f"Field {field.name} missing label"
            assert field.details != "", f"Field {field.name} missing details"

    def test_case_insensitive_by_default(self):
        plugin = self._make_plugin()
        text = "project phoenix is active"
        entities = plugin.detect(text, "en")
        assert len(entities) == 1

    def test_case_sensitive_mode(self):
        plugin = self._make_plugin({"case_sensitive": True})
        text = "project phoenix is active"
        entities = plugin.detect(text, "en")
        assert len(entities) == 0  # lowercase doesn't match

    def test_case_sensitive_exact_match(self):
        plugin = self._make_plugin({"case_sensitive": True})
        text = "Project Phoenix is active"
        entities = plugin.detect(text, "en")
        assert len(entities) == 1

    def test_custom_score(self):
        plugin = self._make_plugin({"score": 0.8})
        text = "Project Phoenix is live."
        entities = plugin.detect(text, "en")
        assert len(entities) == 1
        assert entities[0].score == 0.8


# ===========================================================================
# Example plugin: BadgeNumberDetector
# ===========================================================================


class TestBadgeNumberDetector:
    """Tests for the badge_number_detector example plugin."""

    def _make_plugin(self, config: dict | None = None):
        from example_plugins.badge_number_detector import BadgeNumberDetector

        plugin = BadgeNumberDetector()
        plugin.setup(config or {})
        return plugin

    def test_detects_badge_number(self):
        plugin = self._make_plugin()
        text = "Employee BADGE-1234 reported the issue."
        entities = plugin.detect(text, "en")
        assert len(entities) == 1
        e = entities[0]
        assert e.entity_type == "BADGE_NUMBER"
        assert text[e.start : e.end] == "BADGE-1234"

    def test_multiple_badges(self):
        plugin = self._make_plugin()
        text = "BADGE-0001 and BADGE-9999 were present."
        entities = plugin.detect(text, "en")
        assert len(entities) == 2

    def test_no_match_wrong_format(self):
        plugin = self._make_plugin()
        text = "BADGE-12 is too short. BADGE-12345 is too long."
        entities = plugin.detect(text, "en")
        # "BADGE-12345" should partially match "BADGE-1234" within it
        # because the regex matches "BADGE-" + 4 digits, and "BADGE-12345"
        # contains "BADGE-1234" as a substring.
        assert len(entities) == 1
        assert text[entities[0].start : entities[0].end] == "BADGE-1234"

    def test_no_match_at_all(self):
        plugin = self._make_plugin()
        text = "No badge numbers here."
        entities = plugin.detect(text, "en")
        assert entities == []

    def test_entity_attributes(self):
        plugin = self._make_plugin()
        text = "BADGE-5678"
        entities = plugin.detect(text, "en")
        assert len(entities) == 1
        e = entities[0]
        assert e.entity_type == "BADGE_NUMBER"
        assert e.score == 1.0
        assert e.source == "badge_number_detector"
        assert e.start == 0
        assert e.end == 10

    def test_custom_pattern(self):
        plugin = self._make_plugin({"pattern": r"EMP-\d{6}"})
        text = "EMP-123456 is a valid badge, BADGE-1234 is not."
        entities = plugin.detect(text, "en")
        assert len(entities) == 1
        assert text[entities[0].start : entities[0].end] == "EMP-123456"

    def test_name_and_version(self):
        from example_plugins.badge_number_detector import BadgeNumberDetector

        plugin = BadgeNumberDetector()
        assert plugin.name == "badge_number_detector"
        assert plugin.version == "1.1"

    def test_is_detector_plugin_subclass(self):
        from example_plugins.badge_number_detector import BadgeNumberDetector

        assert issubclass(BadgeNumberDetector, DetectorPlugin)

    def test_teardown_is_noop(self):
        plugin = self._make_plugin()
        plugin.teardown()

    def test_config_schema_declared(self):
        from example_plugins.badge_number_detector import BadgeNumberDetector

        plugin = BadgeNumberDetector()
        assert len(plugin.config_schema) == 3
        field_names = [f.name for f in plugin.config_schema]
        assert "pattern" in field_names
        assert "score" in field_names
        assert "context_words" in field_names

    def test_config_schema_has_label_and_details(self):
        from example_plugins.badge_number_detector import BadgeNumberDetector

        plugin = BadgeNumberDetector()
        for field in plugin.config_schema:
            assert field.label != "", f"Field {field.name} missing label"
            assert field.details != "", f"Field {field.name} missing details"

    def test_custom_score(self):
        plugin = self._make_plugin({"score": 0.7, "context_words": []})
        text = "BADGE-1234"
        entities = plugin.detect(text, "en")
        assert len(entities) == 1
        assert entities[0].score == 0.7

    def test_context_word_boosts_score(self):
        plugin = self._make_plugin({"score": 0.7, "context_words": ["employee"]})
        text = "employee BADGE-1234 reported"
        entities = plugin.detect(text, "en")
        assert len(entities) == 1
        assert entities[0].score > 0.7

    def test_no_context_boost_without_context_words(self):
        plugin = self._make_plugin({"score": 0.8, "context_words": []})
        text = "employee BADGE-1234"
        entities = plugin.detect(text, "en")
        assert len(entities) == 1
        assert entities[0].score == 0.8


# ===========================================================================
# PipelineContext tests
# ===========================================================================


class TestPipelineContext:
    """Tests for the PipelineContext dataclass."""

    def test_basic_creation(self):
        ctx = PipelineContext(
            session_id="sess-001",
            provider_name="anthropic",
            language="en",
        )
        assert ctx.session_id == "sess-001"
        assert ctx.provider_name == "anthropic"
        assert ctx.language == "en"

    def test_default_language(self):
        ctx = PipelineContext(session_id="s1", provider_name="openai")
        assert ctx.language == "en"

    def test_custom_language(self):
        ctx = PipelineContext(
            session_id="s1", provider_name="openai", language="de"
        )
        assert ctx.language == "de"

    def test_empty_session_id_raises(self):
        with pytest.raises(ValueError, match="session_id must be a non-empty"):
            PipelineContext(session_id="", provider_name="openai")

    def test_empty_provider_name_raises(self):
        with pytest.raises(ValueError, match="provider_name must be a non-empty"):
            PipelineContext(session_id="s1", provider_name="")

    def test_empty_language_raises(self):
        with pytest.raises(ValueError, match="language must be a non-empty"):
            PipelineContext(session_id="s1", provider_name="p", language="")

    def test_equality(self):
        c1 = PipelineContext(session_id="s", provider_name="p", language="en")
        c2 = PipelineContext(session_id="s", provider_name="p", language="en")
        assert c1 == c2


# ===========================================================================
# PipelineResult tests
# ===========================================================================


class TestPipelineResult:
    """Tests for the PipelineResult dataclass."""

    def test_empty_result(self):
        result = PipelineResult()
        assert result.entities == []
        assert result.scrubbed_text == ""
        assert result.latency_ms == 0.0
        assert result.entity_count == 0
        assert result.has_entities is False
        assert result.entity_types() == set()

    def test_result_with_entities(self):
        entities = [
            PiiEntity(entity_type="EMAIL", start=0, end=15, score=0.99, source="p"),
            PiiEntity(entity_type="PERSON", start=20, end=30, score=0.85, source="p"),
        ]
        result = PipelineResult(
            entities=entities,
            scrubbed_text="REDACTED_EMAIL_1 sent by REDACTED_PERSON_1",
            latency_ms=12.5,
        )
        assert result.entity_count == 2
        assert result.has_entities is True
        assert result.entity_types() == {"EMAIL", "PERSON"}
        assert result.latency_ms == 12.5

    def test_entities_by_type(self):
        entities = [
            PiiEntity(entity_type="EMAIL", start=0, end=10, score=0.9, source="s"),
            PiiEntity(entity_type="PERSON", start=15, end=25, score=0.8, source="s"),
            PiiEntity(entity_type="EMAIL", start=30, end=40, score=0.95, source="s"),
        ]
        result = PipelineResult(entities=entities, scrubbed_text="...", latency_ms=1.0)
        emails = result.entities_by_type("EMAIL")
        assert len(emails) == 2
        assert all(e.entity_type == "EMAIL" for e in emails)
        persons = result.entities_by_type("PERSON")
        assert len(persons) == 1

    def test_entities_by_type_empty(self):
        result = PipelineResult()
        assert result.entities_by_type("EMAIL") == []

    def test_negative_latency_raises(self):
        with pytest.raises(ValueError, match="latency_ms must be >= 0.0"):
            PipelineResult(latency_ms=-1.0)

    def test_default_entities_are_independent(self):
        """Ensure default entity lists are not shared between instances."""
        r1 = PipelineResult()
        r2 = PipelineResult()
        r1.entities.append(
            PiiEntity(entity_type="X", start=0, end=1, score=0.5, source="s")
        )
        assert r2.entities == []


# ===========================================================================
# Integration-style: plugin -> PipelineResult
# ===========================================================================


class TestPluginIntegration:
    """End-to-end tests combining plugins with pipeline models."""

    def test_plugin_entities_fit_in_pipeline_result(self):
        """Entities from a plugin can be placed in a PipelineResult."""
        plugin = _KeywordDetector()
        plugin.setup({"keywords": ["John Doe"]})
        text = "Hello John Doe, welcome."
        entities = plugin.detect(text, "en")
        result = PipelineResult(
            entities=entities,
            scrubbed_text="Hello REDACTED_KEYWORD_1, welcome.",
            latency_ms=0.5,
        )
        assert result.entity_count == 1
        assert result.entities[0].entity_type == "KEYWORD"
        assert text[result.entities[0].start : result.entities[0].end] == "John Doe"

    def test_pipeline_context_and_result_together(self):
        """PipelineContext and PipelineResult can coexist as expected."""
        ctx = PipelineContext(
            session_id="sess-42", provider_name="anthropic", language="en"
        )
        result = PipelineResult(
            entities=[
                PiiEntity(
                    entity_type="EMAIL",
                    start=0,
                    end=16,
                    score=0.99,
                    source="presidio",
                )
            ],
            scrubbed_text="REDACTED_EMAIL_1",
            latency_ms=8.3,
        )
        # Just verifying the types work together without issues
        assert ctx.session_id == "sess-42"
        assert result.has_entities is True

    def test_multiple_plugins_contribute_entities(self):
        """Entities from multiple plugins can be aggregated."""
        from example_plugins.badge_number_detector import BadgeNumberDetector
        from example_plugins.project_codename_detector import (
            ProjectCodenameDetector,
        )

        codename_plugin = ProjectCodenameDetector()
        codename_plugin.setup({})
        badge_plugin = BadgeNumberDetector()
        badge_plugin.setup({})

        text = "Project Phoenix engineer BADGE-4321 filed a report."
        all_entities: list[PiiEntity] = []
        all_entities.extend(codename_plugin.detect(text, "en"))
        all_entities.extend(badge_plugin.detect(text, "en"))

        result = PipelineResult(
            entities=all_entities,
            scrubbed_text="REDACTED_PROJECT_CODENAME_1 engineer REDACTED_BADGE_NUMBER_1 filed a report.",
            latency_ms=2.1,
        )
        assert result.entity_count == 2
        assert result.entity_types() == {"PROJECT_CODENAME", "BADGE_NUMBER"}
