"""Tests for the Presidio-based PII detection plugin."""
from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest


@dataclass
class _FakeRecognizerResult:
    """Mimics presidio_analyzer.RecognizerResult for testing."""

    entity_type: str
    start: int
    end: int
    score: float


class TestPresidioPluginSetup:
    """Test PresidioPlugin setup and configuration via setup(config)."""

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    def test_default_setup(self, mock_engine_cls: MagicMock, mock_provider_cls: MagicMock):
        """PresidioPlugin.setup() with empty config uses defaults."""
        from scruxy.plugin.presidio import PresidioPlugin

        mock_provider = MagicMock()
        mock_provider_cls.return_value = mock_provider

        plugin = PresidioPlugin()
        plugin.setup({})

        mock_provider_cls.assert_called_once()
        nlp_cfg = mock_provider_cls.call_args[1]["nlp_configuration"]
        assert nlp_cfg["nlp_engine_name"] == "spacy"
        assert nlp_cfg["models"] == [{"lang_code": "en", "model_name": "en_core_web_lg"}]
        assert "labels_to_ignore" in nlp_cfg.get("ner_model_configuration", {})
        mock_engine_cls.assert_called_once_with(
            nlp_engine=mock_provider.create_engine(),
            supported_languages=["en"],
        )
        assert plugin._language == "en"
        assert plugin._score_threshold == 0.7
        assert plugin._entities is None

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    def test_custom_setup(self, mock_engine_cls: MagicMock, mock_provider_cls: MagicMock):
        """PresidioPlugin.setup() accepts custom config values."""
        from scruxy.plugin.presidio import PresidioPlugin

        plugin = PresidioPlugin()
        plugin.setup({
            "spacy_model": "en_core_web_sm",
            "language": "de",
            "score_threshold": 0.8,
            "entities": ["PERSON", "EMAIL_ADDRESS"],
        })

        mock_provider_cls.assert_called_once()
        nlp_cfg = mock_provider_cls.call_args[1]["nlp_configuration"]
        assert nlp_cfg["models"] == [{"lang_code": "de", "model_name": "en_core_web_sm"}]
        assert plugin._language == "de"
        assert plugin._score_threshold == 0.8
        assert plugin._entities == ["PERSON", "EMAIL_ADDRESS"]


class TestPresidioPluginDetect:
    """Test PresidioPlugin.detect() method."""

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    def test_detect_returns_pii_entities(
        self, mock_engine_cls: MagicMock, mock_provider_cls: MagicMock
    ):
        """detect() converts RecognizerResult to PiiEntity with source='presidio'."""
        from scruxy.plugin.presidio import PiiEntity, PresidioPlugin

        mock_analyzer = MagicMock()
        mock_engine_cls.return_value = mock_analyzer
        mock_analyzer.analyze.return_value = [
            _FakeRecognizerResult(entity_type="PERSON", start=0, end=8, score=0.85),
            _FakeRecognizerResult(entity_type="EMAIL_ADDRESS", start=20, end=40, score=0.95),
        ]

        plugin = PresidioPlugin()
        plugin.setup({})
        results = plugin.detect("John Doe sent mail to john.doe@example.com", "en")

        assert len(results) == 2

        assert results[0] == PiiEntity(
            entity_type="PERSON", start=0, end=8, score=0.85, source="presidio"
        )
        assert results[1] == PiiEntity(
            entity_type="EMAIL_ADDRESS", start=20, end=40, score=0.95, source="presidio"
        )

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    def test_detect_empty_text(self, mock_engine_cls: MagicMock, mock_provider_cls: MagicMock):
        """detect() returns empty list for empty text without calling analyzer."""
        from scruxy.plugin.presidio import PresidioPlugin

        mock_analyzer = MagicMock()
        mock_engine_cls.return_value = mock_analyzer

        plugin = PresidioPlugin()
        plugin.setup({})
        mock_analyzer.analyze.reset_mock()  # clear warmup call
        results = plugin.detect("", "en")

        assert results == []
        mock_analyzer.analyze.assert_not_called()

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    def test_detect_no_pii_found(self, mock_engine_cls: MagicMock, mock_provider_cls: MagicMock):
        """detect() returns empty list when no PII is found."""
        from scruxy.plugin.presidio import PresidioPlugin

        mock_analyzer = MagicMock()
        mock_engine_cls.return_value = mock_analyzer
        mock_analyzer.analyze.return_value = []

        plugin = PresidioPlugin()
        plugin.setup({})
        results = plugin.detect("No personal information here.", "en")

        assert results == []

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    def test_detect_passes_score_threshold(
        self, mock_engine_cls: MagicMock, mock_provider_cls: MagicMock
    ):
        """detect() passes score_threshold to analyzer.analyze()."""
        from scruxy.plugin.presidio import PresidioPlugin

        mock_analyzer = MagicMock()
        mock_engine_cls.return_value = mock_analyzer
        mock_analyzer.analyze.return_value = []

        plugin = PresidioPlugin()
        plugin.setup({"score_threshold": 0.7})
        plugin.detect("test text", "en")

        call_kwargs = mock_analyzer.analyze.call_args[1]
        assert call_kwargs["score_threshold"] == 0.7

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    def test_detect_passes_entities_filter(
        self, mock_engine_cls: MagicMock, mock_provider_cls: MagicMock
    ):
        """detect() passes entities filter when specified."""
        from scruxy.plugin.presidio import PresidioPlugin

        mock_analyzer = MagicMock()
        mock_engine_cls.return_value = mock_analyzer
        mock_analyzer.analyze.return_value = []

        plugin = PresidioPlugin()
        plugin.setup({"entities": ["PERSON", "PHONE_NUMBER"]})
        plugin.detect("test text", "en")

        call_kwargs = mock_analyzer.analyze.call_args[1]
        assert call_kwargs["entities"] == ["PERSON", "PHONE_NUMBER"]

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    def test_detect_no_entities_filter_when_none(
        self, mock_engine_cls: MagicMock, mock_provider_cls: MagicMock
    ):
        """detect() does not pass entities kwarg when entities is None."""
        from scruxy.plugin.presidio import PresidioPlugin

        mock_analyzer = MagicMock()
        mock_engine_cls.return_value = mock_analyzer
        mock_analyzer.analyze.return_value = []

        plugin = PresidioPlugin()
        plugin.setup({"entities": None})
        plugin.detect("test text", "en")

        call_kwargs = mock_analyzer.analyze.call_args[1]
        assert "entities" not in call_kwargs

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    def test_detect_uses_language_param(
        self, mock_engine_cls: MagicMock, mock_provider_cls: MagicMock
    ):
        """detect() uses the language parameter passed to the method."""
        from scruxy.plugin.presidio import PresidioPlugin

        mock_analyzer = MagicMock()
        mock_engine_cls.return_value = mock_analyzer
        mock_analyzer.analyze.return_value = []

        plugin = PresidioPlugin()
        plugin.setup({"language": "en"})
        plugin.detect("test text", "de")

        call_kwargs = mock_analyzer.analyze.call_args[1]
        assert call_kwargs["language"] == "de"

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    def test_detect_falls_back_to_configured_language(
        self, mock_engine_cls: MagicMock, mock_provider_cls: MagicMock
    ):
        """detect() falls back to configured language when language param is empty."""
        from scruxy.plugin.presidio import PresidioPlugin

        mock_analyzer = MagicMock()
        mock_engine_cls.return_value = mock_analyzer
        mock_analyzer.analyze.return_value = []

        plugin = PresidioPlugin()
        plugin.setup({"language": "de"})
        plugin.detect("test text", "")

        call_kwargs = mock_analyzer.analyze.call_args[1]
        assert call_kwargs["language"] == "de"


class TestPresidioPluginAttributes:
    """Test PresidioPlugin class attributes and DetectorPlugin compliance."""

    def test_class_attributes(self):
        """PresidioPlugin has correct class attributes."""
        from scruxy.plugin.presidio import PresidioPlugin

        assert PresidioPlugin.name == "presidio"
        assert PresidioPlugin.plugin_type == "builtin"
        assert PresidioPlugin.enabled is True
        assert isinstance(PresidioPlugin.version, str)

    def test_config_schema_fields(self):
        """PresidioPlugin.config_schema declares expected fields."""
        from scruxy.plugin.presidio import PresidioPlugin

        schema = PresidioPlugin.config_schema
        field_names = [f.name for f in schema]
        assert "spacy_model" in field_names
        assert "language" in field_names
        assert "score_threshold" in field_names
        assert "entities" in field_names

        # Check score_threshold field details
        threshold_field = next(f for f in schema if f.name == "score_threshold")
        assert threshold_field.field_type == "number"
        assert threshold_field.min_value == 0.0
        assert threshold_field.max_value == 1.0

    def test_inherits_detector_plugin(self):
        """PresidioPlugin is a subclass of DetectorPlugin."""
        from scruxy.plugin.presidio import PresidioPlugin
        from scruxy.plugin.base import DetectorPlugin

        assert issubclass(PresidioPlugin, DetectorPlugin)


class TestPresidioPluginEnhancedSchema:
    """Test the enhanced config_schema with labels, details, and select types."""

    def test_language_is_select_type(self):
        from scruxy.plugin.presidio import PresidioPlugin

        schema = PresidioPlugin.config_schema
        lang_field = next(f for f in schema if f.name == "language")
        assert lang_field.field_type == "select"
        assert "en" in lang_field.choices
        assert "es" in lang_field.choices
        assert "de" in lang_field.choices
        assert lang_field.label == "Language"

    def test_entities_has_sensible_defaults(self):
        from scruxy.plugin.presidio import PresidioPlugin

        schema = PresidioPlugin.config_schema
        entities_field = next(f for f in schema if f.name == "entities")
        assert isinstance(entities_field.default, list)
        assert "PERSON" in entities_field.default
        assert "EMAIL_ADDRESS" in entities_field.default
        assert "PHONE_NUMBER" in entities_field.default
        assert entities_field.label == "Entity Types"
        assert entities_field.details != ""

    def test_spacy_model_has_label_and_details(self):
        from scruxy.plugin.presidio import PresidioPlugin

        schema = PresidioPlugin.config_schema
        model_field = next(f for f in schema if f.name == "spacy_model")
        assert model_field.label == "spaCy Model"
        assert model_field.details != ""

    def test_score_threshold_has_label_and_details(self):
        from scruxy.plugin.presidio import PresidioPlugin

        schema = PresidioPlugin.config_schema
        threshold_field = next(f for f in schema if f.name == "score_threshold")
        assert threshold_field.label == "Confidence Threshold"
        assert threshold_field.details != ""


class TestBackwardCompatAlias:
    """Test that the PresidioStage backward-compatibility alias works."""

    def test_presidio_stage_alias(self):
        """PresidioStage is an alias for PresidioPlugin."""
        from scruxy.plugin.presidio import PresidioPlugin, PresidioStage

        assert PresidioStage is PresidioPlugin


class TestWindowsPlatformHandling:
    """Test Windows-specific spaCy configuration."""

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    @patch("scruxy.plugin.presidio.sys")
    def test_windows_platform_detected(
        self,
        mock_sys: MagicMock,
        mock_engine_cls: MagicMock,
        mock_provider_cls: MagicMock,
    ):
        """On Windows, _configure_spacy_for_platform is called during setup."""
        mock_sys.platform = "win32"

        from scruxy.plugin.presidio import _configure_spacy_for_platform

        # Verify it does not raise on Windows
        with patch("scruxy.plugin.presidio.sys", mock_sys):
            _configure_spacy_for_platform()

    @patch("scruxy.plugin.presidio.NlpEngineProvider")
    @patch("scruxy.plugin.presidio.AnalyzerEngine")
    @patch("scruxy.plugin.presidio.sys")
    def test_non_windows_platform_skips(
        self,
        mock_sys: MagicMock,
        mock_engine_cls: MagicMock,
        mock_provider_cls: MagicMock,
    ):
        """On non-Windows, _configure_spacy_for_platform does minimal work."""
        mock_sys.platform = "linux"

        from scruxy.plugin.presidio import _configure_spacy_for_platform

        with patch("scruxy.plugin.presidio.sys", mock_sys):
            _configure_spacy_for_platform()  # should not raise


class TestPiiEntityDataclass:
    """Test PiiEntity dataclass behavior."""

    def test_pii_entity_equality(self):
        """Two PiiEntity instances with same values are equal."""
        from scruxy.plugin.presidio import PiiEntity

        a = PiiEntity(entity_type="PERSON", start=0, end=5, score=0.9, source="presidio")
        b = PiiEntity(entity_type="PERSON", start=0, end=5, score=0.9, source="presidio")
        assert a == b

    def test_pii_entity_inequality(self):
        """Two PiiEntity instances with different values are not equal."""
        from scruxy.plugin.presidio import PiiEntity

        a = PiiEntity(entity_type="PERSON", start=0, end=5, score=0.9, source="presidio")
        b = PiiEntity(entity_type="EMAIL_ADDRESS", start=0, end=5, score=0.9, source="presidio")
        assert a != b


# ======================================================================
# Post-filter tests
# ======================================================================


class TestPostFilterRules:
    """Test the code-aware post-filter that rejects false positives."""

    def _make_entity(self, text: str, entity_type: str = "PERSON", score: float = 0.8) -> PiiEntity:
        from scruxy.plugin.base import PiiEntity
        return PiiEntity(entity_type=entity_type, start=0, end=len(text), score=score, source="presidio")

    def test_rejects_camelcase_person(self):
        """camelCase identifiers like 'sessionID' should be rejected as PERSON."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "sessionID"
        entities = [self._make_entity(text, "PERSON")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 0

    def test_rejects_function_call_person(self):
        """Function call like 'ToList(' should be rejected as PERSON."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "ToList("
        entities = [self._make_entity(text, "PERSON")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 0

    def test_rejects_html_fragment_person(self):
        """HTML fragments like 'Logs</a></li' should be rejected as PERSON."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "Logs</a></li"
        entities = [self._make_entity(text, "PERSON")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 0

    def test_rejects_dotted_identifier_person(self):
        """Dotted identifiers like 't.id' should be rejected as PERSON."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "t.id"
        entities = [self._make_entity(text, "PERSON")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 0

    def test_rejects_css_value_person(self):
        """CSS values like '768px' should be rejected as PERSON."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "768px"
        entities = [self._make_entity(text, "PERSON")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 0

    def test_rejects_scope_operator_location(self):
        """'::' should be rejected as LOCATION."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "::"
        entities = [self._make_entity(text, "LOCATION")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 0

    def test_rejects_colon_asterisk_location(self):
        """':**' should be rejected as LOCATION."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = ":**"
        entities = [self._make_entity(text, "LOCATION")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 0

    def test_rejects_snake_case_location(self):
        """snake_case identifiers like 'session_id' should be rejected as LOCATION."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "session_id"
        entities = [self._make_entity(text, "LOCATION")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 0

    def test_rejects_bare_scope_operator_ip(self):
        """'::' should be rejected as IP_ADDRESS."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "::"
        entities = [self._make_entity(text, "IP_ADDRESS")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 0

    def test_accepts_real_person_name(self):
        """Real person names like 'John Smith' should pass the filter."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "John Smith"
        entities = [self._make_entity(text, "PERSON")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 1

    def test_accepts_real_location(self):
        """Real location names like 'France' should pass the filter."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "France"
        entities = [self._make_entity(text, "LOCATION")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 1

    def test_accepts_real_ip_address(self):
        """Real IPs like '192.168.1.1' should pass the filter."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "192.168.1.1"
        entities = [self._make_entity(text, "IP_ADDRESS")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 1

    def test_accepts_email_unfiltered(self):
        """EMAIL_ADDRESS has no post-filter rules — should always pass."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "john@example.com"
        entities = [self._make_entity(text, "EMAIL_ADDRESS")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 1

    def test_no_rules_passes_everything(self):
        """With empty rules, all entities pass."""
        from scruxy.plugin.presidio import _apply_post_filter

        text = "ToList("
        entities = [self._make_entity(text, "PERSON")]
        result = _apply_post_filter(text, entities, {}, text)
        assert len(result) == 1

    def test_rejects_code_operator_person(self):
        """Code method calls like 'OrderBy(v' should be rejected."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        for code_token in ["OrderBy(v", "Contains(prop", "Select(Escap", "JsonProperty(\"x"]:
            entities = [self._make_entity(code_token, "PERSON")]
            result = _apply_post_filter(code_token, entities, rules, code_token)
            assert len(result) == 0, f"Expected {code_token!r} to be rejected as PERSON"

    def test_rejects_git_flag_person(self):
        """CLI flags like '--git' should be rejected as PERSON."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules, _DEFAULT_POST_FILTER_RULES

        rules = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        text = "--git"
        entities = [self._make_entity(text, "PERSON")]
        result = _apply_post_filter(text, entities, rules, text)
        assert len(result) == 0

    def test_custom_yaml_rules(self):
        """Custom YAML-formatted rules are parsed and applied."""
        from scruxy.plugin.presidio import _apply_post_filter, _compile_post_filter_rules

        custom_rules = {
            "PERSON": {
                "min_length": 5,
                "must_contain_letter": True,
                "reject_patterns": [r"^test"],
            },
        }
        rules = _compile_post_filter_rules(custom_rules)
        # "AB" is too short
        entities = [self._make_entity("AB", "PERSON")]
        assert len(_apply_post_filter("AB", entities, rules, "AB")) == 0
        # "testUser" matches reject pattern
        entities = [self._make_entity("testUser", "PERSON")]
        assert len(_apply_post_filter("testUser", entities, rules, "testUser")) == 0
        # "Sarah Jones" passes
        entities = [self._make_entity("Sarah Jones", "PERSON")]
        assert len(_apply_post_filter("Sarah Jones", entities, rules, "Sarah Jones")) == 1

    def test_post_filter_enabled_in_setup(self):
        """setup() initializes post_filter_enabled and compiled rules."""
        from scruxy.plugin.presidio import PresidioPlugin

        with patch("scruxy.plugin.presidio.NlpEngineProvider"), \
             patch("scruxy.plugin.presidio.AnalyzerEngine"):
            plugin = PresidioPlugin()
            plugin.setup({"post_filter_enabled": True})
            assert plugin._post_filter_enabled is True
            assert isinstance(plugin._post_filter_compiled, dict)
            assert "PERSON" in plugin._post_filter_compiled

    def test_post_filter_disabled_in_setup(self):
        """setup() with post_filter_enabled=False disables filtering."""
        from scruxy.plugin.presidio import PresidioPlugin

        with patch("scruxy.plugin.presidio.NlpEngineProvider"), \
             patch("scruxy.plugin.presidio.AnalyzerEngine"):
            plugin = PresidioPlugin()
            plugin.setup({"post_filter_enabled": False})
            assert plugin._post_filter_enabled is False
