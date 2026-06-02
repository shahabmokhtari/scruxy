"""Tests for the OpenAI Privacy Filter (OPF) detector plugin.

The underlying ``opf`` package is a heavy ML dependency (1.5B params)
that we do NOT install in CI.  These tests therefore focus on:

1. The plugin self-disables cleanly when ``opf`` is not importable.
2. When mocked, ``detect`` correctly converts ``DetectedSpan`` objects
   into Scruxy ``PiiEntity`` objects (label mapping, span bounds, score).
3. Config-field validation (max_text_length cap, enabled_labels filter).
4. Config schema is well-formed (UI consumes ``config_schema``).
"""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest


def test_plugin_self_disables_when_opf_not_installed(monkeypatch, caplog) -> None:
    """If ``find_spec('opf')`` returns None, the plugin must log a
    WARNING and set ``_import_failed = True``; ``detect`` returns
    ``[]`` instead of crashing."""
    import importlib.util as _util
    import logging

    real_find = _util.find_spec
    monkeypatch.setattr(
        _util, "find_spec",
        lambda name: None if name == "opf" else real_find(name),
    )

    from scruxy.plugin.openai_privacy_filter import OpenAIPrivacyFilterPlugin

    p = OpenAIPrivacyFilterPlugin()
    with caplog.at_level(logging.WARNING, logger="scruxy.plugin.openai_privacy_filter"):
        p.setup({})

    assert p._import_failed is True
    assert p._opf is None
    assert any(
        "'opf' package not installed" in r.message for r in caplog.records
    )

    # detect() must not crash even with import failed.
    assert p.detect("alice@example.com is here", "en") == []


def test_plugin_label_mapping_and_span_conversion(monkeypatch) -> None:
    """When the OPF runtime is mocked, ``detect`` must:
    - filter spans whose label is not in ``enabled_labels``,
    - map remaining labels to the canonical Scruxy entity types,
    - preserve ``start``/``end`` exactly,
    - apply the configured ``min_score`` as the entity score.

    Lazy-init: the runtime is constructed on the first ``detect``
    call, not in ``setup``.
    """
    from scruxy.plugin.openai_privacy_filter import (
        OpenAIPrivacyFilterPlugin,
        _OPF_LABEL_TO_ENTITY,
    )

    # Build a fake ``opf._api`` module exposing a stub ``OPF`` class.
    fake_module = types.ModuleType("opf._api")

    class _FakeSpan:
        def __init__(self, label, start, end, text):
            self.label = label
            self.start = start
            self.end = end
            self.text = text
            self.placeholder = f"[{label}]"

    class _FakeResult:
        def __init__(self, spans):
            self.detected_spans = spans

    class _FakeOPF:
        def __init__(self, **kwargs):
            self._kwargs = kwargs

        def redact(self, text):
            return _FakeResult(
                spans=[
                    _FakeSpan("private_email", 0, 17, "alice@example.com"),
                    _FakeSpan("private_person", 25, 30, "Alice"),
                    # Should be filtered out via enabled_labels.
                    _FakeSpan("private_url", 32, 40, "evil.com"),
                ]
            )

    fake_module.OPF = _FakeOPF
    fake_parent = types.ModuleType("opf")
    fake_parent._api = fake_module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "opf", fake_parent)
    monkeypatch.setitem(sys.modules, "opf._api", fake_module)
    # Lazy-init now uses ``importlib.util.find_spec("opf")``; make it
    # return a non-None spec so the importability probe in setup()
    # passes.
    import importlib.util as _util
    real_find = _util.find_spec
    monkeypatch.setattr(
        _util, "find_spec",
        lambda name: MagicMock() if name == "opf" else real_find(name),
    )

    p = OpenAIPrivacyFilterPlugin()
    p.setup(
        {
            "device": "cpu",
            "decode_mode": "viterbi",
            "min_score": 0.85,
            # Only emit email + person.
            "enabled_labels": ["private_email", "private_person"],
            "max_text_length": 0,
        }
    )

    # Lazy-init: setup must NOT have constructed the runtime yet.
    assert p._import_failed is False
    assert p._opf is None, (
        "Lazy-init: OPF runtime must NOT be constructed in setup()"
    )

    text = "alice@example.com sent Alice an evil.com link"
    entities = p.detect(text, "en")

    # Now the runtime IS constructed.
    assert isinstance(p._opf, _FakeOPF)

    # Two entities (URL filtered out by enabled_labels).
    assert len(entities) == 2
    types_seen = {e.entity_type for e in entities}
    assert types_seen == {
        _OPF_LABEL_TO_ENTITY["private_email"],
        _OPF_LABEL_TO_ENTITY["private_person"],
    }
    # Spans preserved exactly.
    email = next(e for e in entities if e.entity_type == "EMAIL_ADDRESS")
    assert email.start == 0 and email.end == 17
    # Score applied uniformly from min_score config.
    for e in entities:
        assert e.score == pytest.approx(0.85)
        assert e.source == "openai_privacy_filter"


def test_plugin_max_text_length_cap(monkeypatch) -> None:
    """Texts above the configured ``max_text_length`` must skip the
    model invocation entirely so a single oversized request can't
    dominate the latency budget."""
    from scruxy.plugin.openai_privacy_filter import OpenAIPrivacyFilterPlugin

    fake_module = types.ModuleType("opf._api")
    fake_opf_instance = MagicMock()
    fake_opf_instance.redact.return_value = MagicMock(detected_spans=())
    fake_module.OPF = MagicMock(return_value=fake_opf_instance)
    fake_parent = types.ModuleType("opf")
    fake_parent._api = fake_module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "opf", fake_parent)
    monkeypatch.setitem(sys.modules, "opf._api", fake_module)
    # Lazy-init's importability probe must see opf as installed.
    import importlib.util as _util
    real_find = _util.find_spec
    monkeypatch.setattr(
        _util, "find_spec",
        lambda name: MagicMock() if name == "opf" else real_find(name),
    )

    p = OpenAIPrivacyFilterPlugin()
    p.setup({"max_text_length": 100})

    short = "a" * 50
    long = "a" * 200

    # Short text invokes the model (and triggers lazy init on first call).
    p.detect(short, "en")
    fake_opf_instance.redact.assert_called_once()

    # Long text skips the model.
    fake_opf_instance.reset_mock()
    p.detect(long, "en")
    fake_opf_instance.redact.assert_not_called()


def test_plugin_config_schema_is_well_formed() -> None:
    """The UI reads ``config_schema`` to render forms; sanity-check
    that every field has a name + field_type + sensible default."""
    from scruxy.plugin.openai_privacy_filter import OpenAIPrivacyFilterPlugin

    schema = OpenAIPrivacyFilterPlugin.config_schema
    assert schema, "plugin must declare a config schema for the UI"
    names = {f.name for f in schema}
    # Document the operator-controllable surface explicitly.
    expected = {
        "device", "checkpoint_path", "decode_mode", "min_score",
        "enabled_labels", "max_text_length",
    }
    assert expected.issubset(names), f"missing schema fields: {expected - names}"
    for f in schema:
        assert f.name and f.field_type
