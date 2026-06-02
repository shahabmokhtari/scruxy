"""Backward-compatibility shim — real implementation moved to scruxy.plugin.presidio."""
from scruxy.plugin.presidio import (  # noqa: F401
    AnalyzerEngine,
    ConfigField,
    DetectorPlugin,
    NlpEngineProvider,
    PiiEntity,
    PresidioPlugin,
    PresidioStage,
    _configure_spacy_for_platform,
    _ensure_spacy_model,
    _get_presidio_version,
    logger,
    sys,
)

__all__ = [
    "PresidioPlugin",
    "PresidioStage",
    "PiiEntity",
    "ConfigField",
    "DetectorPlugin",
    "_configure_spacy_for_platform",
    "_ensure_spacy_model",
    "_get_presidio_version",
]
