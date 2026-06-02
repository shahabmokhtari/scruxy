"""Pipeline data models: PipelineResult and PipelineContext."""
from __future__ import annotations

from dataclasses import dataclass, field

from scruxy.plugin.base import PiiEntity


@dataclass
class PipelineContext:
    """Immutable context passed through every pipeline invocation.

    Carries session-level metadata so pipeline stages can make
    context-aware decisions without accessing global state.

    Attributes:
        session_id: Unique identifier for the current proxy session.
        provider_name: Name of the matched LLM provider (e.g. ``"anthropic"``,
            ``"openai"``).
        language: ISO 639-1 language code for the text being processed
            (e.g. ``"en"``).  Forwarded to Presidio and plugins.
    """

    session_id: str
    provider_name: str
    language: str = "en"

    def __post_init__(self) -> None:
        """Validate required fields."""
        if not self.session_id:
            raise ValueError("session_id must be a non-empty string")
        if not self.provider_name:
            raise ValueError("provider_name must be a non-empty string")
        if not self.language:
            raise ValueError("language must be a non-empty string")


@dataclass
class PipelineResult:
    """The output of a full pipeline run on a single text fragment.

    Attributes:
        entities: All PII entities detected (after merge/deduplication).
        scrubbed_text: The text with all PII spans replaced by
            ``REDACTED_{TYPE}_{N}`` tokens.
        latency_ms: Wall-clock time (in milliseconds) the pipeline took
            to process this fragment.
    """

    entities: list[PiiEntity] = field(default_factory=list)
    scrubbed_text: str = ""
    latency_ms: float = 0.0

    def __post_init__(self) -> None:
        """Validate latency value."""
        if self.latency_ms < 0.0:
            raise ValueError(f"latency_ms must be >= 0.0, got {self.latency_ms}")

    @property
    def entity_count(self) -> int:
        """Return the number of detected entities."""
        return len(self.entities)

    @property
    def has_entities(self) -> bool:
        """Return True if any PII entities were detected."""
        return len(self.entities) > 0

    def entity_types(self) -> set[str]:
        """Return the unique set of entity types detected."""
        return {e.entity_type for e in self.entities}

    def entities_by_type(self, entity_type: str) -> list[PiiEntity]:
        """Return all entities matching the given type."""
        return [e for e in self.entities if e.entity_type == entity_type]
