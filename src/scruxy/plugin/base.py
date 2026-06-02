"""DetectorPlugin ABC and PiiEntity model for custom PII detection plugins."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PiiEntity:
    """A detected PII entity with its location, type, confidence, and source.

    Attributes:
        entity_type: The category of PII detected (e.g. "PERSON", "EMAIL",
            "PROJECT_CODENAME").  Used as the ``{category}`` segment in the
            ``REDACTED_{category}_{n}`` token format.
        start: Start character offset (inclusive) within the source text.
        end: End character offset (exclusive) within the source text.
        score: Confidence score in the range ``[0.0, 1.0]``.  Used during
            merge/deduplication to resolve overlapping spans.
        source: Identifier of the detector that produced this entity (e.g.
            ``"presidio"``, ``"regex"``, or a plugin name).
        use_word_boundary: When ``True``, the pre-filter uses ``\\b`` word
            boundaries when matching this entity's text in later requests.
            Prevents substring matches (e.g. "repo" inside "repositories").
        case_sensitive: When ``False``, the pre-filter uses case-insensitive
            matching for this entity's text.
    """

    entity_type: str
    start: int
    end: int
    score: float
    source: str
    use_word_boundary: bool = False
    case_sensitive: bool = True

    def __post_init__(self) -> None:
        """Validate field values after initialisation."""
        if self.start < 0:
            raise ValueError(f"start must be >= 0, got {self.start}")
        if self.end <= self.start:
            raise ValueError(
                f"end ({self.end}) must be greater than start ({self.start})"
            )
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"score must be in [0.0, 1.0], got {self.score}")
        if not self.entity_type:
            raise ValueError("entity_type must be a non-empty string")
        if not self.source:
            raise ValueError("source must be a non-empty string")

    @property
    def span_length(self) -> int:
        """Return the character length of the detected span."""
        return self.end - self.start

    def overlaps(self, other: PiiEntity) -> bool:
        """Return True if this entity's span overlaps with *other*."""
        return self.start < other.end and other.start < self.end


@dataclass
class ConfigField:
    """Describes a single configurable field exposed by a detector plugin.

    Plugins declare a list of ``ConfigField`` instances on their class as
    ``config_schema``.  The UI reads this schema to dynamically render
    appropriate form controls.

    Attributes:
        name: The configuration key name (e.g. ``"pattern"``).
        field_type: One of ``"string"``, ``"number"``, ``"boolean"``,
            ``"select"``, ``"list"``, ``"text"`` (multiline textarea),
            or ``"file"`` (path input with "Edit File" button).
        default: The default value when the user has not set one.
        description: A human-readable description shown as a form label
            or tooltip.
        choices: Valid options for ``"select"`` type fields.  ``None``
            for other types.
        min_value: Minimum allowed value for ``"number"`` type fields.
        max_value: Maximum allowed value for ``"number"`` type fields.
        label: Human-friendly display label.  When empty, the UI falls
            back to auto-formatting the ``name`` field.
        details: Help text shown below the form control for additional
            guidance.
    """

    name: str
    field_type: str
    default: Any = None
    description: str = ""
    choices: list[str] | None = None
    min_value: float | None = None
    max_value: float | None = None
    label: str = ""
    details: str = ""


class DetectorPlugin(ABC):
    """Abstract base class for custom PII detector plugins.

    Plugins are discovered at startup from ``~/.scruxy/plugins/``.
    Each ``.py`` file must contain exactly one subclass of ``DetectorPlugin``.

    Subclasses **must** define the class attributes ``name`` and ``version``
    and implement the ``setup`` and ``detect`` methods.  ``teardown`` is
    optional and defaults to a no-op.

    Example::

        class MyDetector(DetectorPlugin):
            name = "my_detector"
            version = "1.0"

            config_schema = [
                ConfigField(name="pattern", field_type="string",
                            default=r"\\d+", description="Regex pattern"),
            ]

            def setup(self, config: dict) -> None:
                self.patterns = config.get("patterns", [])

            def detect(self, text: str, language: str) -> list[PiiEntity]:
                ...

    A per-plugin timeout guard (default 50 ms) protects the overall latency
    budget.  If ``detect`` exceeds the deadline the call is aborted and the
    plugin's contribution is skipped for that invocation.
    """

    name: str
    """Unique plugin identifier.  Must be set as a class attribute."""

    version: str
    """Plugin version string.  Must be set as a class attribute."""

    config_schema: list[ConfigField] = []
    """List of configurable fields exposed by this plugin.  The UI reads
    this to generate dynamic configuration forms.  Defaults to an empty
    list (no exposed configuration)."""

    description: str = ""
    """Short human-readable description of what this plugin detects.
    Displayed in the Plugins page UI.  Defaults to an empty string."""

    enabled: bool = True
    """Whether this plugin is enabled.  Defaults to ``True``.  When
    ``False`` the plugin is skipped during detection."""

    plugin_type: str = "user"
    """Plugin type identifier.  ``"user"`` for user-installed plugins,
    ``"builtin"`` for stages shipped with Scruxy."""

    use_word_boundary: bool = False
    """When ``True``, detected tokens use ``\\b`` word-boundary matching in
    the known-PII pre-filter.  Prevents substring matches (e.g. a path
    segment ``"repo"`` matching inside ``"repositories"``).  Individual
    entities may override this via :attr:`PiiEntity.use_word_boundary`."""

    case_sensitive: bool = True
    """When ``False``, the pre-filter uses case-insensitive matching for
    tokens produced by this plugin.  Individual entities may override via
    :attr:`PiiEntity.case_sensitive`."""

    exclude_from_prefilter: bool = False
    """When ``True``, tokens detected by this plugin are **not** added to
    the known-PII pre-filter cache.  Useful for plugins whose detections
    should not influence later requests (e.g. context-dependent detections
    that would cause false positives in different text)."""

    @abstractmethod
    def setup(self, config: dict) -> None:
        """Perform one-time initialisation.

        Called once at proxy startup.  Use this to load lookup tables,
        compile regexes, or initialise any heavyweight resources.

        Plugins can access a per-plugin key-value store via
        ``config["_storage"]`` if storage is configured.  See
        :class:`~scruxy.plugin.storage.PluginStorage` for the API.

        Args:
            config: The ``config`` dict from the ``plugins`` pipeline stage
                in ``config.yaml``.
        """

    @abstractmethod
    def detect(self, text: str, language: str) -> list[PiiEntity]:
        """Detect PII entities in *text*.

        This method is called on every text fragment that passes through the
        scrubbing pipeline.  It must be **fast** (< 50 ms) and **stateless**
        with respect to sessions.

        Args:
            text: The input text to scan.
            language: An ISO 639-1 language code (e.g. ``"en"``).

        Returns:
            A list of ``PiiEntity`` instances for every PII span found.
        """

    def teardown(self) -> None:
        """Release resources on shutdown.

        Called once when the proxy is shutting down.  Override to clean up
        open handles, caches, or temporary files.  The default implementation
        is a no-op.
        """
