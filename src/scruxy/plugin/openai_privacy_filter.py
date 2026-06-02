"""OpenAI Privacy Filter (OPF) detector plugin.

Wraps the open-source ``openai/privacy-filter`` model
(https://github.com/openai/privacy-filter) as a Scruxy
``DetectorPlugin``.  The underlying model is a 1.5B-parameter
bidirectional token classifier with 50M active parameters that
labels eight PII categories in a single forward pass.

Optional dependency: install ``opf`` from the upstream repo
(``pip install git+https://github.com/openai/privacy-filter@main``).
The first call downloads the checkpoint to ``~/.opf/privacy_filter``
unless ``OPF_CHECKPOINT`` or the ``checkpoint_path`` config field is
set.

This plugin is disabled by default.  Enable it on the Plugins page
or in ``config.yaml`` once the ``opf`` package + checkpoint are
available.  When ``opf`` is not installed, ``setup`` logs a
``WARNING`` and the plugin self-disables instead of crashing the
proxy at startup.
"""
from __future__ import annotations

import logging
import threading
from typing import Any

from scruxy.plugin.base import ConfigField, DetectorPlugin, PiiEntity


logger = logging.getLogger(__name__)


# OPF model labels → Scruxy entity types.  Kept conservative — these
# map to the same entity type names Presidio emits where they overlap
# so token reuse across detectors works out of the box.
_OPF_LABEL_TO_ENTITY: dict[str, str] = {
    "account_number": "ACCOUNT_NUMBER",
    "private_address": "ADDRESS",
    "private_email": "EMAIL_ADDRESS",
    "private_person": "PERSON",
    "private_phone": "PHONE_NUMBER",
    "private_url": "URL",
    "private_date": "DATE_TIME",
    "secret": "SECRET",
}


class OpenAIPrivacyFilterPlugin(DetectorPlugin):
    """PII detection via OpenAI Privacy Filter (token classification model).

    Operating points (precision/recall trade-off) are exposed via the
    ``decode_mode`` config: ``viterbi`` (default, higher precision) or
    ``argmax`` (faster, lower precision).
    """

    name = "openai_privacy_filter"
    plugin_type = "builtin"
    version = "0.1"
    description = (
        "OpenAI Privacy Filter — 1.5B-param bidirectional token "
        "classifier for PII detection.  Detects account numbers, "
        "addresses, emails, names, phones, URLs, dates, and secrets. "
        "Requires the optional 'opf' package (see plugin description)."
    )
    # Disabled by default: heavy-weight ML dependency that operators
    # opt into.  The presidio plugin remains the default NER stage.
    enabled = False

    config_schema = [
        ConfigField(
            name="device",
            field_type="select",
            default="cpu",
            choices=["cpu", "cuda"],
            description="Inference device.",
            label="Device",
            details=(
                "Use 'cuda' if you have an NVIDIA GPU with PyTorch CUDA "
                "support installed.  Falls back to 'cpu' on import error."
            ),
        ),
        ConfigField(
            name="checkpoint_path",
            field_type="string",
            default="",
            description=(
                "Path to a pre-downloaded OPF checkpoint directory. "
                "Leave empty to use $OPF_CHECKPOINT or auto-download "
                "to ~/.opf/privacy_filter on first use."
            ),
            label="Checkpoint path",
        ),
        ConfigField(
            name="decode_mode",
            field_type="select",
            default="viterbi",
            choices=["viterbi", "argmax"],
            description=(
                "Span decoder mode.  'viterbi' is higher precision; "
                "'argmax' is faster but may produce noisier spans."
            ),
            label="Decode mode",
        ),
        ConfigField(
            name="min_score",
            field_type="number",
            default=0.5,
            min_value=0.0,
            max_value=1.0,
            description=(
                "Minimum confidence score for emitted spans.  OPF does "
                "not expose per-span probabilities directly, so this is "
                "currently a fixed-confidence label applied to every "
                "span the decoder accepts."
            ),
            label="Min score",
        ),
        ConfigField(
            name="enabled_labels",
            field_type="list",
            default=list(_OPF_LABEL_TO_ENTITY.keys()),
            description=(
                "OPF label categories to emit.  Leave empty to enable all."
            ),
            label="Enabled labels",
        ),
        ConfigField(
            name="max_text_length",
            field_type="number",
            default=64_000,
            min_value=0.0,
            description=(
                "Skip texts longer than this many characters to avoid "
                "the model's per-call latency dominating the pipeline.  "
                "0 disables the cap."
            ),
            label="Max text length (chars)",
        ),
    ]

    def __init__(self) -> None:
        self._opf: Any = None  # opf._api.OPF instance, lazily loaded
        self._lock = threading.Lock()
        self._enabled_labels: set[str] = set()
        self._min_score: float = 0.5
        self._max_text_length: int = 0
        # Normalised confidence label applied to every detection.
        self._fixed_score: float = 0.0
        # Track failed-import state so detect() short-circuits cheaply
        # without re-attempting the import on every call.
        self._import_failed: bool = False

    def setup(self, config: dict) -> None:
        """Lazy-init: only validate config + check importability here.

        The actual OPF runtime construction (which downloads the
        ~1.5GB checkpoint on first use) is deferred to ``detect()``
        the first time it's invoked.  This way:
          - Daemons that have ``opf`` installed but the plugin
            disabled don't pay the cold-start cost on every boot.
          - Toggling enable in the UI becomes a transparent
            "first request loads the model" flow rather than
            requiring a daemon restart.
        """
        device = str(config.get("device", "cpu")).lower()
        if device not in ("cpu", "cuda"):
            device = "cpu"
        self._device = device
        self._checkpoint_path = (config.get("checkpoint_path") or "").strip() or None
        decode_mode = str(config.get("decode_mode", "viterbi")).lower()
        if decode_mode not in ("viterbi", "argmax"):
            decode_mode = "viterbi"
        self._decode_mode = decode_mode
        try:
            self._min_score = float(config.get("min_score", 0.5))
        except (TypeError, ValueError):
            self._min_score = 0.5
        self._fixed_score = max(0.0, min(1.0, self._min_score))
        try:
            self._max_text_length = int(config.get("max_text_length", 64_000) or 0)
        except (TypeError, ValueError):
            self._max_text_length = 64_000

        labels_cfg = config.get("enabled_labels") or list(_OPF_LABEL_TO_ENTITY.keys())
        if isinstance(labels_cfg, str):
            labels_cfg = [s.strip() for s in labels_cfg.split(",") if s.strip()]
        self._enabled_labels = {
            lbl for lbl in labels_cfg if lbl in _OPF_LABEL_TO_ENTITY
        }
        if not self._enabled_labels:
            self._enabled_labels = set(_OPF_LABEL_TO_ENTITY.keys())

        # Probe importability without actually loading the runtime.  This
        # tells the UI whether the optional 'opf' package is present so
        # it can show an "Install" button vs. "Configure" form.
        try:
            import importlib.util as _util
            spec = _util.find_spec("opf")
            self._import_failed = spec is None
        except Exception:
            self._import_failed = True
        if self._import_failed:
            logger.warning(
                "openai_privacy_filter: 'opf' package not installed; "
                "plugin self-disables.  Install via "
                "'pip install -e .[opf]' (or POST "
                "/ui/api/plugins/openai_privacy_filter/install)."
            )
        # OPF runtime constructed on demand in _ensure_runtime().
        self._opf = None

    def _ensure_runtime(self) -> bool:
        """Construct the OPF runtime on first use.  Returns True iff
        ready to serve detect() calls."""
        if self._opf is not None:
            return True
        if self._import_failed:
            return False
        with self._lock:
            if self._opf is not None:
                return True
            try:
                from opf._api import OPF  # type: ignore[import-not-found]
            except ImportError as exc:
                logger.warning(
                    "openai_privacy_filter: deferred import of 'opf' "
                    "failed (%s); self-disabling.",
                    exc,
                )
                self._import_failed = True
                return False
            try:
                self._opf = OPF(
                    model=self._checkpoint_path,
                    device=self._device,  # type: ignore[arg-type]
                    output_mode="typed",
                    decode_mode=self._decode_mode,  # type: ignore[arg-type]
                    output_text_only=False,
                )
            except Exception:
                logger.exception(
                    "openai_privacy_filter: failed to initialise OPF "
                    "runtime; plugin self-disables for this run."
                )
                self._import_failed = True
                self._opf = None
                return False
            return True

    def detect(self, text: str, language: str) -> list[PiiEntity]:
        """Run OPF on ``text`` and return Scruxy ``PiiEntity`` objects."""
        if self._import_failed:
            return []
        if not text:
            return []
        if self._max_text_length and len(text) > self._max_text_length:
            return []
        if not self._ensure_runtime():
            return []

        # The OPF runtime is not documented as thread-safe; serialise
        # via an instance lock.  Pipeline stages are already invoked
        # off the event loop via ``asyncio.to_thread``, so a per-stage
        # lock here just protects against concurrent worker threads
        # calling the same plugin instance.
        with self._lock:
            try:
                result = self._opf.redact(text)
            except Exception:
                logger.exception("openai_privacy_filter: redact() failed")
                return []

        spans = getattr(result, "detected_spans", None) or ()
        entities: list[PiiEntity] = []
        for span in spans:
            label = getattr(span, "label", "")
            if label not in self._enabled_labels:
                continue
            entity_type = _OPF_LABEL_TO_ENTITY.get(label)
            if not entity_type:
                continue
            try:
                start = int(getattr(span, "start", -1))
                end = int(getattr(span, "end", -1))
            except (TypeError, ValueError):
                continue
            if start < 0 or end <= start or end > len(text):
                continue
            entities.append(
                PiiEntity(
                    entity_type=entity_type,
                    start=start,
                    end=end,
                    score=self._fixed_score,
                    source=self.name,
                )
            )
        return entities

    def teardown(self) -> None:
        """Release the OPF runtime so the GPU/RAM is freed on shutdown."""
        with self._lock:
            self._opf = None
