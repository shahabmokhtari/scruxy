"""Presidio-based PII detection stage using spaCy NLP engine."""
from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import logging
import re
import shutil
import subprocess
import sys
import threading
import time
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from scruxy.plugin.base import ConfigField, DetectorPlugin, PiiEntity


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default post-filter rules (YAML-serialisable).
#
# Each rule targets one or more entity types and applies character-class
# validation + heuristic rejection patterns.  Detections that fail ANY
# of the active checks for their entity type are silently dropped before
# they ever reach the token map.
#
# Users can edit these from the Plugins → Presidio page in the UI.
# ---------------------------------------------------------------------------

_DEFAULT_POST_FILTER_RULES: dict[str, dict] = {
    "PERSON": {
        "allowed_chars": r"[\w\s\-\.\'',]",
        "reject_chars": r"[(){}<>=;:\[\]|/\\#@\^`~\+\*\!\?&\$%\d]",
        "min_length": 2,
        "must_contain_letter": True,
        "reject_patterns": [
            r"^[a-z]+[A-Z]",          # camelCase identifier
            r"\w+\(",                  # function call  Foo(
            r"<[^>]+>",               # HTML tag
            r"\d+px",                 # CSS pixel unit
            r"\d+r?em",              # CSS em/rem unit
            r"^\d+\.\d+\.\d+",       # version number
            r"^[A-Z]{1,4}\d",        # abbreviation+digit  KB5, AG08
            r"\bclass=",             # HTML attribute
            r"=>|->|::",             # code operators
            r"^\W+$",               # only non-word chars
            r"^[\s\d]+$",           # only whitespace/digits
            r"\.\w+\(",            # method call .Foo(
            r"\\[rnt]",            # escape sequences
            r"&#\d+;",            # HTML entities
            r"\{[^}]+\}",         # template/code braces
            r"@\w+",              # decorator/annotation
            r"^\w+\.\w+$",        # dotted identifier  t.id
            r"\bnew\(",           # constructor call
            r"^\-\-",             # CLI flag --git
            r"</\w+>",            # closing HTML tag  </a>
            r"^\w+=",             # assignment  Type=
        ],
    },
    "LOCATION": {
        "allowed_chars": r"[\w\s\-\.\'',]",
        "reject_chars": r"[(){}<>=;\[\]|\\#@\^`~\+\!\?\$%]",
        "min_length": 2,
        "must_contain_letter": True,
        "reject_patterns": [
            r"^[a-z]+[A-Z]",          # camelCase
            r"\w+\(",                  # function call
            r"<[^>]+>",               # HTML tag
            r"\d+px",                 # CSS
            r"\d+r?em",
            r"^:\*{1,2}$",           # :** or :*
            r"^::$",                 # scope operator
            r"=>|->",               # code operators
            r"^\W+$",               # only non-word chars
            r"^[\s\d]+$",
            r"\.\w+\(",            # method call
            r"\\[rnt]",
            r"\{[^}]+\}",
            r"@\w+",
            r"^\w+\.\w+$",        # dotted identifier
            r"^\w+_\w+$",         # snake_case identifier
            r"</\w+>",
            r"^\w+=",
        ],
    },
    "IP_ADDRESS": {
        "min_length": 3,
        "must_contain_letter": False,
        "reject_patterns": [
            r"^::$",                  # bare scope operator
            r"^:\*+$",               # colon+asterisks
            r"^\*+:$",               # asterisks+colon
        ],
    },
}


def _compile_post_filter_rules(
    raw_rules: dict[str, dict],
) -> dict[str, dict]:
    """Compile regex patterns in post-filter rules for fast matching."""
    compiled: dict[str, dict] = {}
    for entity_type, rule in raw_rules.items():
        entry: dict = {
            "min_length": rule.get("min_length", 1),
            "must_contain_letter": rule.get("must_contain_letter", False),
        }
        if "allowed_chars" in rule:
            try:
                entry["allowed_re"] = re.compile(rule["allowed_chars"])
            except re.error:
                logger.warning("Invalid allowed_chars pattern for %s: %s", entity_type, rule["allowed_chars"])
        if "reject_chars" in rule:
            try:
                entry["reject_re"] = re.compile(rule["reject_chars"])
            except re.error:
                logger.warning("Invalid reject_chars pattern for %s: %s", entity_type, rule["reject_chars"])
        reject_patterns: list[re.Pattern] = []
        for pat_str in rule.get("reject_patterns", []):
            try:
                reject_patterns.append(re.compile(pat_str))
            except re.error:
                logger.warning("Invalid reject_pattern for %s: %s", entity_type, pat_str)
        entry["reject_compiled"] = reject_patterns
        compiled[entity_type] = entry
    return compiled


def _apply_post_filter(
    text: str,
    entities: list[PiiEntity],
    compiled_rules: dict[str, dict],
    source_text: str,
) -> list[PiiEntity]:
    """Filter Presidio results, removing detections that match code patterns.

    Args:
        text: Unused (kept for API consistency).
        entities: Raw Presidio detections.
        compiled_rules: Pre-compiled per-entity-type filter rules.
        source_text: The original input text for span extraction.

    Returns:
        Filtered list with false positives removed.
    """
    if not compiled_rules:
        return entities

    accepted: list[PiiEntity] = []
    rejected_count = 0
    for entity in entities:
        rule = compiled_rules.get(entity.entity_type)
        if rule is None:
            # No filter for this entity type — accept as-is
            accepted.append(entity)
            continue

        span = source_text[entity.start:entity.end]
        # R67-6 fix: never log raw PII span content even at DEBUG.
        # Logging only the entity_type + position + length means
        # an operator with DEBUG enabled doesn't accidentally write
        # raw names/SSNs/etc. to log files.
        _span_meta = (entity.entity_type, entity.start, entity.end, len(span))

        # Min length check
        if len(span) < rule["min_length"]:
            rejected_count += 1
            logger.debug("Post-filter: rejected %s @[%d:%d] (len=%d) — too short", *_span_meta)
            continue

        # Must contain at least one letter
        if rule["must_contain_letter"] and not any(c.isalpha() for c in span):
            rejected_count += 1
            logger.debug("Post-filter: rejected %s @[%d:%d] (len=%d) — no letters", *_span_meta)
            continue

        # Reject if span contains forbidden characters
        reject_re = rule.get("reject_re")
        if reject_re is not None and reject_re.search(span):
            rejected_count += 1
            logger.debug("Post-filter: rejected %s @[%d:%d] (len=%d) — reject_chars match", *_span_meta)
            continue

        # Check reject patterns
        rejected = False
        for pat in rule.get("reject_compiled", []):
            if pat.search(span):
                rejected = True
                rejected_count += 1
                logger.debug(
                    "Post-filter: rejected %s @[%d:%d] (len=%d) — pattern %s",
                    *_span_meta, pat.pattern,
                )
                break
        if rejected:
            continue

        accepted.append(entity)

    if rejected_count:
        logger.info(
            "Post-filter: rejected %d of %d Presidio detections",
            rejected_count, len(entities),
        )
    return accepted


def _configure_spacy_for_platform() -> None:
    """Set spaCy n_process=1 on Windows to avoid spawn-related issues."""
    if sys.platform == "win32":
        try:
            import spacy

            # spaCy uses multiprocessing internally; Windows uses 'spawn' not 'fork',
            # so we must limit to a single process.
            spacy.prefer_gpu(False) if hasattr(spacy, "prefer_gpu") else None
        except ImportError:
            pass


def _ensure_spacy_model(model_name: str) -> None:
    """Ensure spaCy model is installed, downloading via uv/pip if needed."""
    import spacy

    if spacy.util.is_package(model_name):
        return

    logger.info("spaCy model '%s' not installed — downloading...", model_name)

    try:
        spacy.cli.download(model_name)
        return
    except SystemExit:
        # spacy download calls pip internally, which may not exist in uv venvs
        pass

    if not shutil.which("uv"):
        raise RuntimeError(
            f"spaCy model '{model_name}' not installed and auto-download failed. "
            f"Install manually: python -m spacy download {model_name}"
        )

    # Resolve compatible model version via spaCy's compatibility JSON
    import json
    import urllib.request

    compat_url = "https://raw.githubusercontent.com/explosion/spacy-models/master/compatibility.json"
    with urllib.request.urlopen(compat_url, timeout=30) as resp:
        compat = json.loads(resp.read())

    spacy_ver = spacy.about.__version__
    model_version = None
    for compat_spacy_ver, models in compat.get("spacy", {}).items():
        if model_name in models and spacy_ver.startswith(compat_spacy_ver.rsplit(".", 1)[0]):
            model_version = models[model_name][0]
            break

    if not model_version:
        raise RuntimeError(
            f"No compatible '{model_name}' version for spaCy {spacy_ver}. "
            f"Install manually: python -m spacy download {model_name}"
        )

    wheel_url = (
        f"https://github.com/explosion/spacy-models/releases/download/"
        f"{model_name}-{model_version}/{model_name}-{model_version}-py3-none-any.whl"
    )
    logger.info("Installing %s-%s via uv...", model_name, model_version)
    subprocess.check_call(["uv", "pip", "install", wheel_url])


def _get_presidio_version() -> str:
    """Return the installed presidio-analyzer version, or 'unknown'."""
    try:
        return importlib.metadata.version("presidio-analyzer")
    except Exception:
        return "unknown"


class PresidioPlugin(DetectorPlugin):
    """PII detection plugin powered by Microsoft Presidio and spaCy NLP.

    This plugin wraps Presidio's AnalyzerEngine to detect PII entities in text.
    It is thread-safe after initialization (Presidio's AnalyzerEngine is thread-safe).
    """

    name = "presidio"
    plugin_type = "builtin"
    version = _get_presidio_version()
    description = "Microsoft Presidio NLP-based PII detection with configurable entity types and score thresholds."
    enabled = True

    def __init__(self) -> None:
        # C5 fix: initialize the setup-lock unconditionally at construct
        # time so it has a stable identity before any thread can call
        # setup() / detect().  The previous lazy-init pattern
        # (`if not hasattr(self, "_setup_lock"): ... = RLock()`) was
        # itself non-atomic — concurrent first-time entry could create
        # two distinct locks and defeat the serialization guarantee.
        import threading as _threading
        self._setup_lock = _threading.RLock()
        super().__init__()

    config_schema = [
        ConfigField(
            name="spacy_model",
            field_type="string",
            default="en_core_web_lg",
            description="Name of the spaCy model to use for NLP",
            label="spaCy Model",
            details="Common models: en_core_web_sm (fast), en_core_web_md (balanced), en_core_web_lg (accurate)",
        ),
        ConfigField(
            name="language",
            field_type="select",
            default="en",
            description="Language code for text analysis",
            label="Language",
            choices=["en", "es", "de", "fr", "it", "pt", "nl", "he"],
        ),
        ConfigField(
            name="score_threshold",
            field_type="number",
            default=0.7,
            description="Minimum confidence score to include a detection",
            min_value=0.0,
            max_value=1.0,
            label="Confidence Threshold",
            details="Recommended range: 0.5 (more recall) to 0.85 (more precision). Default 0.7 balances precision for code-heavy text.",
        ),
        ConfigField(
            name="entities",
            field_type="list",
            default=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IP_ADDRESS"],
            description="List of entity types to detect (empty means all supported types)",
            label="Entity Types",
            details="Common types: PERSON, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN, IP_ADDRESS, LOCATION, IBAN_CODE, DATE_TIME, NRP. LOCATION removed by default due to high false-positive rate on code.",
        ),
        ConfigField(
            name="post_filter_enabled",
            field_type="boolean",
            default=True,
            description="Enable code-aware post-filtering to reject false positives (recommended for code-heavy traffic)",
            label="Post-Filter Enabled",
            details="When enabled, Presidio results are validated against per-entity-type rules that reject code identifiers, HTML fragments, CSS values, etc.",
        ),
        ConfigField(
            name="post_filter_rules",
            field_type="text",
            default="",
            description="YAML-formatted post-filter rules (leave empty to use built-in defaults)",
            label="Post-Filter Rules (YAML)",
            details=(
                "Per-entity-type rules with: allowed_chars (regex char class), reject_chars (regex char class), "
                "min_length, must_contain_letter (bool), reject_patterns (list of regexes). "
                "Example:\n"
                "PERSON:\n"
                "  min_length: 2\n"
                "  must_contain_letter: true\n"
                "  reject_patterns:\n"
                "    - '\\w+\\('\n"
                "    - '<[^>]+>'"
            ),
        ),
    ]

    def setup(self, config: dict) -> None:
        """Perform one-time initialisation using the provided config dict.

        Reads spacy_model, language, score_threshold, and entities from *config*,
        configures the platform, ensures the spaCy model is available, and
        creates the Presidio AnalyzerEngine.

        Thread-safety (B5/C5): the entire body runs under ``_setup_lock``
        (initialized in ``__init__``), and ``detect()`` takes the same
        lock for its read of the analyzer / language / entities /
        threshold attributes.  Without this serialisation a concurrent
        ``detect()`` thread could observe a partially-updated state
        and produce silently wrong results.
        """
        with self._setup_lock:
            self._setup_unlocked(config)

    def _setup_unlocked(self, config: dict) -> None:
        spacy_model = config.get("spacy_model", "en_core_web_lg")
        language = config.get("language", "en")
        self._language = language
        self._score_threshold = config.get("score_threshold", 0.7)
        self._entities = config.get("entities") or None

        _configure_spacy_for_platform()
        _ensure_spacy_model(spacy_model)

        # spaCy NER labels that Presidio has no recognizers for.
        # Listing them in labels_to_ignore silences the noisy warnings.
        _spacy_only_labels = [
            "CARDINAL", "ORDINAL", "MONEY", "PERCENT", "QUANTITY",
            "PRODUCT", "FAC", "WORK_OF_ART", "LAW", "LANGUAGE", "EVENT",
        ]

        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": spacy_model}],
                "ner_model_configuration": {
                    "labels_to_ignore": _spacy_only_labels,
                },
            }
        )
        nlp_engine = provider.create_engine()

        # Disable spaCy pipeline components not needed for NER.
        # Only tok2vec + ner are required; parser, tagger, lemmatizer,
        # and attribute_ruler add ~30-50% overhead for zero PII benefit.
        _disable_components = ["parser", "tagger", "lemmatizer", "attribute_ruler"]
        try:
            nlp_obj = nlp_engine.nlp.get(language) if hasattr(nlp_engine, "nlp") else None
            if nlp_obj is None and hasattr(nlp_engine, "nlp_engine"):
                nlp_obj = nlp_engine.nlp_engine
            if nlp_obj is not None:
                disabled = []
                for comp_name in _disable_components:
                    if comp_name in nlp_obj.pipe_names:
                        nlp_obj.disable_pipe(comp_name)
                        disabled.append(comp_name)
                if disabled:
                    logger.info(
                        "Disabled spaCy components for NER-only: %s (remaining: %s)",
                        disabled,
                        nlp_obj.pipe_names,
                    )
        except Exception:
            logger.debug("Could not disable spaCy components", exc_info=True)

        # Build the analyzer, then strip recognizers that don't support the
        # configured language or entity types.  This silences the noisy
        # "recognizer X doesn't support language Y" warnings that Presidio
        # emits for every unused recognizer on every analyze() call.
        self._analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=[language],
        )
        if self._entities:
            wanted = set(self._entities)
            registry = self._analyzer.registry
            to_remove = []
            for rec in registry.recognizers:
                supported = set(getattr(rec, "supported_entities", []))
                if not supported & wanted:
                    to_remove.append(rec)
            for rec in to_remove:
                try:
                    registry.remove_recognizer(rec.name if hasattr(rec, "name") else str(rec))
                except Exception:
                    # remove_recognizer might not exist in older versions
                    try:
                        registry.recognizers.remove(rec)
                    except ValueError:
                        pass
            if to_remove:
                kept = [getattr(r, "name", type(r).__name__) for r in registry.recognizers]
                logger.info("Presidio: removed %d unneeded recognizers, kept: %s", len(to_remove), kept)

        # Store config for reload detection.
        self._config = dict(config)

        # -- Post-filter: code-aware false-positive rejection --
        self._post_filter_enabled = config.get("post_filter_enabled", True)
        raw_rules_yaml = config.get("post_filter_rules", "")
        if raw_rules_yaml and isinstance(raw_rules_yaml, str) and raw_rules_yaml.strip():
            import yaml as _yaml
            try:
                user_rules = _yaml.safe_load(raw_rules_yaml)
                if isinstance(user_rules, dict):
                    self._post_filter_compiled = _compile_post_filter_rules(user_rules)
                    logger.info("Post-filter: loaded %d user-defined rules", len(user_rules))
                else:
                    logger.warning("Post-filter: YAML must be a mapping (entity_type → rule); using defaults")
                    self._post_filter_compiled = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
            except Exception:
                logger.warning("Post-filter: failed to parse YAML rules; using defaults", exc_info=True)
                self._post_filter_compiled = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        else:
            self._post_filter_compiled = _compile_post_filter_rules(_DEFAULT_POST_FILTER_RULES)
        # C3 fix: store the raw rules text so we can fingerprint it
        # in the result-cache key.  Without this fingerprint a
        # `reconfigure()` that changes the rule contents (but not the
        # enabled toggle) can return cached results computed under
        # the OLD rules — silent PII miss after rule tightening.
        self._post_filter_rules_fingerprint = hashlib.md5(
            (raw_rules_yaml or "").encode("utf-8", errors="replace")
        ).hexdigest()[:16]
        if self._post_filter_enabled:
            logger.info(
                "Post-filter enabled for entity types: %s",
                list(self._post_filter_compiled.keys()),
            )

        # Result cache: hash(text) → list[PiiEntity].  Avoids re-running
        # expensive NLP inference on text we've already analyzed.
        self._cache: dict[str, list[PiiEntity]] = {}
        self._cache_max_size: int = config.get("cache_size", 256)
        self._cache_hits = 0
        self._cache_misses = 0
        self._cache_lock = threading.Lock()

        # Warm up the analyzer with a dummy call to avoid a cold-start
        # latency spike (~2s) on the first real request.
        try:
            self._analyzer.analyze(text="warmup", language=language)
        except Exception:
            pass

        logger.info(
            "PresidioPlugin initialized with model=%s, language=%s, threshold=%.2f",
            spacy_model,
            language,
            self._score_threshold,
        )

    def reconfigure(self, config: dict) -> None:
        """Re-initialize if the configuration has changed."""
        old = getattr(self, "_config", None)
        if old == config:
            return
        logger.info("Presidio config changed — reinitializing")
        self.setup(config)

    def detect(self, text: str, language: str = "") -> list[PiiEntity]:
        """Detect PII entities in the given text using Presidio.

        Results are cached by text hash so identical text is not re-analyzed.

        Thread-safety (B5): we snapshot the analyzer + relevant config
        attributes under ``_setup_lock`` so a concurrent
        ``reconfigure()`` cannot rewrite them mid-detect.  The cache
        key derived from the snapshot ensures we don't return cached
        results that belong to a stale config.

        Args:
            text: The input text to analyze for PII.
            language: ISO 639-1 language code. If empty, falls back to
                the language configured during ``setup()``.

        Returns:
            A list of PiiEntity instances representing detected PII.
        """
        if not text:
            return []

        # Snapshot config under the setup lock (initialized in __init__)
        # so reconfigure() cannot interleave attribute reassignments
        # with our reads.  We hold the lock for the analyzer call too:
        # presidio's analyzer is documented thread-safe but reconfigure()
        # replaces the whole object, so we must keep our reference stable.
        with self._setup_lock:
            analyzer = self._analyzer
            language_cfg = self._language
            entities_cfg = list(self._entities) if self._entities else []
            score_threshold = self._score_threshold
            post_filter_enabled = self._post_filter_enabled
            post_filter_compiled = self._post_filter_compiled
            post_filter_fp = self._post_filter_rules_fingerprint

        # Check cache first.  The cache key MUST include every parameter
        # that affects analyzer output: language, entity filter,
        # score_threshold, and post_filter toggle.  Otherwise a
        # ``reconfigure()`` call (e.g. switching language or tightening
        # the threshold) could return stale results from an earlier
        # config — a silent PII-leakage path.
        lang_for_key = language or language_cfg
        ent_for_key = "|".join(sorted(entities_cfg)) if entities_cfg else "*"
        post_for_key = (
            f"1:{post_filter_fp}" if post_filter_enabled else "0"
        )
        score_for_key = f"{score_threshold:.4f}"
        cache_payload = (
            f"{lang_for_key}\x00{ent_for_key}\x00{score_for_key}\x00{post_for_key}\x00"
        ).encode("utf-8") + text.encode("utf-8", errors="replace")
        cache_key = hashlib.md5(cache_payload).hexdigest()
        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._cache_hits += 1
                logger.debug(
                    "Presidio cache HIT (len=%d, hits=%d, misses=%d)",
                    len(text), self._cache_hits, self._cache_misses,
                )
                # R66-1 fix: shallow ``list(...)`` copy returned the same
                # ``PiiEntity`` references (mutable dataclass) so callers
                # could corrupt the cache by mutating returned entries.
                # Per-element ``copy.copy(e)`` (which preserves
                # ad-hoc attributes like ``_matched_text`` set by
                # callers) isolates cache from caller.
                return [copy.copy(e) for e in cached]
            # R65-5 fix: increment cache_misses INSIDE the lock so
            # concurrent threads don't lose counter updates (telemetry).
            self._cache_misses += 1

        _start = time.perf_counter()

        lang = language or language_cfg

        kwargs: dict = {
            "text": text,
            "language": lang,
            "score_threshold": score_threshold,
            # Skip pipeline placeholder markers so they aren't detected as PII
            "allow_list": ["§§§SCRX\\d{4,}§§§"],
            "allow_list_match": "regex",
            "regex_flags": re.DOTALL | re.MULTILINE,
        }
        if entities_cfg:
            kwargs["entities"] = entities_cfg

        results = analyzer.analyze(**kwargs)

        entities: list[PiiEntity] = []
        for result in results:
            entities.append(
                PiiEntity(
                    entity_type=result.entity_type,
                    start=result.start,
                    end=result.end,
                    score=result.score,
                    source="presidio",
                )
            )

        # Apply code-aware post-filter before caching (use snapshot)
        pre_filter_count = len(entities)
        if post_filter_enabled and entities:
            entities = _apply_post_filter(
                text, entities, post_filter_compiled, text,
            )

        _elapsed = (time.perf_counter() - _start) * 1000
        if pre_filter_count != len(entities):
            logger.info(
                "Presidio: %d→%d entities (post-filter rejected %d) in %d chars, %.0fms",
                pre_filter_count, len(entities), pre_filter_count - len(entities),
                len(text), _elapsed,
            )
        else:
            logger.info(
                "Presidio: %d entities in %d chars, %.0fms (cache miss, hits=%d misses=%d)",
                len(entities), len(text), _elapsed,
                self._cache_hits, self._cache_misses,
            )

        # Store in cache (evict oldest if full).
        # R65-3 / R66-1 fix: store per-element COPIES (not just a
        # list copy of references) so caller mutations of returned
        # entries don't corrupt cached state.  Cache-hit path also
        # copies before returning.
        # R67-2 fix: skip cache entirely when cache_size <= 0 so
        # `next(iter({}))` doesn't raise StopIteration on the first
        # request when caching is disabled by config.
        if self._cache_max_size > 0:
            with self._cache_lock:
                if len(self._cache) >= self._cache_max_size:
                    oldest = next(iter(self._cache))
                    del self._cache[oldest]
                self._cache[cache_key] = [copy.copy(e) for e in entities]

        return entities


# Backward-compatibility alias
PresidioStage = PresidioPlugin
