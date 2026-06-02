"""FastAPI application factory with lifespan management.

``create_app`` builds the FastAPI application, wiring together configuration,
the scrubbing pipeline, token-map session store, proxy routes, and the
optional web UI.  Services are stored on ``app.state`` for handler access.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI

from scruxy.config.loader import load_config
from scruxy.config.models import AppConfig
from scruxy.pipeline.engine import PipelineEngine
from scruxy.plugin.file_path import FilePathDetector
from scruxy.plugin.presidio import PresidioPlugin
from scruxy.plugin.regex import RegexPlugin
from scruxy.plugin.whitelist import WhitelistPlugin
from scruxy.pipeline.plugin_stage import PluginStage
from scruxy.providers.anthropic import AnthropicProvider
from scruxy.providers.base import LLMProvider
from scruxy.providers.openai import OpenAIProvider
from scruxy.providers.openai_responses import OpenAIResponsesProvider
from scruxy.providers.registry import ProviderRegistry
from scruxy.proxy.forwarder import UpstreamForwarder
from scruxy.proxy.routes import router as proxy_router
from scruxy.recording.recorder import SessionRecorder
from scruxy.scrubber.request_scrubber import RequestScrubber
from scruxy.scrubber.response_unscrubber import ResponseUnscrubber
from scruxy.stats.collector import StatsCollector
from scruxy.tokenmap.replacer import build_strategies
from scruxy.tokenmap.service import ConcurrentSessionStore
from scruxy.ui.routes import mount_static, router as ui_router

logger = logging.getLogger(__name__)

VERSION = "0.1.0"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown."""
    config: AppConfig = app.state.config
    background_tasks: list[asyncio.Task[None]] = []

    logger.info("Starting Scruxy v%s", VERSION)

    # 0a. Legacy-config rescue: the ``mitmproxy`` interception mode
    # was retired several releases ago.  Older user configs in
    # ``~/.scruxy/config.yaml`` may still carry it.  Previously we
    # raised ``RuntimeError`` and the app refused to start, leaving
    # the operator with a daemon that wouldn't boot.  WHY this slipped
    # past 70 rounds of code review: every reviewer worked on the
    # in-tree source against synthetic test configs; no round ever
    # exercised "operator runs the app with a stale on-disk config".
    # Tests use ``AppConfig()`` defaults (``mode == "primary"``), so
    # the failure path was unreachable from the test suite.
    #
    # Fix: auto-migrate to ``primary`` with a loud WARNING.  The
    # operator gets a working daemon AND a clear instruction to
    # update their config file.  This is strictly safer than
    # crashing because (a) ``primary`` mode HAS scrubbing, (b)
    # ``mitmproxy`` mode has no scrubbing and would have leaked PII
    # if it had actually started — auto-migration to ``primary``
    # therefore upgrades both safety AND availability.
    if config.interception.mode == "mitmproxy":
        logger.warning(
            "Legacy interception.mode='mitmproxy' detected in config; "
            "auto-migrating to 'primary' for this run.  Edit "
            "~/.scruxy/config.yaml and change "
            "'interception.mode' from 'mitmproxy' to 'primary' to "
            "silence this warning.  (mitmproxy mode is no longer "
            "supported and would forward traffic WITHOUT PII "
            "scrubbing if it were honoured.)"
        )
        config.interception.mode = "primary"

    # 0b. Ensure directories and seed default files
    from scruxy.config.loader import ensure_directories
    ensure_directories(config)

    stages: list = []

    # Map base plugin names to their classes for instantiation
    _PLUGIN_CLASSES: dict[str, type] = {
        "whitelist": WhitelistPlugin,
        "presidio": PresidioPlugin,
        "regex": RegexPlugin,
        "file_path": FilePathDetector,
    }

    # Optional ML plugin: registered lazily so a missing ``opf`` package
    # never blocks startup.  The plugin's own ``setup()`` self-disables
    # if the import fails.
    try:
        from scruxy.plugin.openai_privacy_filter import OpenAIPrivacyFilterPlugin
        _PLUGIN_CLASSES["openai_privacy_filter"] = OpenAIPrivacyFilterPlugin
    except Exception:
        logger.debug("OpenAI Privacy Filter plugin unavailable", exc_info=True)

    def _resolve_base_type(stage_cfg: object) -> str:
        """Resolve a stage config to its base plugin type.

        Prefers explicit persisted ``stage_type`` metadata and falls back to
        legacy name inference for older configs.
        """
        explicit_type = getattr(stage_cfg, "stage_type", "")
        if explicit_type:
            return explicit_type

        name = getattr(stage_cfg, "name", "")
        for base in _PLUGIN_CLASSES:
            if name == base or name.startswith(base + "_copy"):
                return base
        return name

    # Whitelist stages must always run before other detectors, even if the
    # config was hand-edited or persisted in a bad order.
    ordered_stage_cfgs = sorted(
        config.pipeline.stages,
        key=lambda stage_cfg: (_resolve_base_type(stage_cfg) != "whitelist"),
    )
    config.pipeline.stages = ordered_stage_cfgs

    # Mutual-exclusion warning: Presidio and OpenAI Privacy Filter cover
    # the same PII categories.  Running both wastes CPU and complicates
    # token accounting because each detector mints its own entity for
    # the same span (the engine then merges them, but the second-pass
    # work is unnecessary).  Recommend operators pick one.
    _enabled_ner_stages = [
        getattr(s, "name", "")
        for s in ordered_stage_cfgs
        if getattr(s, "enabled", True)
        and _resolve_base_type(s) in ("presidio", "openai_privacy_filter")
    ]
    _has_presidio = any(_resolve_base_type(s) == "presidio"
                        for s in ordered_stage_cfgs
                        if getattr(s, "enabled", True))
    _has_opf = any(_resolve_base_type(s) == "openai_privacy_filter"
                   for s in ordered_stage_cfgs
                   if getattr(s, "enabled", True))
    if _has_presidio and _has_opf:
        logger.warning(
            "Both 'presidio' and 'openai_privacy_filter' stages are "
            "enabled in the pipeline.  These detectors cover the same "
            "PII categories and running both wastes CPU.  Disable one "
            "(typically 'presidio' if you want to A/B-test OPF) — "
            "enabled stages: %s",
            _enabled_ner_stages,
        )

    # Initialize all pipeline stages in config order (supports multiple instances).
    # Disabled stages are still instantiated so they appear in the runtime
    # pipeline list; the engine skips them via ``getattr(stage, "enabled", True)``.
    for stage_cfg in ordered_stage_cfgs:
        cfg_dict = dict(stage_cfg.config)
        base_type = _resolve_base_type(stage_cfg)

        # PluginStage (user plugins) — handled specially
        if base_type == "plugins":
            plugin_dir = cfg_dict.get("plugin_dir", "")
            plugin_stage = PluginStage(
                plugin_dir=plugin_dir,
                timeout_ms=cfg_dict.get("timeout_ms", 50),
                disabled_plugins=cfg_dict.get("disabled_plugins", []),
                storage_base_dir=str(Path(plugin_dir).expanduser() / "data") if plugin_dir else None,
                plugin_configs=cfg_dict.get("plugin_configs", {}),
            )
            plugin_stage.load_plugins()
            plugin_stage.enabled = stage_cfg.enabled
            stages.append(plugin_stage)
            logger.info("Plugin stage '%s' initialized (enabled=%s)", stage_cfg.name, stage_cfg.enabled)
            continue

        # Presidio — optional dependency, wrapped in try/except
        if base_type == "presidio":
            try:
                instance = PresidioPlugin()
                instance.setup(cfg_dict)
                instance.name = stage_cfg.name
                instance.enabled = stage_cfg.enabled
                stages.append(instance)
                logger.info("Presidio plugin '%s' initialized (enabled=%s)", stage_cfg.name, stage_cfg.enabled)
            except (ImportError, OSError) as exc:
                # Missing spaCy model or optional dependency — skip gracefully
                logger.warning(
                    "Presidio plugin '%s' not available — skipping (%s)",
                    stage_cfg.name, exc,
                )
            except Exception as exc:
                # Config/runtime error — fail fast so the user knows scrubbing is broken
                logger.error(
                    "Presidio plugin '%s' failed to initialize: %s",
                    stage_cfg.name, exc,
                )
                raise
            continue

        # All other builtin plugins
        cls = _PLUGIN_CLASSES.get(base_type)
        if cls is not None:
            instance = cls()
            instance.setup(cfg_dict)
            instance.name = stage_cfg.name
            instance.enabled = stage_cfg.enabled
            stages.append(instance)
            logger.info("%s plugin '%s' initialized (enabled=%s)", base_type.replace("_", " ").title(), stage_cfg.name, stage_cfg.enabled)
        else:
            logger.warning("Unknown pipeline stage type '%s' — skipping", stage_cfg.name)

    # 4-5. Register providers and wire upstream URLs from config
    registry = ProviderRegistry()
    provider_configs = config.providers  # dict[str, ProviderConfig]

    # Built-in providers: each class auto-loads its own YAML defaults.
    # Config overrides (upstream_url, enabled, text paths, etc.) are applied on top.
    builtin_providers: dict[str, type] = {
        "anthropic": AnthropicProvider,
        "openai": OpenAIProvider,
        "openai_responses": OpenAIResponsesProvider,
    }

    def _apply_config_overrides(prov: LLMProvider, cfg: ProviderConfig) -> None:
        """Apply user config overrides to a provider instance."""
        prov.upstream_url = cfg.upstream_url or prov.upstream_url
        prov.enabled = cfg.enabled
        # R69-1c (GPT-5.5 sibling): legacy YAML configs may already
        # contain a ``request_text_paths``/``response_text_paths``
        # list that exactly matches the provider's defaults (e.g. an
        # earlier UI "Save Paths" click before R69-1 fix landed, or a
        # config emitted by the displayed-defaults bug).  Re-applying
        # such a list as a user override would silently disable
        # AnthropicProvider/OpenAIProvider's custom Python extractors
        # of ``tool_use.input`` / ``tool_calls.function.arguments``.
        # Treat any byte-equal-to-default list as "use defaults".
        req_paths = cfg.request_text_paths
        if req_paths is not None and list(req_paths) == list(prov.default_request_text_paths or []):
            req_paths = None
        prov.user_request_text_paths = req_paths
        resp_paths = cfg.response_text_paths
        if resp_paths is not None and list(resp_paths) == list(prov.default_response_text_paths or []):
            resp_paths = None
        prov.user_response_text_paths = resp_paths
        if cfg.url_patterns is not None:
            prov._url_patterns = cfg.url_patterns
        if cfg.match_headers is not None:
            prov._match_headers = cfg.match_headers
        # Restore auth and session extraction overrides
        if cfg.auth_headers is not None:
            prov._auth_headers = cfg.auth_headers
        if cfg.session_id_headers is not None:
            prov._session_id_headers = cfg.session_id_headers
        if cfg.session_id_body_path is not None:
            prov._session_id_body_path = cfg.session_id_body_path
        if cfg.session_id_body_regex is not None:
            prov._session_id_body_regex = cfg.session_id_body_regex
            if cfg.session_id_body_regex:
                import re as _re_cfg
                # R71-7 fix: pre-screen with the same ReDoS heuristic
                # the PUT handler uses; reject pathological patterns
                # at startup instead of stalling on the first matching
                # request.
                try:
                    from scruxy.plugin.regex import _looks_catastrophic as _lc
                    _redos = _lc(cfg.session_id_body_regex)
                except Exception:
                    _redos = None
                if _redos:
                    logger.warning(
                        "Provider %r: session_id_body_regex looks "
                        "ReDoS-prone (%s); ignoring config override.",
                        getattr(prov, "name", "<unnamed>"), _redos,
                    )
                    prov._session_id_body_regex = ""
                    prov._compiled_session_id_body_regex = None
                else:
                    try:
                        prov._compiled_session_id_body_regex = _re_cfg.compile(cfg.session_id_body_regex)
                    except _re_cfg.error:
                        pass
            else:
                prov._compiled_session_id_body_regex = None
        if cfg.session_id_body_prefix is not None:
            prov._session_id_body_prefix = cfg.session_id_body_prefix

    for name, cls in builtin_providers.items():
        try:
            prov = cls()
            if name in provider_configs:
                _apply_config_overrides(prov, provider_configs[name])
            registry.register(prov)
            logger.info("Registered built-in provider '%s' (upstream=%s)", name, prov.upstream_url)
        except Exception:
            logger.warning("Failed to register built-in provider '%s'", name)

    # YAML-only built-in providers (no custom Python class needed)
    from scruxy.providers.yaml_provider import YAMLProvider as _YP
    _default_providers_dir = Path(__file__).resolve().parent.parent.parent / "default_config" / "providers"
    _registered_names = {p.name for p in registry.providers}
    for _yaml_name in ("copilot_chat", "copilot_responses"):
        if _yaml_name in _registered_names:
            continue
        _yaml_path = _default_providers_dir / f"{_yaml_name}.yaml"
        if _yaml_path.exists():
            try:
                import yaml as _yaml
                with open(_yaml_path) as _f:
                    _ycfg = _yaml.safe_load(_f)
                _prov = _YP(_ycfg)
                if _yaml_name in provider_configs:
                    _apply_config_overrides(_prov, provider_configs[_yaml_name])
                registry.register(_prov)
                logger.info("Registered built-in provider '%s' (upstream=%s)", _yaml_name, _prov.upstream_url)
            except Exception:
                logger.warning("Failed to register built-in provider '%s'", _yaml_name)

    # Load user-defined providers from custom_providers_dir
    from scruxy.providers.loader import load_providers as load_providers_from_dir
    user_providers_dir = Path(config.custom_providers_dir)
    if user_providers_dir.is_dir():
        for prov in load_providers_from_dir(user_providers_dir):
            if prov.name in builtin_providers or prov.name in registry:
                logger.info("Skipping user provider '%s' — already registered", prov.name)
                continue
            if prov.name in provider_configs:
                _apply_config_overrides(prov, provider_configs[prov.name])
            registry.register(prov)

    # Register any remaining providers defined in config but not yet loaded
    from scruxy.providers.yaml_provider import YAMLProvider
    registered_names = {p.name for p in registry.providers}
    for prov_name, prov_cfg in provider_configs.items():
        if prov_name in registered_names:
            continue
        try:
            yaml_config = {
                "name": prov_name,
                "display_name": prov_name,
                "upstream_url": prov_cfg.upstream_url,
                "enabled": prov_cfg.enabled,
                "url_patterns": prov_cfg.url_patterns or [],
                "match_headers": prov_cfg.match_headers or [],
                "auth_headers": prov_cfg.auth_headers or [],
                "session_id_headers": prov_cfg.session_id_headers or [],
                "session_id_body_path": prov_cfg.session_id_body_path,
                "session_id_body_regex": prov_cfg.session_id_body_regex,
                "session_id_body_prefix": prov_cfg.session_id_body_prefix,
                "request_text_paths": prov_cfg.request_text_paths or [],
                "response_text_paths": prov_cfg.response_text_paths or [],
            }
            custom_prov = YAMLProvider(yaml_config)
            registry.register(custom_prov)
            logger.info("Registered custom provider '%s' (upstream=%s)", prov_name, prov_cfg.upstream_url)
        except Exception:
            logger.warning("Failed to register custom provider '%s'", prov_name)

    app.state.registry = registry
    app.state.providers = registry

    # 6. Initialize session store
    replacement_strategies = build_strategies(config.tokens.replacements)
    session_store = ConcurrentSessionStore(
        storage_dir=str(config.sessions.storage_dir),
        flush_interval_seconds=config.sessions.flush_interval_seconds,
        replacements=replacement_strategies,
        expiration_hours=config.tokens.expiration_hours,
        persistent=config.tokens.persistent,
    )
    app.state.replacement_strategies = replacement_strategies
    await session_store.start()
    app.state.session_store = session_store
    logger.info("Session store initialized")

    # 7. Initialize stats
    stats = StatsCollector(storage_file=str(config.stats.storage_file))
    await stats.load_from_disk()
    app.state.stats = stats
    logger.info("Stats collector initialized")

    # 8. Session recorder (only when enabled)
    recorder = None
    if config.recording.enabled:
        recorder = SessionRecorder(
            storage_dir=str(config.sessions.storage_dir),
            store_body_original=config.recording.store_body_original,
        )
        app.state.recorder = recorder
        app.state.recording = recorder
        logger.info("Session recorder initialized")
    else:
        app.state.recorder = None
        app.state.recording = None
        logger.info("Session recorder disabled by config")

    # 8b. Session title resolver (Claude/Copilot transcript titles)
    from scruxy.ui.session_titles import SessionTitleResolver
    title_resolver = SessionTitleResolver()
    app.state.session_title_resolver = title_resolver

    # 9. Pipeline engine
    pipeline = PipelineEngine(stages=stages)
    app.state.pipeline = pipeline
    logger.info("Pipeline engine initialized with %d stages", len(stages))

    # 9b. Event bus for SSE push to UI
    from types import SimpleNamespace
    event_bus = SimpleNamespace(subscribers=[])
    app.state.event_bus = event_bus

    # 10. Scrubber / Unscrubber
    app.state.request_scrubber = RequestScrubber()
    app.state.response_unscrubber = ResponseUnscrubber()

    # 11. Upstream forwarder
    forwarder = UpstreamForwarder()
    app.state.forwarder = forwarder

    # 11b. Passthrough log (in-memory ring buffer + disk persistence)
    from collections import deque
    import json as _json
    pt_cfg = config.interception.passthrough
    pt_log: deque = deque(maxlen=pt_cfg.max_entries)
    pt_storage = Path(pt_cfg.storage_file)

    # Load persisted entries from previous session
    if pt_storage.is_file():
        try:
            with open(pt_storage, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        pt_log.append(_json.loads(line))
            logger.info("Loaded %d passthrough log entries from %s", len(pt_log), pt_storage)
        except Exception:
            logger.warning("Failed to load passthrough log from %s", pt_storage)

    app.state.passthrough_log = pt_log
    app.state.passthrough_enabled = pt_cfg.enabled
    app.state.passthrough_storage_file = str(pt_storage)

    # Store the main listen port so the proxy catch-all can distinguish
    # dashboard requests (main port) from proxy requests (other ports).
    # Passthrough is only allowed on non-main ports (8081, 8443, etc.).
    app.state.main_listen_port = config.interception.listen_port

    # Routes are mounted in create_app() — not here — so they're always
    # available regardless of lifespan startup success.

    # 14. (Background JSON flush removed — DB write-through handles persistence)

    # 14b. Mitmproxy mode — rejected at startup (see 0a above)
    app.state.mitmproxy_backend = None

    # 14c. Start forward proxy if enabled
    app.state.forward_proxy = None
    if config.interception.forward_proxy.enabled:
        try:
            from scruxy.cert.ca import CertificateAuthority
            from scruxy.proxy.forward_proxy import ForwardProxyServer, _set_strict_http_parsing

            # Apply strict-HTTP-parsing toggle (default False = tolerant
            # WARN+passthrough; safer for real-world clients).
            _set_strict_http_parsing(
                bool(getattr(config.interception.forward_proxy, "strict_http_parsing", False))
            )

            ca = CertificateAuthority(cert_dir=config.interception.forward_proxy.ca_cert_dir)
            fwd_proxy = ForwardProxyServer(
                host=config.interception.listen_host,
                port=config.interception.forward_proxy.listen_port,
                ca=ca,
                registry=registry,
                pipeline=pipeline,
                session_store=session_store,
                request_scrubber=app.state.request_scrubber,
                response_unscrubber=app.state.response_unscrubber,
                stats=stats,
                event_bus=event_bus,
                recorder=recorder,
                passthrough_log=app.state.passthrough_log,
                passthrough_enabled_ref=lambda: getattr(app.state, "passthrough_enabled", False),
                passthrough_storage_file=getattr(app.state, "passthrough_storage_file", None),
                main_listen_port=config.interception.listen_port,
            )
            await fwd_proxy.start()
            app.state.forward_proxy = fwd_proxy
            logger.info(
                "Forward proxy started on %s:%d (CA cert: %s)",
                config.interception.listen_host,
                config.interception.forward_proxy.listen_port,
                ca.ca_cert_path,
            )
        except Exception:
            logger.exception("Failed to start forward proxy")

    # 14d. Start HTTPS reverse proxy listener if enabled
    app.state.https_server = None
    if config.interception.https.enabled:
        try:
            import ssl
            import tempfile

            import uvicorn

            from scruxy.cert.ca import CertificateAuthority

            ca = CertificateAuthority(cert_dir=config.interception.https.ca_cert_dir)
            host = config.interception.listen_host
            pair = ca.get_host_cert(host)

            # Write cert/key to persistent files in the cert dir
            cert_dir = Path(config.interception.https.ca_cert_dir).expanduser()
            cert_dir.mkdir(parents=True, exist_ok=True)
            cert_file = cert_dir / "localhost.pem"
            key_file = cert_dir / "localhost.key"
            cert_file.write_bytes(pair.cert_pem)
            key_file.write_bytes(pair.key_pem)
            try:
                key_file.chmod(0o600)
            except OSError:
                pass  # Windows doesn't support Unix permissions

            uv_config = uvicorn.Config(
                app,
                host=host,
                port=config.interception.https.listen_port,
                ssl_certfile=str(cert_file),
                ssl_keyfile=str(key_file),
                log_level=config.logging.level.lower(),
                lifespan="off",
            )
            https_server = uvicorn.Server(uv_config)

            async def _run_https() -> None:
                try:
                    await https_server.serve()
                except asyncio.CancelledError:
                    pass
                except SystemExit:
                    logger.warning(
                        "HTTPS listener failed to start (port %d may be in use). "
                        "Proxy continues without HTTPS.",
                        config.interception.https.listen_port,
                    )

            https_task = asyncio.create_task(_run_https())
            background_tasks.append(https_task)
            app.state.https_server = https_server
            logger.info(
                "HTTPS listener started on https://%s:%d (CA cert: %s)",
                host,
                config.interception.https.listen_port,
                ca.ca_cert_path,
            )
        except Exception:
            logger.exception("Failed to start HTTPS listener")

    logger.info("Scruxy startup complete")
    try:
        yield
    except asyncio.CancelledError:
        # Uvicorn on Windows raises CancelledError during Ctrl+C shutdown.
        # This is expected and safe to suppress.
        pass

    # SHUTDOWN
    logger.info("Shutting down Scruxy")

    for task in background_tasks:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    # R55-3 fix: stop the forward proxy (cancels in-flight scrub
    # tasks) BEFORE closing the session store so any final token
    # mappings produced by those tasks are persisted via the still-
    # open SQLite handle.  The previous order (`session_store.stop()`
    # first) closed the DB while scrub tasks were still writing,
    # losing the last few mappings — same PII would mint a NEW
    # token on the next start, breaking determinism.
    if app.state.forward_proxy is not None:
        try:
            await app.state.forward_proxy.stop()
        except Exception:
            logger.debug("Error stopping forward proxy", exc_info=True)

    if app.state.mitmproxy_backend is not None:
        try:
            await app.state.mitmproxy_backend.stop()
        except Exception:
            logger.debug("Error stopping mitmproxy backend", exc_info=True)

    try:
        await session_store.stop()
    except Exception:
        logger.debug("Error during session store shutdown", exc_info=True)

    try:
        await forwarder.close()
    except Exception:
        logger.debug("Error closing upstream forwarder", exc_info=True)

    try:
        await stats.save_to_disk()
    except Exception:
        logger.debug("Error saving stats to disk", exc_info=True)

    if app.state.https_server is not None:
        try:
            app.state.https_server.should_exit = True
        except Exception:
            logger.debug("Error stopping HTTPS server", exc_info=True)

    # R58-4 fix: invoke ``teardown()`` on every pipeline stage that
    # has one — most importantly ``PluginStage.teardown()`` which
    # flushes per-plugin storage and shuts down the worker
    # ``ThreadPoolExecutor``.  Without this, plugin state written
    # via ``_storage.set()`` between flushes can be lost on normal
    # Scruxy shutdown.  Errors are logged but suppressed so one
    # broken stage cannot block the rest of the shutdown sequence.
    pipeline = getattr(app.state, "pipeline", None)
    if pipeline is not None:
        for stage in getattr(pipeline, "stages", []) or []:
            teardown = getattr(stage, "teardown", None)
            if callable(teardown):
                try:
                    teardown()
                except Exception:
                    logger.debug(
                        "Error tearing down pipeline stage %r",
                        stage, exc_info=True,
                    )

    logger.info("Scruxy shutdown complete")


def create_app(config: AppConfig | None = None, config_path: Path | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        config: Validated application config. Loaded from default if ``None``.
        config_path: Path to the YAML config file on disk.  Stored on
            ``app.state.config_path`` so that UI endpoints can persist
            config changes back to the same file.
    """
    if config is None:
        config = load_config()

    app = FastAPI(
        title="Scruxy",
        version=VERSION,
        lifespan=lifespan,
    )
    app.state.config = config
    app.state.config_path = config_path

    # Disable caching for static files during local development.
    # Must be added before app starts (before lifespan runs).
    import asyncio as _asyncio

    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request as StarletteRequest
    from starlette.responses import Response as StarletteResponse

    class NoCacheStaticMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: StarletteRequest, call_next: object) -> StarletteResponse:
            try:
                response = await call_next(request)  # type: ignore[operator]
            except _asyncio.CancelledError:
                # Shutdown in progress — return a minimal response to avoid
                # noisy tracebacks from BaseHTTPMiddleware's task group.
                return StarletteResponse(status_code=503)  # type: ignore[return-value]
            if request.url.path.startswith("/ui/static"):
                response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                response.headers["Pragma"] = "no-cache"
            return response  # type: ignore[return-value]

    app.add_middleware(NoCacheStaticMiddleware)

    # Mount routes at app creation time (not in lifespan) so they're always
    # available even if a lifespan stage fails.  Order matters: static mounts
    # first, then UI router, then the proxy catch-all last.
    mount_static(app)
    app.include_router(ui_router)
    app.include_router(proxy_router)

    return app
