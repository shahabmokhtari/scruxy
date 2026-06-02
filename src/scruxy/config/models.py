"""Pydantic configuration models mirroring config.yaml schema."""
from __future__ import annotations

from pathlib import Path

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class MitmproxyConfig(BaseModel):
    """Mitmproxy fallback interception settings."""

    listen_port: int = 8081
    auto_install_cert: bool = True
    auto_uninstall_cert_on_exit: bool = True
    cert_dir: str = "~/.mitmproxy"


class ForwardProxyConfig(BaseModel):
    """HTTP forward proxy settings (standard HTTP_PROXY protocol)."""

    enabled: bool = True
    listen_port: int = 8081
    ca_cert_dir: str = "~/.scruxy/certs"
    auto_install_ca_cert: bool = True
    # When True, enforce strict RFC 9110/9112 request parsing:
    # - reject obs-fold continuation lines
    # - reject bare CR / LF in header values
    # - reject non-token characters in header field-name
    # - reject CTL chars in header values
    # - reject non-ASCII Content-Length / chunk-size
    # - reject method/version forms outside RFC 9112 §3
    # When False (default), the same checks log a WARNING and pass
    # the request through.  Default is False because real-world
    # clients (some VS Code extensions, legacy proxies) emit lax
    # forms that strict parsing rejects with 400, breaking the
    # user experience.  Operators handling untrusted traffic should
    # set strict_http_parsing=True.
    strict_http_parsing: bool = False


class HttpsConfig(BaseModel):
    """HTTPS reverse proxy listener settings."""

    enabled: bool = False
    listen_port: int = 8443
    ca_cert_dir: str = "~/.scruxy/certs"


class PassthroughConfig(BaseModel):
    """Passthrough logging settings for non-provider requests."""

    enabled: bool = False
    max_entries: int = 500
    storage_file: str = "~/.scruxy/passthrough_log.jsonl"


class InterceptionConfig(BaseModel):
    """Interception mode settings."""

    mode: str = "primary"
    listen_host: str = "localhost"
    listen_port: int = 8080
    mitmproxy: MitmproxyConfig = Field(default_factory=MitmproxyConfig)
    forward_proxy: ForwardProxyConfig = Field(default_factory=ForwardProxyConfig)
    https: HttpsConfig = Field(default_factory=HttpsConfig)
    passthrough: PassthroughConfig = Field(default_factory=PassthroughConfig)


class ProviderConfig(BaseModel):
    """Per-provider configuration."""

    enabled: bool = True
    upstream_url: str = ""
    url_patterns: list[str] | None = None
    match_headers: list[str] | None = None
    auth_headers: list[str] | None = None
    session_id_headers: list[str] | None = None
    session_id_body_path: str = ""  # Dotted path to extract session ID from body
    session_id_body_regex: str = ""  # Regex with capture group to extract portion
    session_id_body_prefix: str = ""  # Prefix for body-extracted session IDs
    request_text_paths: list[str] | None = None
    response_text_paths: list[str] | None = None


class ReplacementConfig(BaseModel):
    """Per-entity-type replacement strategy configuration."""

    strategy: Literal["default", "uuid", "script"] = "default"
    command: str = ""  # required when strategy == "script"
    timeout_ms: int = 5000  # for script strategy
    enabled: bool = True

    @model_validator(mode="after")
    def _validate_script_command(self) -> ReplacementConfig:
        if self.strategy == "script" and not self.command.strip():
            raise ValueError("strategy 'script' requires a non-empty 'command'")
        return self


class TokenConfig(BaseModel):
    """Token format settings."""

    prefix: str = "REDACTED"
    format: str = "{prefix}_{category}_{n}"
    max_token_length: int = 40
    expiration_hours: int = 168  # 7 days, 0 = never expire
    persistent: bool = True  # False = in-memory only, no SQLite DB
    replacements: dict[str, ReplacementConfig] = Field(default_factory=dict)


class PipelineStageConfig(BaseModel):
    """Individual pipeline stage configuration."""

    name: str
    stage_type: str = ""  # Persisted plugin/stage type; empty = infer from name for legacy configs
    display_name: str = ""  # User-facing title; empty = use computed name
    enabled: bool = True
    config: dict = Field(default_factory=dict)


class PipelineConfig(BaseModel):
    """Scrubbing pipeline settings."""

    stages: list[PipelineStageConfig] = Field(default_factory=lambda: [
        PipelineStageConfig(
            name="whitelist",
            enabled=True,
            config={"whitelist_file": "~/.scruxy/whitelist.yaml"},
        ),
        PipelineStageConfig(
            name="presidio",
            enabled=True,
            config={
                "spacy_model": "en_core_web_lg",
                "language": "en",
                "score_threshold": 0.7,
                "entities": [
                    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
                    "CREDIT_CARD", "US_SSN", "IP_ADDRESS",
                ],
                "post_filter_enabled": True,
            },
        ),
        PipelineStageConfig(
            name="regex",
            enabled=True,
            config={"patterns_file": "~/.scruxy/regex_patterns.yaml"},
        ),
        PipelineStageConfig(
            name="file_path",
            enabled=True,
            config={"score": 0.95},
        ),
        PipelineStageConfig(
            name="plugins",
            enabled=True,
            config={"plugin_dir": "~/.scruxy/plugins", "timeout_ms": 50},
        ),
        PipelineStageConfig(
            # OpenAI Privacy Filter — heavy ML PII detector.  Disabled
            # by default because (a) the ``opf`` package is an optional
            # extra (``pip install 'scruxy[opf]'``) and (b) Presidio is
            # the default NER stage.  Recommended pattern: enable EITHER
            # presidio OR openai_privacy_filter, not both — they cover
            # the same PII categories and running both wastes CPU and
            # complicates token accounting.  ``app.py`` emits a WARNING
            # at startup when both are enabled.
            #
            # Listed AFTER ``plugins`` so existing tests that index
            # ``config.pipeline.stages[4]`` (the plugins stage) keep
            # working without modification.
            name="openai_privacy_filter",
            enabled=False,
            config={
                "device": "cpu",
                "decode_mode": "viterbi",
                "min_score": 0.5,
                "max_text_length": 64000,
            },
        ),
    ])


class SessionConfig(BaseModel):
    """Session management settings."""

    storage_dir: str = "~/.scruxy/sessions"
    max_session_age_hours: int = 168
    flush_interval_seconds: int = 5


class RecordingConfig(BaseModel):
    """Session recording settings."""

    enabled: bool = True
    store_body_original: bool = False


class UIConfig(BaseModel):
    """Web UI settings."""

    enabled: bool = True
    open_browser_on_start: bool = True


class LoggingConfig(BaseModel):
    """Logging settings."""

    level: str = "info"
    log_dir: str = "~/.scruxy/logs"
    log_scrub_events: bool = True
    retention_days: int = 7


class StatsConfig(BaseModel):
    """Statistics settings."""

    enabled: bool = True
    storage_file: str = "~/.scruxy/stats.json"


class AppConfig(BaseModel):
    """Root application configuration."""

    interception: InterceptionConfig = Field(default_factory=InterceptionConfig)
    providers: dict[str, ProviderConfig] = Field(default_factory=lambda: {
        "anthropic": ProviderConfig(enabled=True, upstream_url="https://api.anthropic.com"),
        "openai": ProviderConfig(enabled=True, upstream_url="https://api.openai.com"),
        "openai_responses": ProviderConfig(enabled=True, upstream_url="https://api.openai.com"),
    })
    custom_providers_dir: str = "~/.scruxy/providers"
    tokens: TokenConfig = Field(default_factory=TokenConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    sessions: SessionConfig = Field(default_factory=SessionConfig)
    recording: RecordingConfig = Field(default_factory=RecordingConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    stats: StatsConfig = Field(default_factory=StatsConfig)

    @model_validator(mode="after")
    def _expand_tilde_paths(self) -> AppConfig:
        """Expand ~ in all path-like string fields throughout the config tree."""
        for field_name in ("custom_providers_dir",):
            val = getattr(self, field_name)
            if isinstance(val, str) and val.startswith("~"):
                object.__setattr__(self, field_name, str(Path(val).expanduser()))
        # Sub-models with path fields
        if isinstance(self.sessions.storage_dir, str) and self.sessions.storage_dir.startswith("~"):
            self.sessions.storage_dir = str(Path(self.sessions.storage_dir).expanduser())
        if isinstance(self.logging.log_dir, str) and self.logging.log_dir.startswith("~"):
            self.logging.log_dir = str(Path(self.logging.log_dir).expanduser())
        if isinstance(self.stats.storage_file, str) and self.stats.storage_file.startswith("~"):
            self.stats.storage_file = str(Path(self.stats.storage_file).expanduser())
        if isinstance(self.interception.mitmproxy.cert_dir, str) and self.interception.mitmproxy.cert_dir.startswith("~"):
            self.interception.mitmproxy.cert_dir = str(Path(self.interception.mitmproxy.cert_dir).expanduser())
        if isinstance(self.interception.forward_proxy.ca_cert_dir, str) and self.interception.forward_proxy.ca_cert_dir.startswith("~"):
            self.interception.forward_proxy.ca_cert_dir = str(Path(self.interception.forward_proxy.ca_cert_dir).expanduser())
        if isinstance(self.interception.passthrough.storage_file, str) and self.interception.passthrough.storage_file.startswith("~"):
            self.interception.passthrough.storage_file = str(Path(self.interception.passthrough.storage_file).expanduser())
        # Pipeline stage configs
        for stage_cfg in self.pipeline.stages:
            for key, val in list(stage_cfg.config.items()):
                if isinstance(val, str) and val.startswith("~"):
                    stage_cfg.config[key] = str(Path(val).expanduser())
        return self
