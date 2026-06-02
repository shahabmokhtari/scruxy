"""Tests for configuration loading and validation."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scruxy.config.loader import ensure_directories, load_config
from scruxy.config.models import AppConfig


class TestAppConfigDefaults:
    """Test default configuration values."""

    def test_default_config_creates_valid_model(self):
        config = AppConfig()
        assert config.interception.mode == "primary"
        assert config.interception.listen_port == 8080

    def test_default_providers(self):
        config = AppConfig()
        assert "anthropic" in config.providers
        assert "openai" in config.providers
        assert config.providers["anthropic"].enabled is True
        assert "azure_openai" not in config.providers

    def test_default_token_format(self):
        config = AppConfig()
        assert config.tokens.prefix == "REDACTED"
        assert config.tokens.max_token_length == 40
        assert config.tokens.persistent is True

    def test_default_pipeline_stages(self):
        config = AppConfig()
        assert len(config.pipeline.stages) == 6
        names = [s.name for s in config.pipeline.stages]
        assert names == [
            "whitelist", "presidio", "regex", "file_path",
            "plugins", "openai_privacy_filter",
        ]

    def test_default_session_config(self):
        config = AppConfig()
        assert config.sessions.max_session_age_hours == 168
        assert config.sessions.flush_interval_seconds == 5


class TestLoadConfig:
    """Test YAML config loading."""

    def test_load_from_file(self, sample_config: Path):
        config = load_config(sample_config)
        assert config.interception.listen_port == 9090
        assert config.sessions.max_session_age_hours == 24
        assert config.logging.level == "debug"

    def test_load_missing_file_returns_defaults(self, tmp_path: Path):
        config = load_config(tmp_path / "nonexistent.yaml")
        assert config.interception.listen_port == 8080
        assert config.interception.mode == "primary"

    def test_load_empty_file_returns_defaults(self, tmp_path: Path):
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("")
        config = load_config(empty_file)
        assert config.interception.listen_port == 8080

    def test_partial_config_merges_with_defaults(self, tmp_path: Path):
        partial = {"interception": {"listen_port": 7070}}
        config_path = tmp_path / "partial.yaml"
        with open(config_path, "w") as f:
            yaml.dump(partial, f)
        config = load_config(config_path)
        assert config.interception.listen_port == 7070
        assert config.interception.mode == "primary"  # default kept

    def test_path_expansion(self, tmp_path: Path):
        raw = {"sessions": {"storage_dir": "~/my-sessions"}}
        config_path = tmp_path / "paths.yaml"
        with open(config_path, "w") as f:
            yaml.dump(raw, f)
        config = load_config(config_path)
        assert "~" not in config.sessions.storage_dir
        assert Path.home().name in config.sessions.storage_dir


class TestEnsureDirectories:
    """Test directory creation."""

    def test_creates_session_dir(self, tmp_path: Path):
        config = AppConfig(
            sessions={"storage_dir": str(tmp_path / "sessions")},
            logging={"log_dir": str(tmp_path / "logs")},
            custom_providers_dir=str(tmp_path / "providers"),
            pipeline={"stages": []},
        )
        ensure_directories(config)
        assert (tmp_path / "sessions").is_dir()
        assert (tmp_path / "logs").is_dir()
        assert (tmp_path / "providers").is_dir()

    def test_creates_plugin_dir_from_stage_config(self, tmp_path: Path):
        config = AppConfig(
            sessions={"storage_dir": str(tmp_path / "sessions")},
            logging={"log_dir": str(tmp_path / "logs")},
            custom_providers_dir=str(tmp_path / "providers"),
            pipeline={
                "stages": [
                    {
                        "name": "plugins",
                        "enabled": True,
                        "config": {"plugin_dir": str(tmp_path / "my_plugins")},
                    }
                ]
            },
        )
        ensure_directories(config)
        assert (tmp_path / "my_plugins").is_dir()

    def test_idempotent(self, tmp_path: Path):
        config = AppConfig(
            sessions={"storage_dir": str(tmp_path / "sessions")},
            logging={"log_dir": str(tmp_path / "logs")},
            custom_providers_dir=str(tmp_path / "providers"),
            pipeline={"stages": []},
        )
        ensure_directories(config)
        ensure_directories(config)  # no error on second call
        assert (tmp_path / "sessions").is_dir()
