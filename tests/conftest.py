"""Shared test fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the local src/ directory takes precedence over any editable install
# from the parent repo (important when running tests in a git worktree).
_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import pytest
import yaml


@pytest.fixture
def tmp_config_dir(tmp_path: Path) -> Path:
    """Create a temporary config directory with default structure."""
    config_dir = tmp_path / ".scruxy"
    config_dir.mkdir()
    (config_dir / "sessions").mkdir()
    (config_dir / "plugins").mkdir()
    (config_dir / "providers").mkdir()
    (config_dir / "logs").mkdir()
    return config_dir


@pytest.fixture
def sample_config(tmp_config_dir: Path) -> Path:
    """Write a sample config.yaml and return its path."""
    config = {
        "interception": {
            "mode": "primary",
            "listen_host": "127.0.0.1",
            "listen_port": 9090,
        },
        "providers": {
            "anthropic": {
                "enabled": True,
                "upstream_url": "https://api.anthropic.com",
            },
        },
        "tokens": {
            "prefix": "REDACTED",
            "format": "{prefix}_{category}_{n}",
            "max_token_length": 40,
        },
        "sessions": {
            "storage_dir": str(tmp_config_dir / "sessions"),
            "max_session_age_hours": 24,
            "flush_interval_seconds": 10,
        },
        "logging": {
            "level": "debug",
            "log_dir": str(tmp_config_dir / "logs"),
        },
        "stats": {
            "storage_file": str(tmp_config_dir / "stats.json"),
        },
    }
    config_path = tmp_config_dir / "config.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f)
    return config_path
