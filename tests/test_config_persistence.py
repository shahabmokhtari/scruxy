"""Tests for config persistence: save/reload roundtrip, path collapsing, atomic write."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scruxy.config.loader import _collapse_paths, _expand_paths, load_config, save_config
from scruxy.config.models import AppConfig


# ---------------------------------------------------------------------------
# _collapse_paths tests
# ---------------------------------------------------------------------------

class TestCollapsePaths:
    """Verify that _collapse_paths correctly converts absolute home paths to ~/..."""

    def test_collapses_home_path(self) -> None:
        home = str(Path.home())
        data = {"storage_dir": home + "/sessions"}
        result = _collapse_paths(data)
        assert result["storage_dir"] == "~/sessions"

    def test_collapses_nested_home_path(self) -> None:
        home = str(Path.home())
        data = {"sessions": {"storage_dir": home + "/.scruxy/sessions"}}
        result = _collapse_paths(data)
        assert result["sessions"]["storage_dir"] == "~/.scruxy/sessions"

    def test_leaves_non_home_paths_unchanged(self) -> None:
        # Build an absolute path that is definitely *not* under the user's home.
        import sys

        if sys.platform == "win32":
            non_home_path = "C:\\SomeOtherRoot\\data"
        else:
            non_home_path = "/opt/some/other/path"

        data = {"dir": non_home_path}
        result = _collapse_paths(data)
        assert result["dir"] == non_home_path

    def test_leaves_relative_paths_unchanged(self) -> None:
        data = {"dir": "relative/path"}
        result = _collapse_paths(data)
        assert result["dir"] == "relative/path"

    def test_leaves_non_string_values_unchanged(self) -> None:
        data = {"port": 8080, "enabled": True}
        result = _collapse_paths(data)
        assert result["port"] == 8080
        assert result["enabled"] is True

    def test_handles_list_of_dicts(self) -> None:
        home = str(Path.home())
        data = {
            "stages": [
                {"config": {"plugin_dir": home + "/plugins"}},
                {"config": {"patterns_file": home + "/patterns.yaml"}},
            ],
        }
        result = _collapse_paths(data)
        assert result["stages"][0]["config"]["plugin_dir"] == "~/plugins"
        assert result["stages"][1]["config"]["patterns_file"] == "~/patterns.yaml"

    def test_handles_home_dir_exactly(self) -> None:
        """Edge case: the value *is* the home directory."""
        home = str(Path.home())
        data = {"dir": home}
        result = _collapse_paths(data)
        assert result["dir"] == "~"

    def test_roundtrip_expand_collapse(self) -> None:
        """_expand_paths and _collapse_paths are inverses for ~-prefixed paths."""
        original = {"sessions": {"storage_dir": "~/.scruxy/sessions"}}
        expanded = _expand_paths(original)
        collapsed = _collapse_paths(expanded)
        assert collapsed == original


# ---------------------------------------------------------------------------
# save_config / load_config roundtrip tests
# ---------------------------------------------------------------------------

class TestSaveConfig:
    """Verify save_config produces valid YAML that load_config can round-trip."""

    def test_save_and_reload_roundtrip(self, tmp_path: Path) -> None:
        config = AppConfig(
            interception={"listen_port": 9999, "mode": "primary"},
            sessions={"storage_dir": str(tmp_path / "sessions")},
            logging={"log_dir": str(tmp_path / "logs")},
            custom_providers_dir=str(tmp_path / "providers"),
        )
        config_path = tmp_path / "config.yaml"
        save_config(config, path=config_path)

        reloaded = load_config(config_path)
        assert reloaded.interception.listen_port == 9999
        assert reloaded.interception.mode == "primary"

    def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        config_path = tmp_path / "nested" / "dir" / "config.yaml"
        config = AppConfig()
        save_config(config, path=config_path)
        assert config_path.exists()

    def test_save_default_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """save_config uses ~/.scruxy/config.yaml when path is None."""
        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))

        from scruxy.config import loader
        monkeypatch.setattr(loader, "DEFAULT_CONFIG_DIR", fake_home / ".scruxy")

        config = AppConfig()
        save_config(config, path=None)
        assert (fake_home / ".scruxy" / "config.yaml").exists()

    def test_saved_file_is_valid_yaml(self, tmp_path: Path) -> None:
        config = AppConfig()
        config_path = tmp_path / "config.yaml"
        save_config(config, path=config_path)

        with open(config_path) as f:
            data = yaml.safe_load(f)
        assert isinstance(data, dict)
        assert "interception" in data

    def test_saved_file_uses_collapsed_paths(self, tmp_path: Path) -> None:
        """Absolute paths under home should be stored as ~/... in the YAML."""
        home = str(Path.home())
        config = AppConfig(
            sessions={"storage_dir": home + "/.scruxy/sessions"},
        )
        config_path = tmp_path / "config.yaml"
        save_config(config, path=config_path)

        with open(config_path) as f:
            data = yaml.safe_load(f)
        assert data["sessions"]["storage_dir"] == "~/.scruxy/sessions"

    def test_atomic_write_leaves_valid_file(self, tmp_path: Path) -> None:
        """Even if we overwrite, the file is always valid YAML."""
        config_path = tmp_path / "config.yaml"

        # Write initial config.
        config1 = AppConfig(interception={"listen_port": 1111})
        save_config(config1, path=config_path)

        # Overwrite with new config.
        config2 = AppConfig(interception={"listen_port": 2222})
        save_config(config2, path=config_path)

        reloaded = load_config(config_path)
        assert reloaded.interception.listen_port == 2222

    def test_roundtrip_preserves_all_fields(self, tmp_path: Path) -> None:
        """A full default AppConfig survives a save/load cycle."""
        config = AppConfig()
        config_path = tmp_path / "config.yaml"
        save_config(config, path=config_path)
        reloaded = load_config(config_path)

        # Compare key fields.
        assert reloaded.interception.mode == config.interception.mode
        assert reloaded.interception.listen_port == config.interception.listen_port
        assert reloaded.tokens.prefix == config.tokens.prefix
        assert len(reloaded.pipeline.stages) == len(config.pipeline.stages)
        assert reloaded.recording.enabled == config.recording.enabled
        assert reloaded.ui.enabled == config.ui.enabled


    def test_roundtrip_preserves_pipeline_stage_type(self, tmp_path: Path) -> None:
        config = AppConfig(pipeline={
            "stages": [
                {
                    "name": "regex_custom",
                    "stage_type": "regex",
                    "enabled": True,
                    "config": {"patterns_file": str(tmp_path / "regex.yaml")},
                }
            ]
        })
        config_path = tmp_path / "config.yaml"

        save_config(config, path=config_path)
        reloaded = load_config(config_path)

        assert reloaded.pipeline.stages[0].name == "regex_custom"
        assert reloaded.pipeline.stages[0].stage_type == "regex"
