"""Tests for the plugin-based PII detection stage."""
from __future__ import annotations

import textwrap
import time
from pathlib import Path

import pytest

from scruxy.pipeline.plugin_stage import DetectorPlugin, PiiEntity, PluginStage


def _write_plugin(plugin_dir: Path, filename: str, content: str) -> Path:
    """Write a plugin .py file to the given directory."""
    path = plugin_dir / filename
    path.write_text(textwrap.dedent(content))
    return path


class TestPluginStageInit:
    """Test PluginStage initialization."""

    def test_init_sets_plugin_dir(self, tmp_path: Path):
        stage = PluginStage(plugin_dir=str(tmp_path))
        assert stage._plugin_dir == tmp_path

    def test_init_default_timeout(self, tmp_path: Path):
        stage = PluginStage(plugin_dir=str(tmp_path))
        assert stage._timeout_s == pytest.approx(0.05)

    def test_init_custom_timeout(self, tmp_path: Path):
        stage = PluginStage(plugin_dir=str(tmp_path), timeout_ms=100)
        assert stage._timeout_s == pytest.approx(0.1)

    def test_init_no_plugins_loaded(self, tmp_path: Path):
        stage = PluginStage(plugin_dir=str(tmp_path))
        assert stage.plugins == []


class TestPluginLoading:
    """Test plugin discovery and loading."""

    def test_load_valid_plugin(self, tmp_path: Path):
        """A valid plugin file is loaded and setup() is called."""
        _write_plugin(tmp_path, "my_plugin.py", """\
            from abc import ABC, abstractmethod
            from dataclasses import dataclass

            @dataclass
            class PiiEntity:
                entity_type: str
                start: int
                end: int
                score: float
                source: str

            class DetectorPlugin(ABC):
                name: str
                version: str
                @abstractmethod
                def setup(self, config: dict) -> None: ...
                @abstractmethod
                def detect(self, text: str, language: str) -> list[PiiEntity]: ...
                def teardown(self) -> None: pass

            class MyPlugin(DetectorPlugin):
                name = "my_plugin"
                version = "1.0.0"
                def setup(self, config: dict) -> None:
                    self.ready = True
                def detect(self, text: str, language: str) -> list[PiiEntity]:
                    return []
        """)

        stage = PluginStage(plugin_dir=str(tmp_path))
        stage.load_plugins()
        assert len(stage.plugins) == 1
        assert stage.plugins[0].name == "my_plugin"

    def test_load_skips_files_starting_with_underscore(self, tmp_path: Path):
        """Plugin files starting with _ are skipped."""
        _write_plugin(tmp_path, "_helper.py", """\
            class NotAPlugin:
                pass
        """)

        stage = PluginStage(plugin_dir=str(tmp_path))
        stage.load_plugins()
        assert len(stage.plugins) == 0

    def test_load_skips_file_without_plugin_class(self, tmp_path: Path):
        """Files without a DetectorPlugin subclass are silently skipped."""
        _write_plugin(tmp_path, "no_plugin.py", """\
            class SomeOtherClass:
                pass
        """)

        stage = PluginStage(plugin_dir=str(tmp_path))
        stage.load_plugins()
        assert len(stage.plugins) == 0

    def test_load_handles_missing_directory(self, tmp_path: Path):
        """Missing plugin directory is handled gracefully."""
        stage = PluginStage(plugin_dir=str(tmp_path / "nonexistent"))
        stage.load_plugins()  # should not raise
        assert len(stage.plugins) == 0

    def test_load_handles_syntax_error(self, tmp_path: Path):
        """Plugin files with syntax errors are skipped without crashing."""
        _write_plugin(tmp_path, "broken.py", """\
            def this_is_broken(
                # missing closing paren and colon
        """)

        stage = PluginStage(plugin_dir=str(tmp_path))
        stage.load_plugins()  # should not raise
        assert len(stage.plugins) == 0

    def test_load_handles_setup_exception(self, tmp_path: Path):
        """Plugins that fail during setup() are skipped."""
        _write_plugin(tmp_path, "bad_setup.py", """\
            from abc import ABC, abstractmethod
            from dataclasses import dataclass

            @dataclass
            class PiiEntity:
                entity_type: str
                start: int
                end: int
                score: float
                source: str

            class DetectorPlugin(ABC):
                name: str
                version: str
                @abstractmethod
                def setup(self, config: dict) -> None: ...
                @abstractmethod
                def detect(self, text: str, language: str) -> list[PiiEntity]: ...
                def teardown(self) -> None: pass

            class BadSetupPlugin(DetectorPlugin):
                name = "bad_setup"
                version = "0.1"
                def setup(self, config: dict) -> None:
                    raise RuntimeError("Setup failed!")
                def detect(self, text: str, language: str) -> list[PiiEntity]:
                    return []
        """)

        stage = PluginStage(plugin_dir=str(tmp_path))
        stage.load_plugins()
        assert len(stage.plugins) == 0

    def test_load_multiple_plugins_sorted_by_filename(self, tmp_path: Path):
        """Multiple valid plugins are loaded in sorted filename order."""
        for name in ["b_plugin.py", "a_plugin.py"]:
            _write_plugin(tmp_path, name, f"""\
                from abc import ABC, abstractmethod
                from dataclasses import dataclass

                @dataclass
                class PiiEntity:
                    entity_type: str
                    start: int
                    end: int
                    score: float
                    source: str

                class DetectorPlugin(ABC):
                    name: str
                    version: str
                    @abstractmethod
                    def setup(self, config: dict) -> None: ...
                    @abstractmethod
                    def detect(self, text: str, language: str) -> list[PiiEntity]: ...
                    def teardown(self) -> None: pass

                class Plugin(DetectorPlugin):
                    name = "{name.removesuffix('.py')}"
                    version = "1.0"
                    def setup(self, config: dict) -> None: pass
                    def detect(self, text: str, language: str) -> list[PiiEntity]:
                        return []
            """)

        stage = PluginStage(plugin_dir=str(tmp_path))
        stage.load_plugins()
        assert len(stage.plugins) == 2
        assert stage.plugins[0].name == "a_plugin"
        assert stage.plugins[1].name == "b_plugin"


class TestPluginDisableEnable:
    """Test per-plugin enable/disable support."""

    PLUGIN_TEMPLATE = """\
        from abc import ABC, abstractmethod
        from dataclasses import dataclass

        @dataclass
        class PiiEntity:
            entity_type: str
            start: int
            end: int
            score: float
            source: str

        class DetectorPlugin(ABC):
            name: str
            version: str
            @abstractmethod
            def setup(self, config: dict) -> None: ...
            @abstractmethod
            def detect(self, text: str, language: str) -> list[PiiEntity]: ...
            def teardown(self) -> None: pass

        class {cls_name}(DetectorPlugin):
            name = "{plugin_name}"
            version = "1.0"
            def setup(self, config: dict) -> None: pass
            def detect(self, text: str, language: str) -> list[PiiEntity]:
                return [PiiEntity(
                    entity_type="PERSON",
                    start=0,
                    end=4,
                    score=0.8,
                    source="",
                )]
    """

    def _create_plugin(self, tmp_path: Path, filename: str, cls_name: str, plugin_name: str) -> None:
        content = self.PLUGIN_TEMPLATE.format(cls_name=cls_name, plugin_name=plugin_name)
        _write_plugin(tmp_path, filename, content)

    def test_disabled_plugin_not_loaded(self, tmp_path: Path):
        """Plugins listed in disabled_plugins are loaded but marked as disabled."""
        self._create_plugin(tmp_path, "alpha.py", "AlphaPlugin", "alpha")
        self._create_plugin(tmp_path, "beta.py", "BetaPlugin", "beta")

        stage = PluginStage(
            plugin_dir=str(tmp_path),
            disabled_plugins=["alpha"],
        )
        stage.load_plugins()

        assert len(stage.plugins) == 2
        alpha = [p for p in stage.plugins if p.name == "alpha"][0]
        beta = [p for p in stage.plugins if p.name == "beta"][0]
        assert getattr(alpha, "enabled", True) is False
        assert getattr(beta, "enabled", True) is True

    def test_all_plugins_disabled_at_load(self, tmp_path: Path):
        """When all plugins are disabled, they are still loaded but marked disabled."""
        self._create_plugin(tmp_path, "alpha.py", "AlphaPlugin", "alpha")
        self._create_plugin(tmp_path, "beta.py", "BetaPlugin", "beta")

        stage = PluginStage(
            plugin_dir=str(tmp_path),
            disabled_plugins=["alpha", "beta"],
        )
        stage.load_plugins()

        assert len(stage.plugins) == 2
        assert all(not getattr(p, "enabled", True) for p in stage.plugins)

    def test_disable_plugin_at_runtime(self, tmp_path: Path):
        """disable_plugin() causes a loaded plugin to be skipped during detect()."""
        self._create_plugin(tmp_path, "alpha.py", "AlphaPlugin", "alpha")
        self._create_plugin(tmp_path, "beta.py", "BetaPlugin", "beta")

        stage = PluginStage(plugin_dir=str(tmp_path), timeout_ms=5000)
        stage.load_plugins()
        assert len(stage.plugins) == 2

        # Both plugins should detect entities before disabling
        results_before = stage.detect("test")
        assert len(results_before) == 2

        stage.disable_plugin("alpha")

        results_after = stage.detect("test")
        assert len(results_after) == 1
        assert results_after[0].source == "plugin:beta"

    def test_enable_plugin_at_runtime(self, tmp_path: Path):
        """enable_plugin() re-enables a disabled plugin for detect()."""
        self._create_plugin(tmp_path, "alpha.py", "AlphaPlugin", "alpha")

        stage = PluginStage(
            plugin_dir=str(tmp_path),
            timeout_ms=5000,
            disabled_plugins=["alpha"],
        )
        stage.load_plugins()
        # alpha was disabled at load time — loaded but marked disabled
        assert len(stage.plugins) == 1
        assert getattr(stage.plugins[0], "enabled", True) is False

        # detect() should skip disabled plugins
        results_disabled = stage.detect("test")
        assert results_disabled == []

        # Enabling it now makes it participate in detection
        stage.enable_plugin("alpha")
        results = stage.detect("test")
        assert len(results) == 1

    def test_enable_restores_runtime_disabled_plugin(self, tmp_path: Path):
        """enable_plugin() restores a plugin that was disabled at runtime."""
        self._create_plugin(tmp_path, "alpha.py", "AlphaPlugin", "alpha")

        stage = PluginStage(plugin_dir=str(tmp_path), timeout_ms=5000)
        stage.load_plugins()
        assert len(stage.plugins) == 1

        # Disable at runtime
        stage.disable_plugin("alpha")
        results_disabled = stage.detect("test")
        assert results_disabled == []

        # Re-enable at runtime
        stage.enable_plugin("alpha")
        results_enabled = stage.detect("test")
        assert len(results_enabled) == 1
        assert results_enabled[0].source == "plugin:alpha"

    def test_disabled_plugins_skipped_during_detect(self, tmp_path: Path):
        """Plugins disabled at runtime are skipped during detect(), not removed from the list."""
        self._create_plugin(tmp_path, "alpha.py", "AlphaPlugin", "alpha")

        stage = PluginStage(plugin_dir=str(tmp_path), timeout_ms=5000)
        stage.load_plugins()
        assert len(stage.plugins) == 1

        stage.disable_plugin("alpha")

        # Plugin is still in the plugins list, just skipped during detect
        assert len(stage.plugins) == 1
        results = stage.detect("test")
        assert results == []

    def test_disabled_plugins_default_empty(self, tmp_path: Path):
        """By default, no plugins are disabled."""
        stage = PluginStage(plugin_dir=str(tmp_path))
        assert stage._disabled_plugins == set()

    def test_disabled_plugins_none_treated_as_empty(self, tmp_path: Path):
        """Passing None for disabled_plugins is treated as empty."""
        stage = PluginStage(plugin_dir=str(tmp_path), disabled_plugins=None)
        assert stage._disabled_plugins == set()


class TestPluginDetection:
    """Test PluginStage.detect() method."""

    def test_detect_returns_entities_from_plugin(self, tmp_path: Path):
        """Entities detected by a plugin are returned with source='plugin:{name}'."""
        _write_plugin(tmp_path, "email_plugin.py", """\
            import re
            from abc import ABC, abstractmethod
            from dataclasses import dataclass

            @dataclass
            class PiiEntity:
                entity_type: str
                start: int
                end: int
                score: float
                source: str

            class DetectorPlugin(ABC):
                name: str
                version: str
                @abstractmethod
                def setup(self, config: dict) -> None: ...
                @abstractmethod
                def detect(self, text: str, language: str) -> list[PiiEntity]: ...
                def teardown(self) -> None: pass

            class EmailPlugin(DetectorPlugin):
                name = "email_detector"
                version = "1.0"
                def setup(self, config: dict) -> None: pass
                def detect(self, text: str, language: str) -> list[PiiEntity]:
                    results = []
                    for m in re.finditer(r'[\\w.+-]+@[\\w-]+\\.[\\w.-]+', text):
                        results.append(PiiEntity(
                            entity_type="EMAIL_ADDRESS",
                            start=m.start(),
                            end=m.end(),
                            score=0.9,
                            source="",
                        ))
                    return results
        """)

        stage = PluginStage(plugin_dir=str(tmp_path), timeout_ms=5000)
        stage.load_plugins()

        results = stage.detect("Contact user@example.com for info.")
        assert len(results) == 1
        assert results[0].entity_type == "EMAIL_ADDRESS"
        assert results[0].source == "plugin:email_detector"
        assert results[0].score == 0.9

    def test_detect_empty_text(self, tmp_path: Path):
        """detect() returns empty list for empty text."""
        _write_plugin(tmp_path, "noop.py", """\
            from abc import ABC, abstractmethod
            from dataclasses import dataclass

            @dataclass
            class PiiEntity:
                entity_type: str
                start: int
                end: int
                score: float
                source: str

            class DetectorPlugin(ABC):
                name: str
                version: str
                @abstractmethod
                def setup(self, config: dict) -> None: ...
                @abstractmethod
                def detect(self, text: str, language: str) -> list[PiiEntity]: ...
                def teardown(self) -> None: pass

            class NoopPlugin(DetectorPlugin):
                name = "noop"
                version = "1.0"
                def setup(self, config: dict) -> None: pass
                def detect(self, text: str, language: str) -> list[PiiEntity]:
                    return []
        """)

        stage = PluginStage(plugin_dir=str(tmp_path))
        stage.load_plugins()
        results = stage.detect("")
        assert results == []

    def test_detect_no_plugins_loaded(self, tmp_path: Path):
        """detect() returns empty list when no plugins are loaded."""
        stage = PluginStage(plugin_dir=str(tmp_path))
        results = stage.detect("Some text with user@example.com")
        assert results == []

    def test_detect_exception_in_plugin_is_caught(self, tmp_path: Path):
        """Plugins that raise exceptions are caught and skipped."""
        _write_plugin(tmp_path, "crashing.py", """\
            from abc import ABC, abstractmethod
            from dataclasses import dataclass

            @dataclass
            class PiiEntity:
                entity_type: str
                start: int
                end: int
                score: float
                source: str

            class DetectorPlugin(ABC):
                name: str
                version: str
                @abstractmethod
                def setup(self, config: dict) -> None: ...
                @abstractmethod
                def detect(self, text: str, language: str) -> list[PiiEntity]: ...
                def teardown(self) -> None: pass

            class CrashingPlugin(DetectorPlugin):
                name = "crasher"
                version = "1.0"
                def setup(self, config: dict) -> None: pass
                def detect(self, text: str, language: str) -> list[PiiEntity]:
                    raise ValueError("Plugin crashed!")
        """)

        stage = PluginStage(plugin_dir=str(tmp_path), timeout_ms=5000)
        stage.load_plugins()
        assert len(stage.plugins) == 1

        # Should not raise, just skip the crashing plugin
        results = stage.detect("test text")
        assert results == []

    def test_detect_timeout_is_enforced(self, tmp_path: Path):
        """Plugins that exceed the timeout are skipped."""
        _write_plugin(tmp_path, "slow_plugin.py", """\
            import time
            from abc import ABC, abstractmethod
            from dataclasses import dataclass

            @dataclass
            class PiiEntity:
                entity_type: str
                start: int
                end: int
                score: float
                source: str

            class DetectorPlugin(ABC):
                name: str
                version: str
                @abstractmethod
                def setup(self, config: dict) -> None: ...
                @abstractmethod
                def detect(self, text: str, language: str) -> list[PiiEntity]: ...
                def teardown(self) -> None: pass

            class SlowPlugin(DetectorPlugin):
                name = "slow"
                version = "1.0"
                def setup(self, config: dict) -> None: pass
                def detect(self, text: str, language: str) -> list[PiiEntity]:
                    time.sleep(5)  # way longer than timeout
                    return [PiiEntity(
                        entity_type="PERSON",
                        start=0,
                        end=4,
                        score=0.9,
                        source="",
                    )]
        """)

        # Use a very short timeout (10ms) so the test runs fast
        stage = PluginStage(plugin_dir=str(tmp_path), timeout_ms=10)
        stage.load_plugins()
        assert len(stage.plugins) == 1

        start = time.monotonic()
        results = stage.detect("test")
        elapsed = time.monotonic() - start

        assert results == []
        # Should finish quickly, not wait for the 5-second sleep
        assert elapsed < 2.0

    def test_detect_combines_results_from_multiple_plugins(self, tmp_path: Path):
        """Results from multiple plugins are combined in the output."""
        _write_plugin(tmp_path, "plugin_a.py", """\
            from abc import ABC, abstractmethod
            from dataclasses import dataclass

            @dataclass
            class PiiEntity:
                entity_type: str
                start: int
                end: int
                score: float
                source: str

            class DetectorPlugin(ABC):
                name: str
                version: str
                @abstractmethod
                def setup(self, config: dict) -> None: ...
                @abstractmethod
                def detect(self, text: str, language: str) -> list[PiiEntity]: ...
                def teardown(self) -> None: pass

            class PluginA(DetectorPlugin):
                name = "plugin_a"
                version = "1.0"
                def setup(self, config: dict) -> None: pass
                def detect(self, text: str, language: str) -> list[PiiEntity]:
                    return [PiiEntity(
                        entity_type="PERSON",
                        start=0,
                        end=4,
                        score=0.8,
                        source="",
                    )]
        """)

        _write_plugin(tmp_path, "plugin_b.py", """\
            from abc import ABC, abstractmethod
            from dataclasses import dataclass

            @dataclass
            class PiiEntity:
                entity_type: str
                start: int
                end: int
                score: float
                source: str

            class DetectorPlugin(ABC):
                name: str
                version: str
                @abstractmethod
                def setup(self, config: dict) -> None: ...
                @abstractmethod
                def detect(self, text: str, language: str) -> list[PiiEntity]: ...
                def teardown(self) -> None: pass

            class PluginB(DetectorPlugin):
                name = "plugin_b"
                version = "1.0"
                def setup(self, config: dict) -> None: pass
                def detect(self, text: str, language: str) -> list[PiiEntity]:
                    return [PiiEntity(
                        entity_type="EMAIL_ADDRESS",
                        start=5,
                        end=21,
                        score=0.9,
                        source="",
                    )]
        """)

        stage = PluginStage(plugin_dir=str(tmp_path), timeout_ms=5000)
        stage.load_plugins()
        assert len(stage.plugins) == 2

        results = stage.detect("test user@example.com")
        assert len(results) == 2

        sources = {e.source for e in results}
        assert "plugin:plugin_a" in sources
        assert "plugin:plugin_b" in sources


class TestPluginTeardown:
    """Test PluginStage.teardown() method."""

    def test_teardown_calls_plugin_teardown(self, tmp_path: Path):
        """teardown() calls teardown on all loaded plugins."""
        _write_plugin(tmp_path, "teardown_plugin.py", """\
            from abc import ABC, abstractmethod
            from dataclasses import dataclass

            @dataclass
            class PiiEntity:
                entity_type: str
                start: int
                end: int
                score: float
                source: str

            class DetectorPlugin(ABC):
                name: str
                version: str
                @abstractmethod
                def setup(self, config: dict) -> None: ...
                @abstractmethod
                def detect(self, text: str, language: str) -> list[PiiEntity]: ...
                def teardown(self) -> None: pass

            class TeardownPlugin(DetectorPlugin):
                name = "teardown_test"
                version = "1.0"
                torn_down = False
                def setup(self, config: dict) -> None: pass
                def detect(self, text: str, language: str) -> list[PiiEntity]:
                    return []
                def teardown(self) -> None:
                    TeardownPlugin.torn_down = True
        """)

        stage = PluginStage(plugin_dir=str(tmp_path))
        stage.load_plugins()
        assert len(stage.plugins) == 1

        stage.teardown()
        # Verify the plugin's teardown was called
        assert stage.plugins[0].__class__.torn_down is True

    def test_teardown_handles_exception(self, tmp_path: Path):
        """teardown() handles exceptions from individual plugins gracefully."""
        _write_plugin(tmp_path, "bad_teardown.py", """\
            from abc import ABC, abstractmethod
            from dataclasses import dataclass

            @dataclass
            class PiiEntity:
                entity_type: str
                start: int
                end: int
                score: float
                source: str

            class DetectorPlugin(ABC):
                name: str
                version: str
                @abstractmethod
                def setup(self, config: dict) -> None: ...
                @abstractmethod
                def detect(self, text: str, language: str) -> list[PiiEntity]: ...
                def teardown(self) -> None: pass

            class BadTeardownPlugin(DetectorPlugin):
                name = "bad_teardown"
                version = "1.0"
                def setup(self, config: dict) -> None: pass
                def detect(self, text: str, language: str) -> list[PiiEntity]:
                    return []
                def teardown(self) -> None:
                    raise RuntimeError("Teardown failed!")
        """)

        stage = PluginStage(plugin_dir=str(tmp_path))
        stage.load_plugins()
        # Should not raise
        stage.teardown()


class TestDetectorPluginABC:
    """Test the DetectorPlugin abstract base class."""

    def test_cannot_instantiate_abc(self):
        """DetectorPlugin cannot be instantiated directly."""
        with pytest.raises(TypeError):
            DetectorPlugin()

    def test_concrete_plugin_must_implement_setup_and_detect(self):
        """A concrete subclass must implement setup() and detect()."""

        class IncompletePlugin(DetectorPlugin):
            name = "incomplete"
            version = "0.1"

        with pytest.raises(TypeError):
            IncompletePlugin()

    def test_concrete_plugin_with_all_methods(self):
        """A fully implemented concrete plugin can be instantiated."""

        class CompletePlugin(DetectorPlugin):
            name = "complete"
            version = "1.0"

            def setup(self, config: dict) -> None:
                pass

            def detect(self, text: str, language: str) -> list[PiiEntity]:
                return []

        plugin = CompletePlugin()
        assert plugin.name == "complete"
        assert plugin.version == "1.0"
        plugin.teardown()  # default implementation, should not raise


class TestPluginStagePluginsProperty:
    """Test the plugins read-only property."""

    def test_plugins_returns_copy(self, tmp_path: Path):
        """plugins property returns a copy, not a reference to the internal list."""
        stage = PluginStage(plugin_dir=str(tmp_path))
        plugins_list = stage.plugins
        assert plugins_list == []
        plugins_list.append(None)  # type: ignore[arg-type]
        # Internal list should remain unchanged
        assert stage.plugins == []


class TestPluginConfigs:
    """Test per-plugin configuration overrides via plugin_configs."""

    CONFIGURABLE_PLUGIN = """\
        from abc import ABC, abstractmethod
        from dataclasses import dataclass

        @dataclass
        class PiiEntity:
            entity_type: str
            start: int
            end: int
            score: float
            source: str

        class DetectorPlugin(ABC):
            name: str
            version: str
            @abstractmethod
            def setup(self, config: dict) -> None: ...
            @abstractmethod
            def detect(self, text: str, language: str) -> list[PiiEntity]: ...
            def teardown(self) -> None: pass

        class ConfigurablePlugin(DetectorPlugin):
            name = "configurable"
            version = "1.0"
            def setup(self, config: dict) -> None:
                self.threshold = config.get("threshold", 0.5)
                self.mode = config.get("mode", "default")
            def detect(self, text: str, language: str) -> list[PiiEntity]:
                return []
    """

    def test_plugin_configs_passed_to_setup(self, tmp_path: Path):
        """Per-plugin configs from plugin_configs are merged into setup() config."""
        _write_plugin(tmp_path, "configurable.py", self.CONFIGURABLE_PLUGIN)

        stage = PluginStage(
            plugin_dir=str(tmp_path),
            plugin_configs={"configurable": {"threshold": 0.8, "mode": "strict"}},
        )
        stage.load_plugins()

        assert len(stage.plugins) == 1
        plugin = stage.plugins[0]
        assert plugin.threshold == 0.8
        assert plugin.mode == "strict"

    def test_plugin_configs_override_defaults(self, tmp_path: Path):
        """Plugin configs override the plugin's own default values."""
        _write_plugin(tmp_path, "configurable.py", self.CONFIGURABLE_PLUGIN)

        # Without plugin_configs, defaults apply
        stage_default = PluginStage(plugin_dir=str(tmp_path))
        stage_default.load_plugins()
        assert stage_default.plugins[0].threshold == 0.5
        assert stage_default.plugins[0].mode == "default"

        # With plugin_configs, overrides apply
        stage_override = PluginStage(
            plugin_dir=str(tmp_path),
            plugin_configs={"configurable": {"threshold": 0.9}},
        )
        stage_override.load_plugins()
        assert stage_override.plugins[0].threshold == 0.9
        assert stage_override.plugins[0].mode == "default"  # not overridden

    def test_plugin_configs_none_treated_as_empty(self, tmp_path: Path):
        """Passing None for plugin_configs is treated as empty dict."""
        stage = PluginStage(plugin_dir=str(tmp_path), plugin_configs=None)
        assert stage._plugin_configs == {}

    def test_plugin_configs_for_unknown_plugin_ignored(self, tmp_path: Path):
        """Config for a plugin that doesn't exist is silently ignored."""
        _write_plugin(tmp_path, "configurable.py", self.CONFIGURABLE_PLUGIN)

        stage = PluginStage(
            plugin_dir=str(tmp_path),
            plugin_configs={"nonexistent": {"key": "value"}},
        )
        stage.load_plugins()
        assert len(stage.plugins) == 1
        # The configurable plugin should still use defaults
        assert stage.plugins[0].threshold == 0.5

    def test_plugin_configs_preserves_storage(self, tmp_path: Path):
        """plugin_configs merges on top of base config, so _storage is preserved."""
        _write_plugin(tmp_path, "configurable.py", self.CONFIGURABLE_PLUGIN)

        storage_dir = str(tmp_path / "storage")
        (tmp_path / "storage").mkdir()

        stage = PluginStage(
            plugin_dir=str(tmp_path),
            storage_base_dir=storage_dir,
            plugin_configs={"configurable": {"threshold": 0.7}},
        )
        stage.load_plugins()

        plugin = stage.plugins[0]
        assert plugin.threshold == 0.7
        # _storage should still be set from the storage_base_dir
        assert "configurable" in stage._storages
