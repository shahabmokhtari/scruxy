"""Plugin-based PII detection stage with dynamic loading and timeout enforcement."""
from __future__ import annotations

import importlib.util
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path
from typing import Any

from scruxy.plugin.base import DetectorPlugin, PiiEntity
from scruxy.plugin.storage import PluginStorage


logger = logging.getLogger(__name__)


class PluginStage:
    """PII detection stage that dynamically loads and runs detector plugins.

    Plugins are Python files placed in a designated directory. Each file must
    contain a class that inherits from ``DetectorPlugin``. Plugins are executed
    with a per-plugin timeout to protect the overall latency budget.
    """

    def __init__(
        self,
        plugin_dir: str,
        timeout_ms: int = 50,
        disabled_plugins: list[str] | None = None,
        storage_base_dir: str | None = None,
        plugin_configs: dict[str, dict] | None = None,
    ) -> None:
        """Initialize the plugin stage.

        Args:
            plugin_dir: Path to directory containing plugin .py files.
            timeout_ms: Maximum time in milliseconds to allow each plugin's
                detect() call before cancellation.
            disabled_plugins: List of plugin names to disable. Disabled plugins
                are skipped during loading and detection.
            storage_base_dir: Base directory for per-plugin key-value storage.
                If None, plugin storage is not available.
            plugin_configs: Per-plugin configuration overrides.  Keys are
                plugin names, values are config dicts that are merged into
                the base config passed to ``setup()``.
        """
        self._plugin_dir = Path(plugin_dir).expanduser()
        self._timeout_s = timeout_ms / 1000.0
        self._plugins: list[DetectorPlugin] = []
        self._disabled_plugins: set[str] = set(disabled_plugins or [])
        self._storage_base_dir = storage_base_dir
        self._plugin_configs: dict[str, dict] = plugin_configs or {}
        self._storages: dict[str, PluginStorage] = {}
        # Use daemon threads so hanging plugins don't prevent shutdown.
        # Note: Python threads cannot be forcibly killed; future.cancel()
        # only prevents execution if the task hasn't started yet.  Plugins
        # must be cooperative (respect timeouts / avoid infinite loops).
        self._executor = ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix="scruxy-plugin",
        )
        # Per-plugin consecutive-timeout counter.  After N consecutive
        # timeouts the plugin is auto-disabled until the process restarts
        # — a permanently broken plugin cannot keep starving the worker
        # pool one timeout at a time.
        # R53-7 fix: protect compound read-modify-write of the streak
        # counter from concurrent ``asyncio.to_thread`` workers; the
        # CPython GIL makes individual dict ops atomic but does not
        # protect ``get(name,0)+1`` followed by ``[name]=streak``.
        self._plugin_timeout_streak: dict[str, int] = {}
        self._plugin_auto_disabled: set[str] = set()
        self._plugin_timeout_threshold = 5
        self._plugin_timeout_lock = threading.Lock()

    def load_plugins(self) -> None:
        """Scan the plugin directory for .py files and load detector plugins.

        Each .py file is dynamically imported. The first class found that
        inherits from DetectorPlugin is instantiated and its setup() method
        is called. Disabled plugins are still loaded (for UI visibility)
        but marked as ``enabled = False``.
        """
        if not self._plugin_dir.is_dir():
            logger.warning("Plugin directory does not exist: %s", self._plugin_dir)
            return

        for py_file in sorted(self._plugin_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue

            try:
                plugin_cls = self._import_plugin_class(py_file)
                if plugin_cls is None:
                    logger.debug("No DetectorPlugin subclass found in %s", py_file.name)
                    continue

                instance = plugin_cls()

                if instance.name in self._disabled_plugins:
                    instance.enabled = False
                    instance.setup({})
                    self._plugins.append(instance)
                    logger.info(
                        "Loaded disabled plugin: %s from %s",
                        instance.name,
                        py_file.name,
                    )
                    continue

                config: dict[str, Any] = {}
                if self._storage_base_dir:
                    storage = PluginStorage(self._storage_base_dir, instance.name)
                    self._storages[instance.name] = storage
                    config["_storage"] = storage
                # Merge per-plugin config overrides (if any).
                config.update(self._plugin_configs.get(instance.name, {}))
                instance.setup(config)
                self._plugins.append(instance)
                logger.info(
                    "Loaded plugin: %s v%s from %s",
                    instance.name,
                    instance.version,
                    py_file.name,
                )
            except Exception:
                logger.exception("Failed to load plugin from %s", py_file.name)

    def _import_plugin_class(self, py_file: Path) -> type[DetectorPlugin] | None:
        """Dynamically import a .py file and find the first DetectorPlugin subclass.

        Because plugins may define their own DetectorPlugin ABC (until the shared
        base module exists), we match by checking for the required interface:
        a class with ``setup`` and ``detect`` methods plus ``name`` and ``version``
        attributes, whose MRO includes a class named ``DetectorPlugin``.

        Args:
            py_file: Path to the Python file to import.

        Returns:
            The plugin class, or None if no suitable class was found.
        """
        module_name = f"scruxy_plugin_{py_file.stem}"
        spec = importlib.util.spec_from_file_location(module_name, py_file)
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if not isinstance(attr, type):
                continue

            # Check by exact type if the plugin inherits from our ABC
            if issubclass(attr, DetectorPlugin) and attr is not DetectorPlugin:
                return attr

            # Duck-type check: the plugin may define its own DetectorPlugin ABC.
            # Look for concrete classes whose MRO includes a class named
            # "DetectorPlugin" and that have the required interface methods.
            base_names = [base.__name__ for base in attr.__mro__]
            if (
                "DetectorPlugin" in base_names
                and attr.__name__ != "DetectorPlugin"
                and hasattr(attr, "setup")
                and hasattr(attr, "detect")
                and hasattr(attr, "name")
                and hasattr(attr, "version")
            ):
                return attr  # type: ignore[return-value]

        return None

    def enable_plugin(self, name: str) -> None:
        """Enable a previously disabled plugin by name.

        Args:
            name: The plugin name to enable.
        """
        self._disabled_plugins.discard(name)
        logger.info("Enabled plugin: %s", name)

    def disable_plugin(self, name: str) -> None:
        """Disable a plugin by name so it is skipped during detection.

        Args:
            name: The plugin name to disable.
        """
        self._disabled_plugins.add(name)
        logger.info("Disabled plugin: %s", name)

    def detect(self, text: str, language: str = "en") -> list[PiiEntity]:
        """Run all loaded plugins to detect PII entities, with per-plugin timeout.

        Each plugin runs in a thread pool with the configured timeout. Plugins
        that raise exceptions or exceed the timeout are logged and skipped.
        Disabled plugins are skipped entirely.

        Args:
            text: The input text to analyze.
            language: Language code (e.g. "en").

        Returns:
            A combined list of PiiEntity instances from all successful plugins.
        """
        if not self._plugins:
            return []

        if not text:
            return []

        entities: list[PiiEntity] = []

        for plugin in self._plugins:
            plugin_name = getattr(plugin, "name", plugin.__class__.__name__)

            if plugin_name in self._disabled_plugins:
                logger.debug("Skipping disabled plugin during detect: %s", plugin_name)
                continue
            if plugin_name in self._plugin_auto_disabled:
                logger.debug(
                    "Skipping auto-disabled plugin (too many timeouts): %s", plugin_name,
                )
                continue
            source = f"plugin:{plugin_name}"

            try:
                future = self._executor.submit(plugin.detect, text, language)
                try:
                    plugin_results = future.result(timeout=self._timeout_s)
                except FuturesTimeoutError:
                    with self._plugin_timeout_lock:
                        streak = self._plugin_timeout_streak.get(plugin_name, 0) + 1
                        self._plugin_timeout_streak[plugin_name] = streak
                        threshold_hit = streak >= self._plugin_timeout_threshold
                        if threshold_hit:
                            self._plugin_auto_disabled.add(plugin_name)
                    logger.warning(
                        "Plugin %s timed out after %.0f ms (streak=%d/%d) — rebuilding executor",
                        plugin_name,
                        self._timeout_s * 1000,
                        streak,
                        self._plugin_timeout_threshold,
                    )
                    if threshold_hit:
                        logger.error(
                            "Plugin %s auto-disabled after %d consecutive timeouts; "
                            "fix the plugin or restart Scruxy to retry.",
                            plugin_name, streak,
                        )
                    future.cancel()
                    # Rebuild executor to reclaim stuck worker threads
                    old_executor = self._executor
                    self._executor = ThreadPoolExecutor(
                        max_workers=4,
                        thread_name_prefix="scruxy-plugin",
                    )
                    try:
                        old_executor.shutdown(wait=False, cancel_futures=True)
                    except TypeError:
                        old_executor.shutdown(wait=False)
                    continue
                else:
                    # Success: reset the streak so a transient hiccup
                    # doesn't permanently disable an otherwise-healthy plugin.
                    # R53-7 fix: same lock as the timeout branch protects
                    # the compound read/modify/write.
                    with self._plugin_timeout_lock:
                        self._plugin_timeout_streak.pop(plugin_name, None)

                for entity in plugin_results:
                    # Skip out-of-bounds entities from buggy plugins
                    if entity.start < 0 or entity.end > len(text):
                        logger.warning(
                            "Plugin %s returned out-of-bounds entity [%d:%d] for text of length %d",
                            plugin_name, entity.start, entity.end, len(text),
                        )
                        continue
                    # Skip entities that overlap pipeline placeholder markers
                    span = text[entity.start:entity.end]
                    if "§§§SCRX" in span:
                        continue
                    entity.source = source
                    entities.append(entity)

            except Exception:
                logger.exception("Plugin %s raised an exception", plugin_name)

        logger.debug(
            "Plugins detected %d entities in text of length %d", len(entities), len(text)
        )
        return entities

    @property
    def plugins(self) -> list[DetectorPlugin]:
        """Return the list of loaded plugins (read-only access)."""
        return list(self._plugins)

    def flush_all_storages(self) -> None:
        """Flush all plugin storages to disk."""
        for name, storage in self._storages.items():
            try:
                storage.flush()
            except Exception:
                logger.exception("Failed to flush storage for plugin %s", name)

    def teardown(self) -> None:
        """Call teardown() on all loaded plugins and shut down the executor."""
        self.flush_all_storages()
        for plugin in self._plugins:
            try:
                plugin.teardown()
            except Exception:
                logger.exception(
                    "Error tearing down plugin %s",
                    getattr(plugin, "name", plugin.__class__.__name__),
                )
        # Shut down the thread pool to release stuck workers
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            # Python < 3.9 doesn't support cancel_futures
            self._executor.shutdown(wait=False)
