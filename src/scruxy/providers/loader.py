"""Provider loader: scan directories for YAML and Python provider definitions."""
from __future__ import annotations

import importlib.util
import inspect
import logging
from pathlib import Path
from typing import Any

import yaml

from scruxy.providers.base import LLMProvider
from scruxy.providers.yaml_provider import YAMLProvider


logger = logging.getLogger(__name__)


def load_yaml_provider(yaml_path: Path) -> YAMLProvider | None:
    """Load a single YAML provider config file.

    Args:
        yaml_path: Path to the YAML provider config file.

    Returns:
        A YAMLProvider instance, or None if loading fails.
    """
    try:
        with open(yaml_path) as f:
            config = yaml.safe_load(f)

        if not isinstance(config, dict) or "name" not in config:
            logger.warning("Invalid provider YAML (missing 'name'): %s", yaml_path)
            return None

        provider = YAMLProvider(config)
        logger.info("Loaded YAML provider '%s' from %s", provider.name, yaml_path)
        return provider
    except Exception:
        logger.exception("Failed to load YAML provider from %s", yaml_path)
        return None


def load_python_provider(py_path: Path) -> LLMProvider | None:
    """Dynamically load a Python provider module and find an LLMProvider subclass.

    The module is expected to contain exactly one class that inherits from
    LLMProvider (directly or transitively). The class is instantiated with
    no arguments.

    Args:
        py_path: Path to the Python provider module.

    Returns:
        An LLMProvider instance, or None if loading fails.
    """
    try:
        spec = importlib.util.spec_from_file_location(
            f"custom_provider_{py_path.stem}", str(py_path)
        )
        if spec is None or spec.loader is None:
            logger.warning("Could not create module spec for %s", py_path)
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Find LLMProvider subclasses in the module
        provider_classes: list[type[LLMProvider]] = []
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, LLMProvider)
                and obj is not LLMProvider
                and obj.__module__ == module.__name__
            ):
                provider_classes.append(obj)

        if not provider_classes:
            logger.warning("No LLMProvider subclass found in %s", py_path)
            return None

        if len(provider_classes) > 1:
            logger.warning(
                "Multiple LLMProvider subclasses in %s, using first: %s",
                py_path,
                provider_classes[0].__name__,
            )

        provider = provider_classes[0]()
        logger.info("Loaded Python provider '%s' from %s", provider.name, py_path)
        return provider
    except Exception:
        logger.exception("Failed to load Python provider from %s", py_path)
        return None


def load_providers(directory: str | Path) -> list[LLMProvider]:
    """Scan a directory for YAML and Python provider definitions.

    YAML files (*.yaml, *.yml) are loaded as YAMLProvider instances.
    Python files (*.py) are dynamically imported, and LLMProvider subclasses
    found within are instantiated.

    Files are sorted alphabetically for deterministic ordering.

    Args:
        directory: Path to the directory to scan.

    Returns:
        List of successfully loaded LLMProvider instances.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        logger.warning("Provider directory does not exist: %s", dir_path)
        return []

    providers: list[LLMProvider] = []

    # Collect and sort all provider files
    files = sorted(dir_path.iterdir(), key=lambda p: p.name)

    for file_path in files:
        if file_path.suffix in (".yaml", ".yml"):
            provider = load_yaml_provider(file_path)
            if provider is not None:
                providers.append(provider)
        elif file_path.suffix == ".py" and not file_path.name.startswith("_"):
            provider = load_python_provider(file_path)
            if provider is not None:
                providers.append(provider)

    logger.info("Loaded %d providers from %s", len(providers), dir_path)
    return providers
