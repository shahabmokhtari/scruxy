"""Tests for the provider registry and loader."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scruxy.providers.anthropic import AnthropicProvider
from scruxy.providers.base import LLMProvider, ProxyRequest, SSETextField, TextField
from scruxy.providers.loader import load_providers, load_yaml_provider
from scruxy.providers.openai import OpenAIProvider
from scruxy.providers.registry import ProviderRegistry


class TestProviderRegistryBasics:
    """Test basic registry operations."""

    def test_empty_registry(self):
        registry = ProviderRegistry()
        assert len(registry) == 0
        assert registry.providers == []

    def test_register_provider(self):
        registry = ProviderRegistry()
        provider = AnthropicProvider()
        registry.register(provider)
        assert len(registry) == 1
        assert "anthropic" in registry

    def test_register_multiple_providers(self):
        registry = ProviderRegistry()
        registry.register(AnthropicProvider())
        registry.register(OpenAIProvider())
        assert len(registry) == 2
        assert "anthropic" in registry
        assert "openai" in registry

    def test_contains_by_name(self):
        registry = ProviderRegistry()
        registry.register(AnthropicProvider())
        assert "anthropic" in registry
        assert "openai" not in registry

    def test_providers_property_returns_copy(self):
        registry = ProviderRegistry()
        registry.register(AnthropicProvider())
        providers = registry.providers
        providers.clear()  # Modify the copy
        assert len(registry) == 1  # Original unchanged


class TestProviderRegistryMatching:
    """Test request matching through the registry."""

    def test_match_anthropic_request(self):
        registry = ProviderRegistry()
        registry.register(AnthropicProvider())
        registry.register(OpenAIProvider())

        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"anthropic-version": "2023-06-01", "authorization": "Bearer sk-123"},
        )
        provider = registry.match(request)
        assert provider is not None
        assert provider.name == "anthropic"

    def test_match_openai_request(self):
        registry = ProviderRegistry()
        registry.register(AnthropicProvider())
        registry.register(OpenAIProvider())

        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
        )
        provider = registry.match(request)
        assert provider is not None
        assert provider.name == "openai"

    def test_no_match_returns_none(self):
        registry = ProviderRegistry()
        registry.register(AnthropicProvider())
        registry.register(OpenAIProvider())

        request = ProxyRequest(
            method="GET",
            url="https://example.com/api/health",
            headers={"accept": "application/json"},
        )
        provider = registry.match(request)
        assert provider is None

    def test_first_match_wins_priority(self):
        """When multiple providers could match, the first registered wins."""
        registry = ProviderRegistry()

        # Create a custom provider that matches everything
        class CatchAllProvider(LLMProvider):
            name = "catch_all"
            display_name = "Catch All"

            def matches(self, request: ProxyRequest) -> bool:
                return True

            def extract_session_id(self, request: ProxyRequest) -> str:
                return "test"

            def extract_text_fields(self, body: dict) -> list[TextField]:
                return []

            def replace_text_fields(self, body: dict, replacements: dict[str, str]) -> dict:
                return body

            def extract_response_text_fields(self, body: dict) -> list[TextField]:
                return []

            def parse_sse_event(self, event_data: str) -> SSETextField | None:
                return None

            def rebuild_sse_event(self, event_data: str, new_text: str) -> str:
                return event_data

            @property
            def default_url_patterns(self) -> list[str]:
                return ["*"]

            @property
            def auth_headers(self) -> list[str]:
                return []

        # Register catch-all first
        registry.register(CatchAllProvider())
        registry.register(AnthropicProvider())

        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"anthropic-version": "2023-06-01"},
        )
        provider = registry.match(request)
        assert provider is not None
        # With match_headers disambiguation, anthropic wins because its
        # match_headers are present in the request (even though catch_all
        # was registered first). This is correct — header disambiguation
        # prevents routing to the wrong provider.
        assert provider.name == "anthropic"

    def test_priority_order_anthropic_then_openai(self):
        """With proper ordering, Anthropic is matched before OpenAI."""
        registry = ProviderRegistry()
        registry.register(AnthropicProvider())
        registry.register(OpenAIProvider())

        # Request that could only match Anthropic
        request = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"anthropic-version": "2023-06-01"},
        )
        provider = registry.match(request)
        assert provider is not None
        assert provider.name == "anthropic"

    def test_match_with_erroring_provider(self):
        """If a provider raises an exception, matching continues to next provider."""
        registry = ProviderRegistry()

        class BrokenProvider(LLMProvider):
            name = "broken"
            display_name = "Broken"

            def matches(self, request: ProxyRequest) -> bool:
                raise RuntimeError("Provider is broken")

            def extract_session_id(self, request: ProxyRequest) -> str:
                return "test"

            def extract_text_fields(self, body: dict) -> list[TextField]:
                return []

            def replace_text_fields(self, body: dict, replacements: dict[str, str]) -> dict:
                return body

            def extract_response_text_fields(self, body: dict) -> list[TextField]:
                return []

            def parse_sse_event(self, event_data: str) -> SSETextField | None:
                return None

            def rebuild_sse_event(self, event_data: str, new_text: str) -> str:
                return event_data

            @property
            def default_url_patterns(self) -> list[str]:
                return []

            @property
            def auth_headers(self) -> list[str]:
                return []

        registry.register(BrokenProvider())
        registry.register(OpenAIProvider())

        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
        )
        provider = registry.match(request)
        assert provider is not None
        assert provider.name == "openai"

    def test_empty_registry_returns_none(self):
        registry = ProviderRegistry()
        request = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
        )
        assert registry.match(request) is None


class TestProviderLoader:
    """Test the provider loader functionality."""

    def test_load_from_default_config_dir(self):
        """Load providers from the default_config/providers directory."""
        config_dir = Path(__file__).resolve().parent.parent / "default_config" / "providers"
        providers = load_providers(config_dir)
        assert len(providers) == 5
        names = {p.name for p in providers}
        assert "anthropic" in names
        assert "openai" in names
        assert "openai_responses" in names
        assert "copilot_chat" in names
        assert "copilot_responses" in names

    def test_load_from_empty_dir(self, tmp_path: Path):
        providers = load_providers(tmp_path)
        assert providers == []

    def test_load_from_nonexistent_dir(self, tmp_path: Path):
        providers = load_providers(tmp_path / "nonexistent")
        assert providers == []

    def test_load_yaml_provider_directly(self):
        config_path = (
            Path(__file__).resolve().parent.parent
            / "default_config"
            / "providers"
            / "anthropic.yaml"
        )
        provider = load_yaml_provider(config_path)
        assert provider is not None
        assert provider.name == "anthropic"

    def test_load_invalid_yaml(self, tmp_path: Path):
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("not: a: valid: provider: config")
        provider = load_yaml_provider(bad_yaml)
        # Should return None because no 'name' key
        assert provider is None

    def test_load_yaml_missing_name(self, tmp_path: Path):
        no_name = tmp_path / "no_name.yaml"
        no_name.write_text(yaml.dump({"display_name": "Test", "url_patterns": ["*"]}))
        provider = load_yaml_provider(no_name)
        assert provider is None

    def test_load_custom_yaml_provider(self, tmp_path: Path):
        config = {
            "name": "custom",
            "display_name": "Custom Provider",
            "url_patterns": ["*/custom/api"],
            "match_headers": ["x-custom-auth"],
            "auth_headers": ["x-custom-auth"],
            "session_id_headers": ["x-custom-session"],
            "request_text_paths": ["$.messages[*].text"],
            "response_text_paths": ["$.result.text"],
            "sse_events": {},
        }
        yaml_path = tmp_path / "custom.yaml"
        with open(yaml_path, "w") as f:
            yaml.dump(config, f)

        provider = load_yaml_provider(yaml_path)
        assert provider is not None
        assert provider.name == "custom"
        assert provider.display_name == "Custom Provider"

        # Verify it matches
        request = ProxyRequest(
            method="POST",
            url="https://example.com/custom/api",
            headers={"x-custom-auth": "key-123"},
        )
        assert provider.matches(request) is True

    def test_load_skips_underscore_py_files(self, tmp_path: Path):
        """Python files starting with _ are skipped."""
        init_file = tmp_path / "__init__.py"
        init_file.write_text("# init")
        providers = load_providers(tmp_path)
        assert providers == []

    def test_load_deterministic_ordering(self, tmp_path: Path):
        """Providers are loaded in alphabetical order."""
        for name in ["charlie", "alpha", "bravo"]:
            config = {
                "name": name,
                "url_patterns": [f"*/{name}"],
                "match_headers": ["auth"],
            }
            with open(tmp_path / f"{name}.yaml", "w") as f:
                yaml.dump(config, f)

        providers = load_providers(tmp_path)
        assert len(providers) == 3
        assert [p.name for p in providers] == ["alpha", "bravo", "charlie"]


class TestProviderRegistryWithLoader:
    """Integration tests: load providers and register them in the registry."""

    def test_full_workflow(self):
        """Load default providers, register, and match requests."""
        config_dir = Path(__file__).resolve().parent.parent / "default_config" / "providers"
        providers = load_providers(config_dir)

        registry = ProviderRegistry()
        for p in providers:
            registry.register(p)

        # Match an Anthropic request
        anthropic_req = ProxyRequest(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"anthropic-version": "2023-06-01"},
        )
        result = registry.match(anthropic_req)
        assert result is not None
        assert result.name == "anthropic"

        # Match an OpenAI request
        openai_req = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
        )
        result = registry.match(openai_req)
        assert result is not None
        assert result.name == "openai"

        # Non-matching request
        other_req = ProxyRequest(
            method="GET",
            url="https://example.com/health",
            headers={},
        )
        assert registry.match(other_req) is None


class TestFindPassthroughProvider:
    """Test passthrough provider routing for unmatched paths."""

    def _make_registry(self):
        config_dir = Path(__file__).resolve().parent.parent / "default_config" / "providers"
        providers = load_providers(config_dir)
        registry = ProviderRegistry()
        for p in providers:
            registry.register(p)
        return registry

    def _make_registry_with_upstreams(self):
        """Registry with upstream_url set (as would happen in real app startup)."""
        registry = self._make_registry()
        for p in registry.providers:
            if p.name == "anthropic":
                p.upstream_url = "https://api.anthropic.com"
            elif p.name == "openai":
                p.upstream_url = "https://api.openai.com"
        return registry

    def test_host_match_openai(self):
        """Forward proxy: URL hostname matches OpenAI upstream."""
        registry = self._make_registry_with_upstreams()
        req = ProxyRequest(
            method="GET",
            url="https://api.openai.com/v1/models",
            headers={"authorization": "Bearer sk-123"},
        )
        assert registry.match(req) is None  # no full match
        provider = registry.find_passthrough_provider(req)
        assert provider is not None
        assert provider.name == "openai"

    def test_host_match_anthropic(self):
        """Forward proxy: URL hostname matches Anthropic upstream."""
        registry = self._make_registry_with_upstreams()
        req = ProxyRequest(
            method="GET",
            url="https://api.anthropic.com/v1/models",
            headers={"anthropic-version": "2023-06-01"},
        )
        assert registry.match(req) is None
        provider = registry.find_passthrough_provider(req)
        assert provider is not None
        assert provider.name == "anthropic"

    def test_header_match_reverse_proxy_openai(self):
        """Reverse proxy: localhost URL but authorization header → OpenAI."""
        registry = self._make_registry()
        req = ProxyRequest(
            method="GET",
            url="http://localhost:8080/v1/models",
            headers={"authorization": "Bearer sk-123"},
        )
        assert registry.match(req) is None
        provider = registry.find_passthrough_provider(req)
        assert provider is not None
        # Should match OpenAI via authorization header
        assert provider.name == "openai"

    def test_header_match_reverse_proxy_anthropic(self):
        """Reverse proxy: localhost URL with anthropic-version → Anthropic."""
        registry = self._make_registry()
        req = ProxyRequest(
            method="GET",
            url="http://localhost:8080/v1/models",
            headers={"anthropic-version": "2023-06-01"},
        )
        assert registry.match(req) is None
        provider = registry.find_passthrough_provider(req)
        assert provider is not None
        assert provider.name == "anthropic"

    def test_no_match_unknown_host_and_headers(self):
        """No provider matches by host or headers → returns None."""
        registry = self._make_registry()
        req = ProxyRequest(
            method="GET",
            url="https://example.com/api/health",
            headers={"accept": "application/json"},
        )
        assert registry.find_passthrough_provider(req) is None

    def test_empty_registry(self):
        registry = ProviderRegistry()
        req = ProxyRequest(
            method="GET",
            url="https://api.openai.com/v1/models",
            headers={"authorization": "Bearer sk-123"},
        )
        assert registry.find_passthrough_provider(req) is None

    def test_host_match_takes_priority_over_header(self):
        """Host match is tried first (forward proxy accuracy)."""
        registry = self._make_registry_with_upstreams()
        # URL hostname is api.anthropic.com but has authorization header (OpenAI-like)
        req = ProxyRequest(
            method="GET",
            url="https://api.anthropic.com/v1/some-endpoint",
            headers={"authorization": "Bearer sk-123"},
        )
        provider = registry.find_passthrough_provider(req)
        assert provider is not None
        assert provider.name == "anthropic"  # host match wins over header

    def test_disabled_provider_skipped(self):
        """Disabled providers are not considered for passthrough."""
        registry = self._make_registry()
        for p in registry.providers:
            p.enabled = False
        req = ProxyRequest(
            method="GET",
            url="https://api.openai.com/v1/models",
            headers={"authorization": "Bearer sk-123"},
        )
        assert registry.find_passthrough_provider(req) is None


class TestMatchDisabled:
    """Test match_disabled - finds disabled providers that would match."""

    def _make_registry(self):
        config_dir = Path(__file__).resolve().parent.parent / "default_config" / "providers"
        providers = load_providers(config_dir)
        registry = ProviderRegistry()
        for p in providers:
            registry.register(p)
        return registry

    def test_disabled_openai_matched(self):
        registry = self._make_registry()
        for p in registry.providers:
            if p.name == "openai":
                p.enabled = False
        req = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
        )
        assert registry.match(req) is None  # enabled match fails
        disabled = registry.match_disabled(req)
        assert disabled is not None
        assert disabled.name == "openai"

    def test_enabled_provider_not_returned(self):
        registry = self._make_registry()
        req = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
        )
        assert registry.match_disabled(req) is None  # all enabled

    def test_no_disabled_match(self):
        registry = self._make_registry()
        for p in registry.providers:
            p.enabled = False
        req = ProxyRequest(
            method="GET",
            url="https://example.com/health",
            headers={},
        )
        assert registry.match_disabled(req) is None


class TestUserUrlPatterns:
    """Test user-configurable URL pattern overrides."""

    def test_user_override_takes_effect(self):
        config_dir = Path(__file__).resolve().parent.parent / "default_config" / "providers"
        providers = load_providers(config_dir)
        openai = next(p for p in providers if p.name == "openai")

        req_match = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
        )
        assert openai.matches(req_match)

        # Override to only match /v1/custom/*
        openai.user_url_patterns = ["*/v1/custom/*"]
        assert not openai.matches(req_match)

        custom_req = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/custom/endpoint",
            headers={"authorization": "Bearer sk-123"},
        )
        assert openai.matches(custom_req)

    def test_reset_to_defaults(self):
        config_dir = Path(__file__).resolve().parent.parent / "default_config" / "providers"
        providers = load_providers(config_dir)
        openai = next(p for p in providers if p.name == "openai")

        openai.user_url_patterns = ["*/v1/custom/*"]
        openai.user_url_patterns = None  # reset

        req = ProxyRequest(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"authorization": "Bearer sk-123"},
        )
        assert openai.matches(req)

    def test_default_url_patterns_list(self):
        config_dir = Path(__file__).resolve().parent.parent / "default_config" / "providers"
        providers = load_providers(config_dir)
        openai = next(p for p in providers if p.name == "openai")

        defaults = openai.default_url_patterns_list
        assert "*/v1/chat/completions" in defaults
        openai.user_url_patterns = ["*/custom"]
        assert openai.default_url_patterns_list == defaults
