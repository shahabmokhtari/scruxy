"""Tests for the web UI routes and API endpoints."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from scruxy.config.models import AppConfig
from scruxy.recording.recorder import SessionRecorder
from scruxy.ui.routes import mount_static, router

_REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Mock stage classes (avoid importing real stages that require spaCy/presidio)
# ---------------------------------------------------------------------------

from scruxy.plugin.base import ConfigField

MockPresidioPlugin = type("PresidioPlugin", (), {
    "name": "presidio",
    "plugin_type": "builtin",
    "version": "2.2.0",
    "enabled": True,
    "description": "",
    "_language": "en",
    "_score_threshold": 0.5,
    "_entities": ["PERSON", "EMAIL_ADDRESS"],
    "config_schema": [
        ConfigField(name="spacy_model", field_type="string", default="en_core_web_lg", description="spaCy model name", label="spaCy Model", details="Common models info"),
        ConfigField(name="language", field_type="select", default="en", description="Language code", label="Language", choices=["en", "es", "de", "fr"]),
        ConfigField(name="score_threshold", field_type="number", default=0.5, min_value=0.0, max_value=1.0, description="Minimum confidence score", label="Confidence Threshold", details="Recommended range info"),
        ConfigField(name="entities", field_type="list", default=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"], description="Entity types to detect", label="Entity Types", details="Common types info"),
    ],
})

MockRegexPlugin = type("RegexPlugin", (), {
    "name": "regex",
    "plugin_type": "builtin",
    "version": "built-in",
    "enabled": True,
    "description": "",
    "_patterns": [
        SimpleNamespace(entity_type="BADGE_NUMBER"),
        SimpleNamespace(entity_type="PROJECT_CODENAME"),
    ],
    "config_schema": [
        ConfigField(name="patterns_file", field_type="file", default="~/.scruxy/regex_patterns.yaml", description="YAML patterns file path", label="Patterns File", details="Click Edit File to modify patterns"),
    ],
})

_user_plugin = SimpleNamespace(
    name="custom_detector",
    enabled=True,
    entity_types=["SSN"],
    version="1.0.0",
    plugin_type="user",
    description="",
    config_schema=[
        ConfigField(name="pattern", field_type="string", default=r"\d{3}-\d{2}-\d{4}", description="SSN regex pattern"),
        ConfigField(name="confidence", field_type="number", default=0.9, min_value=0.0, max_value=1.0, description="Confidence threshold"),
    ],
    teardown=lambda: None,
)


def _make_mock_plugin_stage():
    """Create a PluginStage-compatible mock with _plugins and load_plugins."""
    stage = SimpleNamespace(
        _plugins=[_user_plugin],
        _storages={},
        plugins=[_user_plugin],
        load_plugins=lambda: None,  # overridden per-test when needed
    )
    # Keep plugins property in sync
    stage.plugins = stage._plugins
    return stage


MockPluginStage = _make_mock_plugin_stage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_app(**state_overrides: Any) -> FastAPI:
    """Build a minimal FastAPI app with the UI router and mocked app state."""
    app = FastAPI()
    app.include_router(router)
    mount_static(app)

    # Default mocks
    config = state_overrides.get("config", AppConfig())

    stats = state_overrides.get("stats", SimpleNamespace(
        total_requests=42,
        total_entities=128,
        latency_history=[1.2, 2.3, 3.4],
        recent_events=[
            {"type": "scrub_event", "timestamp": 1709500000, "message": "Scrubbed EMAIL"},
        ],
        entities_by_type={"EMAIL": 50, "PHONE_NUMBER": 30},
        requests_by_provider={"anthropic": 20, "openai": 22},
        uptime_seconds=3600,
        per_session={
            "sess-001": {"provider": "anthropic", "entities": 5, "requests": 3},
        },
    ))

    token_map = SimpleNamespace(
        scrub_map={"john@example.com": "REDACTED_EMAIL_1"},
        _entity_types={"john@example.com": "EMAIL"},
        size=1,
        to_dict=lambda: {"scrub": {"john@example.com": "REDACTED_EMAIL_1"}},
    )
    session_store = state_overrides.get("session_store", SimpleNamespace(
        session_ids=["sess-001"],
        sessions={"sess-001": token_map},
        shared_map=token_map,
        get_token_map=lambda sid: token_map if sid == "sess-001" else None,
    ))

    recording_entries = [
        {"direction": "request", "timestamp": 1709500000, "url": "/v1/messages"},
        {"direction": "response", "timestamp": 1709500001, "summary": "200 OK"},
    ]
    recording = state_overrides.get("recording", SimpleNamespace(
        get_session_recordings=AsyncMock(return_value=recording_entries),
        get_entries=AsyncMock(return_value=recording_entries),
    ))

    async def _mock_scrub_text(text, token_map, context=None):
        """Mock scrub_text that returns the text unchanged with no entities."""
        from scruxy.pipeline.models import PipelineResult
        return PipelineResult(entities=[], scrubbed_text=text, latency_ms=0.1)

    pipeline = state_overrides.get("pipeline", SimpleNamespace(
        stages=[MockPresidioPlugin(), MockRegexPlugin(), MockPluginStage()],
        plugins=[
            SimpleNamespace(name="custom_detector", enabled=True, entity_types=["SSN"], version="1.0.0"),
        ],
        scrub_text=_mock_scrub_text,
    ))

    providers_registry = state_overrides.get("providers", SimpleNamespace(
        providers=[
            SimpleNamespace(name="anthropic", url_patterns=["/v1/messages"], enabled=True),
            SimpleNamespace(name="openai", url_patterns=["/v1/chat/completions"], enabled=True),
        ],
    ))

    event_bus = state_overrides.get("event_bus", SimpleNamespace(subscribers=[]))

    app.state.config = config
    # Default to a temp file so tests never pollute ~/.scruxy/config.yaml
    if "config_path" in state_overrides:
        app.state.config_path = state_overrides["config_path"]
    else:
        app.state.config_path = Path(tempfile.mkdtemp()) / "test_config.yaml"
    app.state.stats = stats
    app.state.session_store = session_store
    app.state.recording = recording
    app.state.pipeline = pipeline
    app.state.providers = providers_registry
    app.state.event_bus = event_bus
    app.state._listen_host = state_overrides.get("listen_host", "localhost")

    return app


@pytest.fixture
def app() -> FastAPI:
    return _make_app()


@pytest.fixture
def client(app: FastAPI) -> AsyncClient:
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# ---------------------------------------------------------------------------
# Page route tests
# ---------------------------------------------------------------------------

class TestPageRoutes:
    """Verify that page routes return HTML with 200 status."""

    async def test_dashboard_page(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Dashboard" in resp.text

    @pytest.mark.parametrize("page", [
        "plugins", "providers", "tokens",
        "recordings", "logs", "settings",
    ])
    async def test_sub_pages(self, client: AsyncClient, page: str) -> None:
        resp = await client.get(f"/ui/{page}")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    async def test_pipeline_redirects_to_plugins(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/pipeline", follow_redirects=False)
        assert resp.status_code == 301
        assert "/ui/plugins" in resp.headers.get("location", "")

    async def test_invalid_page_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/nonexistent")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

class TestDashboardAPI:

    async def test_returns_json(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "mode" in data
        assert "providers" in data
        assert "active_sessions" in data
        assert "total_requests" in data
        assert "total_entities" in data
        assert "latency_history" in data
        assert "recent_events" in data

    async def test_dashboard_values(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/dashboard")).json()
        assert data["mode"] == "primary"
        assert data["total_requests"] == 42
        assert data["total_entities"] == 128
        assert len(data["latency_history"]) == 3
        assert "sess-001" in data["active_sessions"]

    async def test_dashboard_includes_listen_config(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/dashboard")).json()
        assert "listen_host" in data
        assert "listen_port" in data
        assert data["listen_host"] == "localhost"
        assert data["listen_port"] == 8080

    async def test_dashboard_includes_forward_proxy_config(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/dashboard")).json()
        assert "forward_proxy_enabled" in data
        assert "forward_proxy_port" in data
        assert "ca_cert_path" in data
        assert data["forward_proxy_enabled"] is True
        assert data["forward_proxy_port"] == 8081


class TestLocalhostWriteGuard:
    async def test_sensitive_read_allows_bracketed_ipv6_loopback_host(self) -> None:
        app = _make_app(listen_host="::1")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/ui/api/config",
                headers={"host": "[::1]:8080"},
            )

        assert resp.status_code == 200

    async def test_origin_null_rejected_on_write(self) -> None:
        """Origin: null (sandboxed iframes, file://) must be rejected."""
        app = _make_app(listen_host="127.0.0.1")
        app.state.config_path = Path(tempfile.mkdtemp()) / "config.yaml"
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put(
                "/ui/api/config",
                json={"interception": {"listen_port": 9999}},
                headers={
                    "host": "localhost",
                    "origin": "null",
                },
            )
        assert resp.status_code == 403

    async def test_origin_unparseable_rejected_on_write(self) -> None:
        """Origin without scheme/host must be rejected on write."""
        app = _make_app(listen_host="127.0.0.1")
        app.state.config_path = Path(tempfile.mkdtemp()) / "config.yaml"
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put(
                "/ui/api/config",
                json={"interception": {"listen_port": 9999}},
                headers={
                    "host": "localhost",
                    "origin": "garbage",
                },
            )
        assert resp.status_code == 403

    async def test_public_bind_rejects_cross_origin_loopback_write(self) -> None:
        app = _make_app(listen_host="0.0.0.0")
        app.state.config_path = Path(tempfile.mkdtemp()) / "config.yaml"
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put(
                "/ui/api/config",
                json={"interception": {"listen_port": 9999}},
                headers={
                    "host": "evil.example",
                    "origin": "https://evil.example",
                },
            )

        assert resp.status_code == 403

    async def test_dashboard_no_stats(self) -> None:
        """Dashboard endpoint still works when stats is missing."""
        app = _make_app()
        del app.state.stats
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/ui/api/dashboard")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_requests"] == 0


class TestSessionsAPI:

    async def test_list_sessions(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert "sessions" in data
        assert len(data["sessions"]) == 1
        assert data["sessions"][0]["session_id"] == "sess-001"
        assert data["sessions"][0]["provider"] == "anthropic"


class TestSessionTokensAPI:

    async def test_session_tokens(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/sessions/_shared/tokens")
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "_shared"
        assert "john@example.com" in data["tokens"]
        assert data["tokens"]["john@example.com"] == "REDACTED_EMAIL_1"

    async def test_nonexistent_session_returns_empty_tokens(self, client: AsyncClient) -> None:
        """Nonexistent session returns empty tokens (session-scoped filtering)."""
        resp = await client.get("/ui/api/sessions/nonexistent/tokens")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tokens"] == {}


class TestSessionRecordingsAPI:

    async def test_session_recordings(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/sessions/sess-001/recordings")
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "sess-001"
        assert len(data["recordings"]) == 2
        assert data["recordings"][0]["direction"] == "request"


class TestPipelineConfigAPI:

    async def test_pipeline_config(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/pipeline/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "stages" in data
        assert len(data["stages"]) == 6
        stage_names = [s["name"] for s in data["stages"]]
        assert "whitelist" in stage_names
        assert "presidio" in stage_names
        assert "regex" in stage_names
        assert "plugins" in stage_names

    async def test_pipeline_stages_have_config(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/pipeline/config")).json()
        presidio = next(s for s in data["stages"] if s["name"] == "presidio")
        assert presidio["enabled"] is True
        assert "score_threshold" in presidio["config"]


class TestPluginsAPI:

    async def test_plugins_includes_builtins(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/plugins")
        assert resp.status_code == 200
        data = resp.json()
        assert "plugins" in data
        names = [p["name"] for p in data["plugins"]]
        assert "presidio" in names
        assert "regex" in names

    async def test_plugins_includes_user_plugins(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/plugins")).json()
        user_plugins = [p for p in data["plugins"] if p["type"] == "user"]
        assert len(user_plugins) == 1
        assert user_plugins[0]["name"] == "custom_detector"
        assert user_plugins[0]["entity_types"] == ["SSN"]

    async def test_builtin_plugins_have_metadata(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/plugins")).json()
        presidio = next(p for p in data["plugins"] if p["name"] == "presidio")
        assert presidio["type"] == "builtin"
        assert presidio["display_name"] == "Microsoft Presidio"
        assert "description" in presidio
        assert "entity_types" in presidio
        assert "config" in presidio

    async def test_regex_plugin_has_entity_types(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/plugins")).json()
        regex = next(p for p in data["plugins"] if p["name"] == "regex")
        assert regex["type"] == "builtin"
        assert "BADGE_NUMBER" in regex["entity_types"]
        assert "PROJECT_CODENAME" in regex["entity_types"]

    async def test_user_plugin_has_config_schema(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/plugins")).json()
        user_plugins = [p for p in data["plugins"] if p["type"] == "user"]
        assert len(user_plugins) == 1
        schema = user_plugins[0].get("config_schema", [])
        assert len(schema) == 2
        pattern_field = schema[0]
        assert pattern_field["name"] == "pattern"
        assert pattern_field["field_type"] == "string"
        assert pattern_field["description"] == "SSN regex pattern"
        confidence_field = schema[1]
        assert confidence_field["name"] == "confidence"
        assert confidence_field["field_type"] == "number"
        assert confidence_field["min_value"] == 0.0
        assert confidence_field["max_value"] == 1.0

    async def test_user_plugin_without_schema(self) -> None:
        """A user plugin without config_schema returns empty schema list."""
        mock_stage = type("PluginStage", (), {
            "plugins": [
                SimpleNamespace(name="no_schema", enabled=True, entity_types=[], version="0.1", plugin_type="user"),
            ],
        })
        pipeline = SimpleNamespace(
            stages=[mock_stage()],
        )
        app = _make_app(pipeline=pipeline)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            data = (await c.get("/ui/api/plugins")).json()
            user_plugins = [p for p in data["plugins"] if p["type"] == "user"]
            assert len(user_plugins) == 1
            assert user_plugins[0].get("config_schema", []) == []


class TestProvidersAPI:

    async def test_providers_list(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/providers")
        assert resp.status_code == 200
        data = resp.json()
        assert "providers" in data
        assert len(data["providers"]) == 2
        names = [p["name"] for p in data["providers"]]
        assert "anthropic" in names
        assert "openai" in names

    async def test_providers_fallback_to_config(self) -> None:
        """When providers registry is not set, fall back to config providers."""
        app = _make_app()
        del app.state.providers
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/ui/api/providers")
            data = resp.json()
            assert len(data["providers"]) > 0
            names = [p["name"] for p in data["providers"]]
            assert "anthropic" in names


class TestProviderUpdateAPI:
    """Tests for PUT /ui/api/providers/{name} — provider enable/disable and URL editing."""

    async def test_update_enabled(self, tmp_path) -> None:
        """Toggling enabled succeeds and returns updated provider."""
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/providers/anthropic",
                json={"enabled": False},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["name"] == "anthropic"
            assert data["enabled"] is False

    async def test_update_upstream_url(self, tmp_path) -> None:
        """Updating upstream_url succeeds and returns the new value."""
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/providers/openai",
                json={"upstream_url": "https://custom.openai.example.com"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["name"] == "openai"
            assert data["upstream_url"] == "https://custom.openai.example.com"

    async def test_update_both_fields(self, tmp_path) -> None:
        """Updating both enabled and upstream_url at once works."""
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/providers/openai",
                json={"enabled": False, "upstream_url": "https://custom.openai.example.com"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["name"] == "openai"
            assert data["enabled"] is False
            assert data["upstream_url"] == "https://custom.openai.example.com"

    async def test_update_nonexistent_provider_returns_404(self) -> None:
        """Updating a provider that doesn't exist returns 404."""
        app = _make_app()
        app.state.config_path = Path(tempfile.mkdtemp()) / "config.yaml"

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/providers/nonexistent",
                json={"enabled": False},
            )
            assert resp.status_code == 404
            assert "not found" in resp.json()["error"].lower()

    async def test_invalid_json_returns_400(self) -> None:
        """Sending invalid JSON returns 400."""
        app = _make_app()
        app.state.config_path = Path(tempfile.mkdtemp()) / "config.yaml"

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/providers/anthropic",
                content=b"not valid json",
                headers={"content-type": "application/json"},
            )
            assert resp.status_code == 400
            assert "error" in resp.json()

    async def test_update_persists_to_disk(self, tmp_path) -> None:
        """Provider updates are persisted to disk via save_config."""
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/providers/anthropic",
                json={"enabled": False, "upstream_url": "https://proxy.anthropic.com"},
            )
            assert resp.status_code == 200

            # Verify the YAML file was written with the updated values.
            assert config_path.exists()
            import yaml as _yaml
            with open(config_path) as f:
                raw = _yaml.safe_load(f)
            assert raw["providers"]["anthropic"]["enabled"] is False
            assert raw["providers"]["anthropic"]["upstream_url"] == "https://proxy.anthropic.com"


class TestStatsAPI:

    async def test_stats(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_requests"] == 42
        assert data["total_entities"] == 128
        assert data["uptime_seconds"] == 3600
        assert "entities_by_type" in data
        assert "latency_history" in data

    async def test_stats_empty(self) -> None:
        """Stats endpoint works when stats service is missing."""
        app = _make_app()
        del app.state.stats
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/ui/api/stats")
            assert resp.status_code == 200
            assert resp.json() == {}


class TestConfigAPI:

    async def test_config(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "interception" in data
        assert "providers" in data
        assert "tokens" in data
        assert "pipeline" in data
        assert "sessions" in data

    async def test_config_missing(self) -> None:
        """Config endpoint works when config is not set."""
        app = _make_app()
        del app.state.config
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/ui/api/config")
            assert resp.status_code == 200
            assert resp.json() == {}


# ---------------------------------------------------------------------------
# SSE endpoint tests
# ---------------------------------------------------------------------------

class TestSSEEndpoint:

    async def test_sse_returns_streaming_response(self, app: FastAPI) -> None:
        """The api_events endpoint produces a StreamingResponse with event-stream type."""
        from scruxy.ui.routes import api_events

        scope: dict[str, Any] = {
            "type": "http",
            "method": "GET",
            "path": "/ui/api/events",
            "query_string": b"",
            "headers": [],
            "app": app,
        }
        mock_request = Request(scope)

        resp = await api_events(mock_request)
        assert resp.media_type == "text/event-stream"
        assert resp.headers.get("Cache-Control") == "no-cache"

    async def test_sse_generator_yields_connected_event(self, app: FastAPI) -> None:
        """The SSE generator yields a connected event first."""
        from scruxy.ui.routes import api_events

        scope: dict[str, Any] = {
            "type": "http",
            "method": "GET",
            "path": "/ui/api/events",
            "query_string": b"",
            "headers": [],
            "app": app,
        }
        mock_request = Request(scope)

        resp = await api_events(mock_request)
        # Get the first chunk from the body iterator
        body_iter = resp.body_iterator
        first_chunk = await body_iter.__anext__()  # type: ignore[union-attr]
        assert "connected" in first_chunk
        parsed = json.loads(first_chunk.replace("data: ", "").strip())
        assert parsed["type"] == "connected"
        assert "timestamp" in parsed

    async def test_sse_no_event_bus(self) -> None:
        """SSE works even without an event bus."""
        app = _make_app()
        del app.state.event_bus

        from scruxy.ui.routes import api_events

        scope: dict[str, Any] = {
            "type": "http",
            "method": "GET",
            "path": "/ui/api/events",
            "query_string": b"",
            "headers": [],
            "app": app,
        }
        mock_request = Request(scope)

        resp = await api_events(mock_request)
        assert resp.media_type == "text/event-stream"
        first_chunk = await resp.body_iterator.__anext__()  # type: ignore[union-attr]
        assert "connected" in first_chunk


# ---------------------------------------------------------------------------
# Plugin creation API tests
# ---------------------------------------------------------------------------

class TestPluginCreateAPI:

    async def test_create_plugin_success(self, tmp_path) -> None:
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/plugins/create", json={"name": "my_detector"})
            assert resp.status_code == 201
            data = resp.json()
            assert data["name"] == "my_detector"
            assert (tmp_path / "plugins" / "my_detector.py").exists()

    async def test_create_plugin_duplicate(self, tmp_path) -> None:
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        (tmp_path / "plugins").mkdir()
        (tmp_path / "plugins" / "existing.py").write_text("# existing")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/plugins/create", json={"name": "existing"})
            assert resp.status_code == 409

    async def test_create_plugin_invalid_name(self, tmp_path) -> None:
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/plugins/create", json={"name": "123bad"})
            assert resp.status_code == 400

    async def test_create_plugin_empty_name(self, tmp_path) -> None:
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/plugins/create", json={"name": ""})
            assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Plugin source read / edit / delete API tests
# ---------------------------------------------------------------------------

class TestPluginSourceAPI:
    """Tests for GET/PUT/DELETE plugin source endpoints."""

    async def test_get_source(self, tmp_path) -> None:
        """GET /ui/api/plugins/{name}/source returns the file contents."""
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        (tmp_path / "plugins").mkdir()
        (tmp_path / "plugins" / "my_plugin.py").write_text("# hello world\n", encoding="utf-8")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/ui/api/plugins/my_plugin/source")
            assert resp.status_code == 200
            data = resp.json()
            assert data["name"] == "my_plugin"
            assert data["source"] == "# hello world\n"

    async def test_get_source_not_found(self, tmp_path) -> None:
        """GET returns 404 when the plugin file does not exist."""
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        (tmp_path / "plugins").mkdir()
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/ui/api/plugins/nonexistent/source")
            assert resp.status_code == 404
            assert "not found" in resp.json()["error"].lower()

    async def test_get_source_no_plugin_dir(self) -> None:
        """GET returns 500 when the plugin directory is not configured."""
        app = _make_app()
        # Ensure no plugin_dir is set (remove plugins stage config)
        app.state.config.pipeline.stages[4].config.pop("plugin_dir", None)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/ui/api/plugins/any_plugin/source")
            assert resp.status_code == 500
            assert "not configured" in resp.json()["error"].lower()

    async def test_update_source(self, tmp_path) -> None:
        """PUT /ui/api/plugins/{name}/source writes new content."""
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        (tmp_path / "plugins").mkdir()
        (tmp_path / "plugins" / "my_plugin.py").write_text("# old", encoding="utf-8")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/plugins/my_plugin/source",
                json={"source": "# new content\nprint('hello')\n"},
            )
            assert resp.status_code == 200
            assert "updated" in resp.json()["message"].lower()

            # Verify the file was actually written
            content = (tmp_path / "plugins" / "my_plugin.py").read_text(encoding="utf-8")
            assert content == "# new content\nprint('hello')\n"

    async def test_update_source_missing_body(self, tmp_path) -> None:
        """PUT returns 400 when 'source' key is missing from body."""
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        (tmp_path / "plugins").mkdir()
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/plugins/my_plugin/source",
                json={"not_source": "value"},
            )
            assert resp.status_code == 400
            assert "source" in resp.json()["error"].lower()

    async def test_update_source_no_plugin_dir(self) -> None:
        """PUT returns 500 when the plugin directory is not configured."""
        app = _make_app()
        app.state.config.pipeline.stages[4].config.pop("plugin_dir", None)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/plugins/any_plugin/source",
                json={"source": "# code"},
            )
            assert resp.status_code == 500

    async def test_update_source_creates_dir(self, tmp_path) -> None:
        """PUT creates the plugin directory if it does not exist yet."""
        app = _make_app()
        plugin_dir = str(tmp_path / "new_plugins_dir")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/plugins/fresh_plugin/source",
                json={"source": "# brand new"},
            )
            assert resp.status_code == 200
            assert (tmp_path / "new_plugins_dir" / "fresh_plugin.py").exists()

    async def test_delete_plugin(self, tmp_path) -> None:
        """DELETE /ui/api/plugins/{name} removes the plugin file."""
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        (tmp_path / "plugins").mkdir()
        plugin_file = tmp_path / "plugins" / "to_delete.py"
        plugin_file.write_text("# bye", encoding="utf-8")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.delete("/ui/api/plugins/to_delete")
            assert resp.status_code == 200
            assert "deleted" in resp.json()["message"].lower()
            assert not plugin_file.exists()

    async def test_delete_plugin_not_found(self, tmp_path) -> None:
        """DELETE returns 404 when the plugin file does not exist."""
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        (tmp_path / "plugins").mkdir()
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.delete("/ui/api/plugins/nonexistent")
            assert resp.status_code == 404
            assert "not found" in resp.json()["error"].lower()

    async def test_delete_plugin_no_plugin_dir(self) -> None:
        """DELETE returns 500 when the plugin directory is not configured."""
        app = _make_app()
        app.state.config.pipeline.stages[4].config.pop("plugin_dir", None)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.delete("/ui/api/plugins/any_plugin")
            assert resp.status_code == 500


# ---------------------------------------------------------------------------
# Plugin config update API tests
# ---------------------------------------------------------------------------

class TestPluginConfigUpdateAPI:

    async def test_update_presidio_config(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/ui/api/plugins/presidio/config",
            json={"score_threshold": 0.7},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["config"]["score_threshold"] == 0.7

    async def test_update_unknown_name_stored_as_plugin_config(self, client: AsyncClient) -> None:
        """An unknown name (not a builtin stage) is stored as a user plugin config."""
        resp = await client.put(
            "/ui/api/plugins/nonexistent/config",
            json={"key": "value"},
        )
        # Now stored under plugin_configs in the plugins stage
        assert resp.status_code == 200
        data = resp.json()
        assert data["config"]["key"] == "value"

    async def test_update_returns_404_when_no_plugins_stage(self) -> None:
        """Returns 404 when no plugins stage exists and name is not a builtin stage."""
        config = AppConfig()
        # Remove the plugins stage
        config.pipeline.stages = [s for s in config.pipeline.stages if s.name != "plugins"]
        app = _make_app(config=config)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/plugins/nonexistent/config",
                json={"key": "value"},
            )
            assert resp.status_code == 404

    async def test_update_preserves_existing_keys(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/ui/api/plugins/presidio/config",
            json={"score_threshold": 0.8},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Should still have the original keys
        assert "spacy_model" in data["config"]
        assert data["config"]["score_threshold"] == 0.8

    async def test_update_persists_to_disk(self, tmp_path) -> None:
        """Plugin config updates are persisted to disk via save_config."""
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/plugins/presidio/config",
                json={"score_threshold": 0.65},
            )
            assert resp.status_code == 200

            # Verify file was written
            assert config_path.exists()
            import yaml as _yaml
            with open(config_path) as f:
                raw = _yaml.safe_load(f)
            # Find the presidio stage config
            presidio_stage = next(
                s for s in raw["pipeline"]["stages"] if s["name"] == "presidio"
            )
            assert presidio_stage["config"]["score_threshold"] == 0.65

    async def test_user_plugin_config_stored_under_plugin_configs(self, tmp_path) -> None:
        """User plugin configs are stored under plugins stage -> plugin_configs."""
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/plugins/custom_detector/config",
                json={"pattern": r"\d{3}-\d{4}"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["config"]["pattern"] == r"\d{3}-\d{4}"

            # Verify it's stored under plugin_configs in the plugins stage
            import yaml as _yaml
            with open(config_path) as f:
                raw = _yaml.safe_load(f)
            plugins_stage = next(
                s for s in raw["pipeline"]["stages"] if s["name"] == "plugins"
            )
            assert "plugin_configs" in plugins_stage["config"]
            assert "custom_detector" in plugins_stage["config"]["plugin_configs"]
            assert plugins_stage["config"]["plugin_configs"]["custom_detector"]["pattern"] == r"\d{3}-\d{4}"


# ---------------------------------------------------------------------------
# No-cache header tests
# ---------------------------------------------------------------------------

class TestConfigUpdateAPI:
    """Tests for PUT /ui/api/config — partial config update and persistence."""

    async def test_partial_update_succeeds(self, tmp_path) -> None:
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/config",
                json={"interception": {"listen_port": 9999}},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["interception"]["listen_port"] == 9999
            # Other defaults should still be present.
            assert data["interception"]["mode"] == "primary"

    async def test_invalid_config_returns_400(self) -> None:
        app = _make_app()
        app.state.config_path = Path(tempfile.mkdtemp()) / "config.yaml"

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # listen_port expects an int; a non-numeric string should fail validation.
            resp = await c.put(
                "/ui/api/config",
                json={"interception": {"listen_port": "not_a_number"}},
            )
            assert resp.status_code == 400
            assert "error" in resp.json()

    async def test_updated_config_persists_to_disk(self, tmp_path) -> None:
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/config",
                json={"interception": {"listen_port": 7777}},
            )
            assert resp.status_code == 200

            # Verify file exists and contains the updated value.
            import yaml as _yaml
            with open(config_path) as f:
                raw = _yaml.safe_load(f)
            assert raw["interception"]["listen_port"] == 7777

    async def test_updated_config_visible_via_get(self, tmp_path) -> None:
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            await c.put(
                "/ui/api/config",
                json={"tokens": {"prefix": "SCRUBBED"}},
            )
            get_resp = await c.get("/ui/api/config")
            assert get_resp.status_code == 200
            assert get_resp.json()["tokens"]["prefix"] == "SCRUBBED"

    async def test_deep_merge_preserves_nested_keys(self, tmp_path) -> None:
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # Only update one nested field, should keep sibling keys untouched.
            resp = await c.put(
                "/ui/api/config",
                json={"interception": {"listen_host": "127.0.0.1"}},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["interception"]["listen_host"] == "127.0.0.1"
            assert data["interception"]["listen_port"] == 8080

    async def test_rejects_unsupported_mitmproxy_mode(self, tmp_path) -> None:
        app = _make_app()
        app.state.config_path = tmp_path / "config.yaml"

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/config",
                json={"interception": {"mode": "mitmproxy"}},
            )

        assert resp.status_code == 400
        assert "unsupported" in resp.json()["error"].lower()

    async def test_allows_unrelated_updates_with_legacy_mitmproxy_config(self, tmp_path) -> None:
        """Legacy configs should remain editable outside the interception section."""
        config = AppConfig()
        config.interception.mode = "mitmproxy"

        app = _make_app(config=config)
        app.state.config_path = tmp_path / "config.yaml"

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/config",
                json={"recording": {"enabled": False}},
            )

        assert resp.status_code == 200
        assert resp.json()["interception"]["mode"] == "mitmproxy"
        assert resp.json()["recording"]["enabled"] is False

    async def test_missing_config_returns_500(self) -> None:
        app = _make_app()
        del app.state.config
        app.state.config_path = Path(tempfile.mkdtemp()) / "config.yaml"

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/config",
                json={"interception": {"listen_port": 1234}},
            )
            assert resp.status_code == 500
            assert "error" in resp.json()

    async def test_invalid_json_body_returns_400(self) -> None:
        app = _make_app()
        app.state.config_path = Path(tempfile.mkdtemp()) / "config.yaml"

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/config",
                content=b"not valid json",
                headers={"content-type": "application/json"},
            )
            assert resp.status_code == 400

    async def test_recording_toggle_updates_live_recorder(self, tmp_path) -> None:
        """Changing recording settings should take effect immediately at runtime."""
        app = _make_app()
        app.state.config_path = tmp_path / "config.yaml"
        live_recorder = SessionRecorder(storage_dir=str(tmp_path / "sessions"))
        app.state.recorder = live_recorder
        app.state.recording = live_recorder
        app.state.forward_proxy = SimpleNamespace(_recorder=live_recorder)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/config",
                json={"recording": {"store_body_original": True}},
            )

        assert resp.status_code == 200
        assert isinstance(app.state.recorder, SessionRecorder)
        assert app.state.recorder is app.state.recording
        assert app.state.recorder is not live_recorder
        assert app.state.recorder._store_body_original is True
        assert app.state.forward_proxy._recorder is app.state.recorder

    async def test_disabling_recording_clears_live_recorder(self, tmp_path) -> None:
        """Disabling recording in the UI should stop the live recorder immediately."""
        app = _make_app()
        app.state.config_path = tmp_path / "config.yaml"
        live_recorder = SessionRecorder(storage_dir=str(tmp_path / "sessions"))
        app.state.recorder = live_recorder
        app.state.recording = live_recorder
        app.state.forward_proxy = SimpleNamespace(_recorder=live_recorder)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/config",
                json={"recording": {"enabled": False}},
            )

        assert resp.status_code == 200
        assert app.state.recorder is None
        assert app.state.recording is None
        assert app.state.forward_proxy._recorder is None


class TestConfigSchemaSerializationWithLabelDetails:
    """Verify that label and details are included in serialized config_schema."""

    async def test_label_and_details_in_schema(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/plugins")).json()
        presidio = next(p for p in data["plugins"] if p["name"] == "presidio")
        schema = presidio["config_schema"]

        spacy_field = next(f for f in schema if f["name"] == "spacy_model")
        assert spacy_field["label"] == "spaCy Model"
        assert spacy_field["details"] == "Common models info"

        lang_field = next(f for f in schema if f["name"] == "language")
        assert lang_field["label"] == "Language"
        assert lang_field["field_type"] == "select"
        assert "en" in lang_field["choices"]

        threshold_field = next(f for f in schema if f["name"] == "score_threshold")
        assert threshold_field["label"] == "Confidence Threshold"
        assert threshold_field["details"] == "Recommended range info"

        entities_field = next(f for f in schema if f["name"] == "entities")
        assert entities_field["label"] == "Entity Types"
        assert entities_field["details"] == "Common types info"
        assert isinstance(entities_field["default"], list)
        assert "PERSON" in entities_field["default"]

    async def test_regex_schema_has_file_field(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/plugins")).json()
        regex = next(p for p in data["plugins"] if p["name"] == "regex")
        schema = regex["config_schema"]

        file_field = next(f for f in schema if f["name"] == "patterns_file")
        assert file_field["field_type"] == "file"
        assert file_field["label"] == "Patterns File"
        assert file_field["details"] != ""

    async def test_empty_label_details_default(self, client: AsyncClient) -> None:
        """Fields without label/details get empty strings."""
        data = (await client.get("/ui/api/plugins")).json()
        user_plugins = [p for p in data["plugins"] if p["type"] == "user"]
        if user_plugins:
            schema = user_plugins[0].get("config_schema", [])
            for field in schema:
                assert "label" in field
                assert "details" in field


class TestPatternsFileAPI:
    """Tests for GET/PUT /ui/api/plugins/regex/patterns-file."""

    async def test_get_patterns_file_no_path(self) -> None:
        """Returns empty result when no patterns_file is configured."""
        config = AppConfig()
        # Remove patterns_file from regex stage config
        for stage in config.pipeline.stages:
            if stage.name == "regex":
                stage.config.pop("patterns_file", None)
                break
        app = _make_app(config=config)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/ui/api/plugins/regex/patterns-file")
            assert resp.status_code == 200
            data = resp.json()
            assert data["path"] == ""
            assert data["exists"] is False

    async def test_get_patterns_file_exists(self, tmp_path) -> None:
        """Returns file content when patterns file exists."""
        patterns_file = tmp_path / "patterns.yaml"
        patterns_file.write_text("regex_patterns:\n  - name: test\n", encoding="utf-8")

        app = _make_app()
        for stage in app.state.config.pipeline.stages:
            if stage.name == "regex":
                stage.config["patterns_file"] = str(patterns_file)
                break

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/ui/api/plugins/regex/patterns-file")
            assert resp.status_code == 200
            data = resp.json()
            assert data["exists"] is True
            assert "regex_patterns" in data["content"]

    async def test_get_patterns_file_not_exists(self, tmp_path) -> None:
        """Returns exists=False when file path is set but file doesn't exist."""
        app = _make_app()
        for stage in app.state.config.pipeline.stages:
            if stage.name == "regex":
                stage.config["patterns_file"] = str(tmp_path / "nonexistent.yaml")
                break

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/ui/api/plugins/regex/patterns-file")
            assert resp.status_code == 200
            data = resp.json()
            assert data["exists"] is False
            assert data["content"] == ""

    async def test_put_patterns_file(self, tmp_path) -> None:
        """Writes valid YAML content to the patterns file."""
        patterns_file = tmp_path / "patterns.yaml"

        app = _make_app()
        for stage in app.state.config.pipeline.stages:
            if stage.name == "regex":
                stage.config["patterns_file"] = str(patterns_file)
                break

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            content = "regex_patterns:\n  - name: test\n    entity_type: TEST\n    pattern: \"T-\\\\d+\"\n    score: 0.9\n"
            resp = await c.put(
                "/ui/api/plugins/regex/patterns-file",
                json={"content": content},
            )
            assert resp.status_code == 200
            assert patterns_file.exists()
            assert "regex_patterns" in patterns_file.read_text(encoding="utf-8")

    async def test_put_patterns_file_invalid_yaml(self, tmp_path) -> None:
        """Returns 400 for invalid YAML content."""
        patterns_file = tmp_path / "patterns.yaml"

        app = _make_app()
        for stage in app.state.config.pipeline.stages:
            if stage.name == "regex":
                stage.config["patterns_file"] = str(patterns_file)
                break

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/plugins/regex/patterns-file",
                json={"content": "invalid: yaml: [: broken"},
            )
            assert resp.status_code == 400
            assert "yaml" in resp.json()["error"].lower()

    async def test_put_patterns_file_no_config(self) -> None:
        """Returns 400 when no patterns_file is configured."""
        config = AppConfig()
        for stage in config.pipeline.stages:
            if stage.name == "regex":
                stage.config.pop("patterns_file", None)
                break
        app = _make_app(config=config)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/plugins/regex/patterns-file",
                json={"content": "regex_patterns: []"},
            )
            assert resp.status_code == 400


class TestPipelineStageToggleAPI:
    """Tests for PUT /ui/api/pipeline/stages/{name} — enable/disable stages."""

    async def test_disable_stage(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/ui/api/pipeline/stages/presidio",
            json={"enabled": False},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "presidio"
        assert data["enabled"] is False

    async def test_enable_stage(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/ui/api/pipeline/stages/presidio",
            json={"enabled": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is True

    async def test_toggle_nonexistent_stage_returns_404(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/ui/api/pipeline/stages/nonexistent",
            json={"enabled": False},
        )
        assert resp.status_code == 404
        assert "not found" in resp.json()["error"].lower()

    async def test_toggle_missing_enabled_returns_400(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/ui/api/pipeline/stages/presidio",
            json={"other": "value"},
        )
        assert resp.status_code == 400

    async def test_toggle_persists_to_config(self, tmp_path) -> None:
        """Stage toggle updates the config model."""
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/pipeline/stages/presidio",
                json={"enabled": False},
            )
            assert resp.status_code == 200

            # Verify config model was updated
            config = app.state.config
            presidio_stage = next(
                s for s in config.pipeline.stages if s.name == "presidio"
            )
            assert presidio_stage.enabled is False

    async def test_toggle_updates_runtime_stage(self, tmp_path) -> None:
        """Stage toggle also updates the runtime pipeline stage object."""
        app = _make_app()
        app.state.config_path = tmp_path / "config.yaml"

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/pipeline/stages/presidio",
                json={"enabled": False},
            )
            assert resp.status_code == 200

            # Verify the runtime stage was toggled
            presidio_stage = next(
                s for s in app.state.pipeline.stages
                if getattr(s, "name", None) == "presidio"
            )
            assert presidio_stage.enabled is False

    async def test_toggle_invalid_json(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/ui/api/pipeline/stages/presidio",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400


class TestTesterSamplesAPI:
    """Tests for GET /ui/api/tester/samples."""

    async def test_returns_provider_list(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/tester/samples")
        assert resp.status_code == 200
        data = resp.json()
        assert "providers" in data
        assert "anthropic" in data["providers"]
        assert "openai" in data["providers"]

    async def test_samples_have_required_keys(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/tester/samples")).json()
        for provider in ["anthropic", "openai"]:
            sample = data["samples"][provider]
            assert "display_name" in sample
            assert "request_body" in sample
            assert "response_body" in sample
            assert "request_text_paths" in sample
            assert "response_text_paths" in sample
            assert isinstance(sample["request_text_paths"], list)
            assert len(sample["request_text_paths"]) > 0

    async def test_anthropic_sample_has_pii(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/tester/samples")).json()
        req = data["samples"]["anthropic"]["request_body"]
        assert "messages" in req
        content = req["messages"][0]["content"]
        assert isinstance(content, str)
        assert len(content) > 20

    async def test_openai_sample_has_system_message(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/tester/samples")).json()
        req = data["samples"]["openai"]["request_body"]
        assert "messages" in req
        roles = [m["role"] for m in req["messages"]]
        assert "system" in roles

    async def test_response_samples_have_tokens(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/tester/samples")).json()
        for provider in ["anthropic", "openai"]:
            resp_body = data["samples"][provider]["response_body"]
            resp_str = json.dumps(resp_body)
            assert "REDACTED_" in resp_str


# ---------------------------------------------------------------------------
# Plugin repository & pipeline instance management tests
# ---------------------------------------------------------------------------


class TestPluginRepository:
    """Tests for GET /api/plugin-repository endpoint."""

    async def test_returns_builtin_plugins(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/plugin-repository")
        assert resp.status_code == 200
        data = resp.json()
        assert "plugins" in data
        names = [p["name"] for p in data["plugins"]]
        # All builtin plugin types should appear
        for builtin in ["whitelist", "presidio", "regex", "file_path"]:
            assert builtin in names

    async def test_builtin_entries_have_required_fields(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/plugin-repository")
        data = resp.json()
        for entry in data["plugins"]:
            assert "name" in entry
            assert "display_name" in entry
            assert "type" in entry
            assert "description" in entry
            assert "config_schema" in entry
            assert "instances_in_pipeline" in entry
            assert entry["type"] in ("builtin", "user")

    async def test_instances_in_pipeline_counts(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/plugin-repository")
        data = resp.json()
        by_name = {p["name"]: p for p in data["plugins"]}
        # presidio and regex are in default mock pipeline
        assert by_name["presidio"]["instances_in_pipeline"] >= 1
        assert by_name["regex"]["instances_in_pipeline"] >= 1

    async def test_user_plugins_appear(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/plugin-repository")
        data = resp.json()
        names = [p["name"] for p in data["plugins"]]
        assert "custom_detector" in names
        user_entry = [p for p in data["plugins"] if p["name"] == "custom_detector"][0]
        assert user_entry["type"] == "user"


class TestPluginsAPI:
    async def test_toggle_persists_enabled_state(self, client: AsyncClient, app: FastAPI) -> None:
        """Toggling a plugin's enabled state persists across re-fetches."""
        # presidio is in the mock pipeline and starts enabled
        resp = await client.put("/ui/api/plugins/presidio/toggle", json={"enabled": False})
        assert resp.status_code == 200

        # Re-fetch plugins — presidio should now be disabled
        resp = await client.get("/ui/api/plugins")
        plugins = resp.json()["plugins"]
        presidio = next(p for p in plugins if p["name"] == "presidio")
        assert presidio["enabled"] is False


class TestPipelineAdd:
    """Tests for POST /api/pipeline/add endpoint."""

    async def test_add_builtin_plugin(self, client: AsyncClient, app: FastAPI) -> None:
        resp = await client.post("/ui/api/pipeline/add", json={
            "plugin_name": "whitelist",
            "instance_name": "whitelist_2",
            "config": {},
        })
        assert resp.status_code == 201
        data = resp.json()
        assert "plugin" in data
        assert data["plugin"]["name"] == "whitelist_2"
        # Verify it was actually added to pipeline
        names = [getattr(s, "name", "") for s in app.state.pipeline.stages]
        assert "whitelist_2" in names

    async def test_add_whitelist_creates_independent_file_config(self, tmp_path) -> None:
        import yaml

        from scruxy.config.models import PipelineStageConfig

        wl_path = tmp_path / "whitelist.yaml"
        wl_path.write_text("whitelist:\n  - Claude\n", encoding="utf-8")

        app = _make_app()
        app.state.config.pipeline.stages = [
            PipelineStageConfig(
                name="whitelist",
                stage_type="whitelist",
                config={"whitelist_file": str(wl_path)},
            )
        ]

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/pipeline/add", json={
                "plugin_name": "whitelist",
                "instance_name": "team_whitelist",
                "config": {},
            })

        assert resp.status_code == 201
        plugin = resp.json()["plugin"]
        assert plugin["display_name"] == "Team Whitelist"
        assert plugin["config"]["whitelist_file"] != str(wl_path)

        copied_path = Path(plugin["config"]["whitelist_file"]).expanduser()
        assert copied_path.exists()
        copied_data = yaml.safe_load(copied_path.read_text(encoding="utf-8"))
        assert copied_data["whitelist"] == ["Claude"]

    async def test_add_with_missing_plugin_name(self, client: AsyncClient) -> None:
        resp = await client.post("/ui/api/pipeline/add", json={
            "instance_name": "test_instance",
        })
        assert resp.status_code == 400
        assert "plugin_name" in resp.json()["error"]

    async def test_add_with_missing_instance_name(self, client: AsyncClient) -> None:
        resp = await client.post("/ui/api/pipeline/add", json={
            "plugin_name": "regex",
        })
        assert resp.status_code == 400
        assert "instance_name" in resp.json()["error"]

    async def test_add_duplicate_instance_name(self, client: AsyncClient) -> None:
        resp = await client.post("/ui/api/pipeline/add", json={
            "plugin_name": "regex",
            "instance_name": "presidio",  # already exists
        })
        assert resp.status_code == 409

    async def test_add_unknown_plugin(self, client: AsyncClient) -> None:
        resp = await client.post("/ui/api/pipeline/add", json={
            "plugin_name": "nonexistent_plugin",
            "instance_name": "test_instance",
        })
        assert resp.status_code == 404

    async def test_add_with_config(self, client: AsyncClient, app: FastAPI) -> None:
        resp = await client.post("/ui/api/pipeline/add", json={
            "plugin_name": "regex",
            "instance_name": "regex_custom",
            "config": {"patterns_file": "~/.scruxy/test_patterns.yaml"},
        })
        assert resp.status_code == 201
        # Verify instance was appended at end
        last_stage = app.state.pipeline.stages[-1]
        assert getattr(last_stage, "name", "") == "regex_custom"


class TestPipelineRemove:
    """Tests for DELETE /api/pipeline/{instance_name} endpoint."""

    async def test_remove_existing_stage(self, client: AsyncClient, app: FastAPI) -> None:
        # First add a stage to remove
        await client.post("/ui/api/pipeline/add", json={
            "plugin_name": "whitelist",
            "instance_name": "whitelist_to_remove",
            "config": {},
        })
        names_before = [getattr(s, "name", "") for s in app.state.pipeline.stages]
        assert "whitelist_to_remove" in names_before

        resp = await client.delete("/ui/api/pipeline/whitelist_to_remove")
        assert resp.status_code == 200
        names_after = [getattr(s, "name", "") for s in app.state.pipeline.stages]
        assert "whitelist_to_remove" not in names_after

    async def test_remove_nonexistent(self, client: AsyncClient) -> None:
        resp = await client.delete("/ui/api/pipeline/nonexistent_stage")
        assert resp.status_code == 404

    async def test_remove_does_not_affect_other_stages(self, client: AsyncClient, app: FastAPI) -> None:
        count_before = len(app.state.pipeline.stages)
        await client.post("/ui/api/pipeline/add", json={
            "plugin_name": "regex",
            "instance_name": "regex_temp",
            "config": {},
        })
        assert len(app.state.pipeline.stages) == count_before + 1
        await client.delete("/ui/api/pipeline/regex_temp")
        assert len(app.state.pipeline.stages) == count_before


class TestPipelineDuplicate:
    """Tests for POST /api/pipeline/duplicate/{instance_name} endpoint."""

    async def test_duplicate_builtin_stage(self, client: AsyncClient, app: FastAPI) -> None:
        resp = await client.post("/ui/api/pipeline/duplicate/presidio")
        assert resp.status_code == 201
        data = resp.json()
        assert "plugin" in data
        assert data["plugin"]["name"] == "presidio_copy"
        # Should be inserted right after presidio
        names = [getattr(s, "name", "") for s in app.state.pipeline.stages]
        presidio_idx = names.index("presidio")
        assert names[presidio_idx + 1] == "presidio_copy"

    async def test_duplicate_generates_unique_names(self, client: AsyncClient, app: FastAPI) -> None:
        # First add a stage named "regex_copy" to force _copy2
        await client.post("/ui/api/pipeline/add", json={
            "plugin_name": "regex",
            "instance_name": "regex_copy",
            "config": {},
        })
        resp = await client.post("/ui/api/pipeline/duplicate/regex")
        assert resp.status_code == 201
        data = resp.json()
        assert data["plugin"]["name"] == "regex_copy2"

    async def test_duplicate_nonexistent(self, client: AsyncClient) -> None:
        resp = await client.post("/ui/api/pipeline/duplicate/nonexistent_stage")
        assert resp.status_code == 404

    async def test_duplicate_preserves_original(self, client: AsyncClient, app: FastAPI) -> None:
        stages_before = [getattr(s, "name", "") for s in app.state.pipeline.stages]
        resp = await client.post("/ui/api/pipeline/duplicate/regex")
        assert resp.status_code == 201
        stages_after = [getattr(s, "name", "") for s in app.state.pipeline.stages]
        # Original must still be there
        assert "regex" in stages_after
        # Count should have increased by 1
        assert len(stages_after) == len(stages_before) + 1


class TestTesterRunAPI:
    """Tests for POST /ui/api/tester/run."""

    async def test_run_returns_expected_structure(self, client: AsyncClient) -> None:
        resp = await client.post("/ui/api/tester/run", json={
            "provider": "anthropic",
            "request_body": {"messages": [{"role": "user", "content": "Hello world"}]},
            "response_body": {},
            "request_text_paths": ["$.messages[*].content"],
            "response_text_paths": [],
            "stages": {},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "scrubbed_request" in data
        assert "unscrubbed_response" in data
        assert "entities" in data
        assert "token_map" in data
        assert "latency_ms" in data
        assert "stages_run" in data

    async def test_run_missing_request_body_returns_400(self, client: AsyncClient) -> None:
        resp = await client.post("/ui/api/tester/run", json={
            "provider": "anthropic",
            "response_body": {},
            "request_text_paths": [],
            "response_text_paths": [],
        })
        assert resp.status_code == 400

    async def test_run_invalid_json_returns_400(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/ui/api/tester/run",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400

    async def test_run_no_pipeline_returns_500(self) -> None:
        app = _make_app()
        del app.state.pipeline
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/tester/run", json={
                "provider": "anthropic",
                "request_body": {"messages": [{"role": "user", "content": "hello"}]},
                "response_body": {},
                "request_text_paths": ["$.messages[*].content"],
                "response_text_paths": [],
                "stages": {},
            })
            assert resp.status_code == 500

    async def test_run_stage_overrides_all_disabled(self, client: AsyncClient) -> None:
        resp = await client.post("/ui/api/tester/run", json={
            "provider": "anthropic",
            "request_body": {"messages": [{"role": "user", "content": "test"}]},
            "response_body": {},
            "request_text_paths": ["$.messages[*].content"],
            "response_text_paths": [],
            "stages": {"presidio": False, "regex": False, "plugins": False},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["stages_run"] == []
        assert data["entities"] == []

    async def test_run_empty_text_paths(self, client: AsyncClient) -> None:
        resp = await client.post("/ui/api/tester/run", json={
            "provider": "anthropic",
            "request_body": {"messages": [{"role": "user", "content": "Sarah Johnson"}]},
            "response_body": {},
            "request_text_paths": [],
            "response_text_paths": [],
            "stages": {},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["entities"] == []
        assert data["scrubbed_request"]["messages"][0]["content"] == "Sarah Johnson"

    async def test_tester_page_loads(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/tester")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]


class TestNoCacheHeaders:

    async def test_dashboard_no_cache(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/")
        assert "no-store" in resp.headers.get("cache-control", "")

    async def test_sub_page_no_cache(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/plugins")
        assert "no-store" in resp.headers.get("cache-control", "")


# ---------------------------------------------------------------------------
# Static files test
# ---------------------------------------------------------------------------

class TestStaticFiles:

    async def test_css_file(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/static/css/styles.css")
        assert resp.status_code == 200
        assert "text/css" in resp.headers["content-type"]

    async def test_js_shared(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/static/js/shared.js")
        assert resp.status_code == 200
        assert "javascript" in resp.headers["content-type"]

    async def test_js_dashboard(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/static/js/dashboard.js")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Plugin hot-reload tests
# ---------------------------------------------------------------------------


class TestPluginHotReload:
    """Verify that create/save/delete trigger hot-reload of user plugins."""

    async def test_create_triggers_reload(self, tmp_path) -> None:
        """After creating a plugin, load_plugins is called."""
        reload_called = []

        def mock_load():
            reload_called.append(True)

        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir
        # Wire mock load_plugins onto the PluginStage
        plugin_stage = app.state.pipeline.stages[2]
        plugin_stage.load_plugins = mock_load

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/plugins/create", json={"name": "my_detector"})
            assert resp.status_code == 201
        assert len(reload_called) == 1

    async def test_save_source_triggers_reload(self, tmp_path) -> None:
        """After saving plugin source, load_plugins is called."""
        reload_called = []

        def mock_load():
            reload_called.append(True)

        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        (tmp_path / "plugins").mkdir()
        (tmp_path / "plugins" / "my_detector.py").write_text("# old source")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir
        plugin_stage = app.state.pipeline.stages[2]
        plugin_stage.load_plugins = mock_load

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put("/ui/api/plugins/my_detector/source", json={"source": "# new source"})
            assert resp.status_code == 200
        assert len(reload_called) == 1

    async def test_delete_triggers_reload(self, tmp_path) -> None:
        """After deleting a plugin, load_plugins is called."""
        reload_called = []

        def mock_load():
            reload_called.append(True)

        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        (tmp_path / "plugins").mkdir()
        (tmp_path / "plugins" / "old_plugin.py").write_text("# content")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir
        plugin_stage = app.state.pipeline.stages[2]
        plugin_stage.load_plugins = mock_load

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.delete("/ui/api/plugins/old_plugin")
            assert resp.status_code == 200
        assert len(reload_called) == 1

    async def test_reload_failure_does_not_crash_endpoint(self, tmp_path) -> None:
        """If load_plugins raises, the create still succeeds."""
        def failing_load():
            raise RuntimeError("boom")

        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir
        plugin_stage = app.state.pipeline.stages[2]
        plugin_stage.load_plugins = failing_load

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/plugins/create", json={"name": "test_plugin"})
            assert resp.status_code == 201
            assert (tmp_path / "plugins" / "test_plugin.py").exists()

    async def test_reload_failure_restores_old_plugins(self, tmp_path) -> None:
        """If reload fails, old plugin list is restored."""
        def failing_load():
            raise RuntimeError("boom")

        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir
        plugin_stage = app.state.pipeline.stages[2]
        original_plugins = list(plugin_stage._plugins)
        plugin_stage.load_plugins = failing_load

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            await c.post("/ui/api/plugins/create", json={"name": "test_plugin"})
        # Plugins should be restored after failed reload
        assert len(plugin_stage._plugins) == len(original_plugins)


class TestPluginTemplate:
    """Verify the generated plugin template is valid."""

    def test_template_is_valid_python(self) -> None:
        from scruxy.ui.routes import _PLUGIN_TEMPLATE
        content = _PLUGIN_TEMPLATE.format(
            name="test_pii",
            class_name="TestPiiDetector",
            display_name="Test Pii",
            entity_type="TEST_PII",
        )
        # Should not raise SyntaxError
        compile(content, "<template>", "exec")


class TestPluginNameValidation:
    """Verify name validation on source update and delete endpoints."""

    async def test_source_update_rejects_invalid_name(self, tmp_path) -> None:
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put("/ui/api/plugins/..evil/source", json={"source": "evil"})
            assert resp.status_code == 400

    async def test_delete_rejects_invalid_name(self, tmp_path) -> None:
        app = _make_app()
        plugin_dir = str(tmp_path / "plugins")
        app.state.config.pipeline.stages[4].config["plugin_dir"] = plugin_dir

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.delete("/ui/api/plugins/123bad")
            assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Plugin display_name rename
# ---------------------------------------------------------------------------


class TestPluginRename:
    """Tests for PUT /api/plugins/{plugin_name}/display_name endpoint."""

    async def test_rename_existing_stage(self, client: AsyncClient, app: FastAPI) -> None:
        resp = await client.put("/ui/api/plugins/whitelist/display_name", json={
            "display_name": "My Custom Whitelist",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["display_name"] == "My Custom Whitelist"
        # Verify it was persisted in config
        for stage_cfg in app.state.config.pipeline.stages:
            if stage_cfg.name == "whitelist":
                assert stage_cfg.display_name == "My Custom Whitelist"
                break

    async def test_rename_nonexistent_stage(self, client: AsyncClient) -> None:
        resp = await client.put("/ui/api/plugins/nonexistent/display_name", json={
            "display_name": "Test",
        })
        assert resp.status_code == 404

    async def test_rename_empty_display_name(self, client: AsyncClient) -> None:
        resp = await client.put("/ui/api/plugins/whitelist/display_name", json={
            "display_name": "",
        })
        assert resp.status_code == 400
        assert "empty" in resp.json()["error"].lower()

    async def test_rename_missing_display_name(self, client: AsyncClient) -> None:
        resp = await client.put("/ui/api/plugins/whitelist/display_name", json={})
        assert resp.status_code == 400

    async def test_rename_invalid_json(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/ui/api/plugins/whitelist/display_name",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400

    async def test_rename_reflected_in_plugin_serialization(self, client: AsyncClient) -> None:
        # Set a custom display name
        await client.put("/ui/api/plugins/presidio/display_name", json={
            "display_name": "Custom Presidio Name",
        })
        # Fetch plugins list and check the display_name is used
        resp = await client.get("/ui/api/plugins")
        assert resp.status_code == 200
        plugins = resp.json()["plugins"]
        presidio = next(p for p in plugins if p["name"] == "presidio")
        assert presidio["display_name"] == "Custom Presidio Name"


class TestPluginFileRename:
    """Tests for PUT /api/plugins/{name}/file/{field}/rename endpoint."""

    async def test_rename_whitelist_file(self, tmp_path) -> None:
        import yaml
        from scruxy.config.models import PipelineStageConfig

        wl_path = tmp_path / "whitelist.yaml"
        wl_path.write_text("whitelist:\n  - Claude\n", encoding="utf-8")

        app = _make_app()
        app.state.config.pipeline.stages = [
            PipelineStageConfig(
                name="whitelist",
                stage_type="whitelist",
                config={"whitelist_file": str(wl_path)},
            )
        ]

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            new_path = str(tmp_path / "team_whitelist.yaml")
            resp = await c.put(
                "/ui/api/plugins/whitelist/file/whitelist_file/rename",
                json={"new_path": new_path},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["new_path"] == new_path

        # Old file should be gone, new file should exist with same content
        assert not wl_path.exists()
        new_file = Path(new_path)
        assert new_file.exists()
        assert yaml.safe_load(new_file.read_text())["whitelist"] == ["Claude"]

        # Config should reference the new path
        cfg = app.state.config.pipeline.stages[0].config
        assert cfg["whitelist_file"] == new_path

    async def test_rename_missing_new_path(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/ui/api/plugins/presidio/file/patterns_file/rename",
            json={"new_path": ""},
        )
        assert resp.status_code == 400

    async def test_rename_nonexistent_stage(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/ui/api/plugins/nonexistent/file/whitelist_file/rename",
            json={"new_path": "/tmp/x.yaml"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Whitelist instances endpoint
# ---------------------------------------------------------------------------


class TestWhitelistInstances:
    """Tests for GET /api/whitelist/instances endpoint."""

    async def test_returns_default_whitelist_instance(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/whitelist/instances")
        assert resp.status_code == 200
        data = resp.json()
        instances = data["instances"]
        assert len(instances) >= 1
        assert instances[0]["name"] == "whitelist"
        assert instances[0]["display_name"]  # should have a non-empty display name

    async def test_returns_multiple_instances(self, client: AsyncClient, app: FastAPI) -> None:
        from scruxy.config.models import PipelineStageConfig
        # Add a second whitelist stage to config
        app.state.config.pipeline.stages.append(
            PipelineStageConfig(
                name="whitelist_copy",
                display_name="Word Boundary Whitelist",
                config={"whitelist_file": "~/.scruxy/whitelist_2.yaml"},
            )
        )
        resp = await client.get("/ui/api/whitelist/instances")
        assert resp.status_code == 200
        instances = resp.json()["instances"]
        names = [inst["name"] for inst in instances]
        assert "whitelist" in names
        assert "whitelist_copy" in names
        # Custom display name should be used
        wl_copy = next(i for i in instances if i["name"] == "whitelist_copy")
        assert wl_copy["display_name"] == "Word Boundary Whitelist"

    async def test_disabled_whitelist_excluded(self, client: AsyncClient, app: FastAPI) -> None:
        from scruxy.config.models import PipelineStageConfig
        app.state.config.pipeline.stages.append(
            PipelineStageConfig(
                name="whitelist_disabled",
                enabled=False,
                config={"whitelist_file": "~/.scruxy/whitelist_disabled.yaml"},
            )
        )
        resp = await client.get("/ui/api/whitelist/instances")
        instances = resp.json()["instances"]
        names = [inst["name"] for inst in instances]
        assert "whitelist_disabled" not in names


# ---------------------------------------------------------------------------
# Whitelist add with stage_name targeting
# ---------------------------------------------------------------------------


class TestWhitelistAddTargeted:
    """Tests for POST /api/whitelist/add with stage_name parameter."""

    async def test_add_to_specific_whitelist(self, tmp_path) -> None:
        """Adding to a specific whitelist by stage_name writes to the correct file."""
        from scruxy.config.models import PipelineStageConfig

        wl1_path = tmp_path / "whitelist.yaml"
        wl2_path = tmp_path / "whitelist_2.yaml"
        wl1_path.write_text("whitelist:\n  - Claude\n", encoding="utf-8")
        wl2_path.write_text("whitelist:\n  - OpenAI\n", encoding="utf-8")

        app = _make_app()
        config = app.state.config
        # Replace default whitelist config with test paths
        config.pipeline.stages[0] = PipelineStageConfig(
            name="whitelist",
            config={"whitelist_file": str(wl1_path)},
        )
        config.pipeline.stages.append(
            PipelineStageConfig(
                name="whitelist_copy",
                config={"whitelist_file": str(wl2_path)},
            )
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/whitelist/add", json={
                "term": "TestTerm",
                "stage_name": "whitelist_copy",
            })
            assert resp.status_code == 200
            assert resp.json()["added"] is True

        # Verify the term was added to whitelist_2.yaml, NOT whitelist.yaml
        import yaml
        wl1_data = yaml.safe_load(wl1_path.read_text(encoding="utf-8"))
        wl2_data = yaml.safe_load(wl2_path.read_text(encoding="utf-8"))
        assert "TestTerm" not in wl1_data.get("whitelist", [])
        assert "TestTerm" in wl2_data.get("whitelist", [])

    async def test_add_without_stage_name_uses_first(self, tmp_path) -> None:
        """Without stage_name, the term goes to the first whitelist (backward compat)."""
        from scruxy.config.models import PipelineStageConfig

        wl_path = tmp_path / "whitelist.yaml"
        wl_path.write_text("whitelist:\n  - Claude\n", encoding="utf-8")

        app = _make_app()
        config = app.state.config
        config.pipeline.stages[0] = PipelineStageConfig(
            name="whitelist",
            config={"whitelist_file": str(wl_path)},
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/whitelist/add", json={"term": "NewTerm"})
            assert resp.status_code == 200

        import yaml
        data = yaml.safe_load(wl_path.read_text(encoding="utf-8"))
        assert "NewTerm" in data["whitelist"]


# ---------------------------------------------------------------------------
# Duplicate with file-backed config persistence
# ---------------------------------------------------------------------------


class TestDuplicateFilePersistence:
    """Tests for POST /api/pipeline/duplicate with file-backed plugins."""

    async def test_duplicate_whitelist_gets_unique_file(self, tmp_path) -> None:
        """Duplicating a whitelist stage generates a new config file path."""
        from scruxy.config.models import PipelineStageConfig

        wl_path = tmp_path / "whitelist.yaml"
        wl_path.write_text("whitelist:\n  - Claude\n  - Anthropic\n", encoding="utf-8")

        # Build a mock whitelist plugin
        MockWhitelist = type("WhitelistPlugin", (), {
            "name": "whitelist",
            "plugin_type": "builtin",
            "version": "built-in",
            "enabled": True,
            "description": "",
            "config_schema": [],
        })

        app = _make_app()
        config = app.state.config
        config.pipeline.stages[0] = PipelineStageConfig(
            name="whitelist",
            config={"whitelist_file": str(wl_path)},
        )
        # Insert whitelist mock as first pipeline stage
        wl_mock = MockWhitelist()
        app.state.pipeline.stages.insert(0, wl_mock)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/pipeline/duplicate/whitelist")
            assert resp.status_code == 201

        data = resp.json()
        assert data["plugin"]["name"] == "whitelist_copy"

        # Verify the new config stage has a different whitelist_file
        copy_stage = None
        for sc in config.pipeline.stages:
            if sc.name == "whitelist_copy":
                copy_stage = sc
                break
        assert copy_stage is not None
        new_file = copy_stage.config.get("whitelist_file", "")
        assert new_file != str(wl_path)
        assert "whitelist_2" in new_file

        # Verify the new file was created with same contents
        new_fp = Path(new_file).expanduser()
        assert new_fp.exists()
        import yaml
        new_data = yaml.safe_load(new_fp.read_text(encoding="utf-8"))
        assert "Claude" in new_data.get("whitelist", [])
        assert "Anthropic" in new_data.get("whitelist", [])

    async def test_duplicate_persists_config(self, tmp_path) -> None:
        """Duplicating a stage persists the new stage to config.yaml."""
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/pipeline/duplicate/presidio")
            assert resp.status_code == 201

        # Verify config was persisted to disk
        assert config_path.exists()
        import yaml
        saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        saved_stage = next(s for s in saved["pipeline"]["stages"] if s["name"] == "presidio_copy")
        assert saved_stage["stage_type"] == "presidio"


# ---------------------------------------------------------------------------
# Pipeline add/remove persistence
# ---------------------------------------------------------------------------


class TestPipelineAddPersistence:
    """Tests that add and remove endpoints persist config changes."""

    async def test_add_persists_config(self, tmp_path) -> None:
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/pipeline/add", json={
                "plugin_name": "regex",
                "instance_name": "regex_custom",
                "config": {},
            })
            assert resp.status_code == 201

        import yaml
        saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        saved_stage = next(s for s in saved["pipeline"]["stages"] if s["name"] == "regex_custom")
        assert saved_stage["stage_type"] == "regex"

    async def test_add_whitelist_uses_async_file_io(self, tmp_path) -> None:
        from scruxy.config.models import PipelineStageConfig
        import yaml

        wl_path = tmp_path / "whitelist.yaml"
        wl_path.write_text("whitelist:\n  - Claude\n", encoding="utf-8")

        app = _make_app()
        app.state.config.pipeline.stages[0] = PipelineStageConfig(
            name="whitelist",
            stage_type="whitelist",
            config={"whitelist_file": str(wl_path)},
        )

        async def tracking_to_thread(func, *args, **kwargs):
            tracking_to_thread.calls.append(getattr(func, "__name__", repr(func)))
            return func(*args, **kwargs)

        tracking_to_thread.calls = []

        transport = ASGITransport(app=app)
        with patch("scruxy.ui.routes.asyncio.to_thread", side_effect=tracking_to_thread):
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.post("/ui/api/whitelist/add", json={"term": "NewTerm"})

        assert resp.status_code == 200
        assert "read_text" in tracking_to_thread.calls
        assert "_write_text_atomically" in tracking_to_thread.calls
        data = yaml.safe_load(wl_path.read_text(encoding="utf-8"))
        assert "NewTerm" in data["whitelist"]

    async def test_duplicate_file_copy_uses_async_file_io(self, tmp_path) -> None:
        from scruxy.config.models import PipelineStageConfig

        wl_path = tmp_path / "whitelist.yaml"
        wl_path.write_text("whitelist:\n  - Claude\n", encoding="utf-8")

        MockWhitelist = type("WhitelistPlugin", (), {
            "name": "whitelist",
            "plugin_type": "builtin",
            "version": "built-in",
            "enabled": True,
            "description": "",
            "config_schema": [],
            "setup": lambda self, config: None,
        })
        pipeline = SimpleNamespace(stages=[MockWhitelist()])
        pipeline.stages[0].name = "whitelist"

        app = _make_app(pipeline=pipeline)
        app.state.config.pipeline.stages = [
            PipelineStageConfig(
                name="whitelist",
                stage_type="whitelist",
                config={"whitelist_file": str(wl_path)},
            )
        ]

        async def tracking_to_thread(func, *args, **kwargs):
            tracking_to_thread.calls.append(getattr(func, "__name__", repr(func)))
            return func(*args, **kwargs)

        tracking_to_thread.calls = []

        transport = ASGITransport(app=app)
        with patch("scruxy.ui.routes.asyncio.to_thread", side_effect=tracking_to_thread):
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.post("/ui/api/pipeline/duplicate/whitelist")

        assert resp.status_code == 201
        assert "copy2" in tracking_to_thread.calls

    async def test_remove_persists_config(self, tmp_path) -> None:
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # Add then remove
            await c.post("/ui/api/pipeline/add", json={
                "plugin_name": "regex",
                "instance_name": "regex_to_remove",
                "config": {},
            })
            resp = await c.delete("/ui/api/pipeline/regex_to_remove")
            assert resp.status_code == 200

        import yaml
        saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        stage_names = [s["name"] for s in saved["pipeline"]["stages"]]
        assert "regex_to_remove" not in stage_names


# ---------------------------------------------------------------------------
# display_name in config model
# ---------------------------------------------------------------------------


class TestDisplayNameModel:
    """Tests for display_name field on PipelineStageConfig."""

    def test_default_display_name_is_empty(self) -> None:
        from scruxy.config.models import PipelineStageConfig
        stage = PipelineStageConfig(name="test_stage")
        assert stage.display_name == ""

    def test_display_name_set_explicitly(self) -> None:
        from scruxy.config.models import PipelineStageConfig
        stage = PipelineStageConfig(name="whitelist", display_name="My Whitelist")
        assert stage.display_name == "My Whitelist"

    def test_display_name_survives_serialization(self) -> None:
        from scruxy.config.models import PipelineStageConfig
        stage = PipelineStageConfig(name="whitelist", display_name="Custom Name")
        data = stage.model_dump()
        restored = PipelineStageConfig.model_validate(data)
        assert restored.display_name == "Custom Name"

    def test_display_name_backward_compat(self) -> None:
        """Config without display_name should load fine (uses default empty string)."""
        from scruxy.config.models import PipelineStageConfig
        stage = PipelineStageConfig.model_validate({"name": "whitelist", "enabled": True, "config": {}})
        assert stage.display_name == ""


# ---------------------------------------------------------------------------
# Unique file path generation
# ---------------------------------------------------------------------------


class TestUniqueFilePath:
    """Tests for _generate_unique_file_path helper."""

    def test_first_copy(self, tmp_path) -> None:
        from scruxy.ui.routes import _generate_unique_file_path
        base = str(tmp_path / "whitelist.yaml")
        result = _generate_unique_file_path(base, set())
        assert result == str(tmp_path / "whitelist_2.yaml")

    def test_skips_existing(self, tmp_path) -> None:
        from scruxy.ui.routes import _generate_unique_file_path
        base = str(tmp_path / "whitelist.yaml")
        existing = {str(tmp_path / "whitelist_2.yaml")}
        result = _generate_unique_file_path(base, existing)
        assert result != str(tmp_path / "whitelist.yaml")
        assert result not in existing
        assert result.endswith(".yaml")

    def test_multiple_existing(self, tmp_path) -> None:
        from scruxy.ui.routes import _generate_unique_file_path
        base = str(tmp_path / "whitelist.yaml")
        existing = {
            str(tmp_path / "whitelist_2.yaml"),
            str(tmp_path / "whitelist_3.yaml"),
        }
        result = _generate_unique_file_path(base, existing)
        assert result != str(tmp_path / "whitelist.yaml")
        assert result not in existing
        assert result.endswith(".yaml")

    def test_many_existing_still_generates_unique_path(self, tmp_path) -> None:
        from scruxy.ui.routes import _generate_unique_file_path
        base = str(tmp_path / "regex_patterns.yaml")
        existing = {
            str(tmp_path / f"regex_patterns_{i}.yaml")
            for i in range(2, 2005)
        }
        result = _generate_unique_file_path(base, existing)
        assert result not in existing
        assert result.endswith(".yaml")


class TestSettingsJavascript:
    """Static regressions for the settings page save/selection logic."""

    def test_recording_save_fields_include_store_body_original(self) -> None:
        js = (_REPO_ROOT / "src" / "scruxy" / "ui" / "static" / "js" / "settings.js").read_text(encoding="utf-8")
        assert '{ key: "store_body_original", type: "toggle" }' in js

    def test_interception_mode_selector_no_longer_offers_mitmproxy(self) -> None:
        js = (_REPO_ROOT / "src" / "scruxy" / "ui" / "static" / "js" / "settings.js").read_text(encoding="utf-8")
        start = js.index('renderSelect(container, "interception-mode"')
        end = js.index('renderTextInput(container, "interception-listen_host"', start)
        assert '"mitmproxy"' not in js[start:end]

    def test_interception_mode_selector_preserves_loaded_legacy_value(self) -> None:
        js = (_REPO_ROOT / "src" / "scruxy" / "ui" / "static" / "js" / "settings.js").read_text(encoding="utf-8")
        assert 'modeOptions.indexOf(data.mode) === -1' in js
        assert "unsupported legacy value" in js
