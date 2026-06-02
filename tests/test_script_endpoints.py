"""Tests for the script CRUD endpoints (GET/POST/PUT/DELETE /ui/api/scripts)."""
from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from scruxy.config.models import AppConfig
from scruxy.ui.routes import mount_static, router


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(**state_overrides: Any) -> FastAPI:
    """Build a minimal FastAPI app with the UI router and mocked app state."""
    app = FastAPI()
    app.include_router(router)
    mount_static(app)

    config = state_overrides.get("config", AppConfig())

    app.state.config = config
    app.state.config_path = state_overrides.get(
        "config_path", Path(tempfile.mkdtemp()) / "test_config.yaml"
    )
    app.state.stats = state_overrides.get("stats", SimpleNamespace(
        total_requests=0, total_entities=0, latency_history=[],
        recent_events=[], entities_by_type={}, requests_by_provider={},
        uptime_seconds=0, per_session={},
    ))
    app.state.session_store = state_overrides.get("session_store", SimpleNamespace(
        session_ids=[], sessions={}, get_token_map=lambda sid: None,
    ))
    app.state.recording = state_overrides.get("recording", SimpleNamespace(
        get_session_recordings=AsyncMock(return_value=[]),
        get_entries=AsyncMock(return_value=[]),
    ))
    app.state.pipeline = state_overrides.get("pipeline", SimpleNamespace(
        stages=[], plugins=[], scrub_text=AsyncMock(),
    ))
    app.state.providers = state_overrides.get("providers", SimpleNamespace(providers=[]))
    app.state.event_bus = state_overrides.get("event_bus", SimpleNamespace(subscribers=[]))
    app.state._listen_host = "localhost"

    return app


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScriptListEndpoint:
    """Tests for GET /ui/api/scripts."""

    async def test_list_empty_dir(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/ui/api/scripts")
                assert resp.status_code == 200
                assert resp.json()["scripts"] == []

    async def test_list_nonexistent_dir(self, tmp_path) -> None:
        scripts_dir = tmp_path / "nonexistent"
        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/ui/api/scripts")
                assert resp.status_code == 200
                assert resp.json()["scripts"] == []

    async def test_list_scripts(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "alpha.py").write_text("# alpha", encoding="utf-8")
        (scripts_dir / "beta.py").write_text("# beta", encoding="utf-8")
        (scripts_dir / "not_python.txt").write_text("nope", encoding="utf-8")

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/ui/api/scripts")
                assert resp.status_code == 200
                scripts = resp.json()["scripts"]
                assert "alpha.py" in scripts
                assert "beta.py" in scripts
                assert "not_python.txt" not in scripts


class TestScriptGetEndpoint:
    """Tests for GET /ui/api/scripts/{name}."""

    async def test_get_script(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "hello.py").write_text("print('hi')", encoding="utf-8")

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/ui/api/scripts/hello.py")
                assert resp.status_code == 200
                data = resp.json()
                assert data["name"] == "hello.py"
                assert "print('hi')" in data["content"]

    async def test_get_script_not_found(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/ui/api/scripts/missing.py")
                assert resp.status_code == 404

    async def test_get_script_invalid_name(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/ui/api/scripts/bad%20name!.py")
                assert resp.status_code == 400


class TestScriptCreateEndpoint:
    """Tests for POST /ui/api/scripts."""

    async def test_create_script(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.post(
                    "/ui/api/scripts",
                    json={"name": "my_script"},
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["name"] == "my_script.py"
                # Verify file was created with template
                assert (scripts_dir / "my_script.py").exists()

    async def test_create_script_with_extension(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.post(
                    "/ui/api/scripts",
                    json={"name": "my_script.py"},
                )
                assert resp.status_code == 200
                assert (scripts_dir / "my_script.py").exists()

    async def test_create_duplicate_returns_409(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "existing.py").write_text("# existing", encoding="utf-8")

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.post(
                    "/ui/api/scripts",
                    json={"name": "existing.py"},
                )
                assert resp.status_code == 409

    async def test_create_empty_name_returns_400(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.post(
                    "/ui/api/scripts",
                    json={"name": ""},
                )
                assert resp.status_code == 400


class TestScriptUpdateEndpoint:
    """Tests for PUT /ui/api/scripts/{name}."""

    async def test_update_script(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "target.py").write_text("# old", encoding="utf-8")

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.put(
                    "/ui/api/scripts/target.py",
                    json={"content": "# updated content"},
                )
                assert resp.status_code == 200
                assert (scripts_dir / "target.py").read_text(encoding="utf-8") == "# updated content"

    async def test_update_creates_new_file(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        # Don't create the dir — the endpoint should create it
        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.put(
                    "/ui/api/scripts/new.py",
                    json={"content": "# brand new"},
                )
                assert resp.status_code == 200
                assert (scripts_dir / "new.py").exists()

    async def test_update_missing_content_returns_400(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.put(
                    "/ui/api/scripts/test.py",
                    json={},
                )
                assert resp.status_code == 400

    async def test_update_invalid_name_returns_400(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.put(
                    "/ui/api/scripts/bad name!.py",
                    json={"content": "# bad"},
                )
                assert resp.status_code == 400


class TestScriptDeleteEndpoint:
    """Tests for DELETE /ui/api/scripts/{name}."""

    async def test_delete_script(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "doomed.py").write_text("# bye", encoding="utf-8")

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.delete("/ui/api/scripts/doomed.py")
                assert resp.status_code == 200
                assert not (scripts_dir / "doomed.py").exists()

    async def test_delete_nonexistent_returns_404(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.delete("/ui/api/scripts/ghost.py")
                assert resp.status_code == 404

    async def test_delete_invalid_name_returns_400(self, tmp_path) -> None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        with patch("scruxy.ui.routes._get_scripts_dir", return_value=scripts_dir):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.delete("/ui/api/scripts/bad%20name!.py")
                assert resp.status_code == 400


class TestNullDeletion:
    """Tests for null-deletion via PUT /ui/api/config (deep_merge fix)."""

    async def test_null_deletes_replacement_rule(self, tmp_path) -> None:
        """Sending a null value for a replacement rule removes it."""
        from scruxy.config.models import AppConfig, ReplacementConfig

        config = AppConfig()
        config.tokens.replacements = {
            "PERSON": ReplacementConfig(strategy="uuid"),
            "GUID": ReplacementConfig(strategy="default"),
        }

        app = _make_app(config=config)
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/config",
                json={"tokens": {"replacements": {"PERSON": None}}},
            )
            assert resp.status_code == 200
            data = resp.json()
            replacements = data["tokens"]["replacements"]
            assert "PERSON" not in replacements
            assert "GUID" in replacements

    async def test_null_on_nonexistent_key_is_noop(self, tmp_path) -> None:
        app = _make_app()
        config_path = tmp_path / "config.yaml"
        app.state.config_path = config_path

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.put(
                "/ui/api/config",
                json={"tokens": {"replacements": {"NONEXISTENT": None}}},
            )
            assert resp.status_code == 200


class TestTesterStateEndpoints:
    """Tests for GET/PUT /ui/api/tester/state."""

    async def test_get_empty_state(self, tmp_path) -> None:
        state_path = tmp_path / "tester_state.json"
        with patch("scruxy.ui.routes._get_tester_state_path", return_value=state_path):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/ui/api/tester/state")
                assert resp.status_code == 200
                assert resp.json() == {}

    async def test_put_and_get_state(self, tmp_path) -> None:
        state_path = tmp_path / "tester_state.json"
        state = {
            "provider": "anthropic",
            "request_body": '{"test": true}',
            "response_body": '{"ok": true}',
            "request_text_paths": "$.test",
            "response_text_paths": "$.ok",
        }
        with patch("scruxy.ui.routes._get_tester_state_path", return_value=state_path):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.put("/ui/api/tester/state", json=state)
                assert resp.status_code == 200

                resp = await c.get("/ui/api/tester/state")
                assert resp.status_code == 200
                data = resp.json()
                assert data["provider"] == "anthropic"
                assert data["request_body"] == '{"test": true}'

    async def test_put_invalid_json_returns_400(self, tmp_path) -> None:
        state_path = tmp_path / "tester_state.json"
        with patch("scruxy.ui.routes._get_tester_state_path", return_value=state_path):
            app = _make_app()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.put(
                    "/ui/api/tester/state",
                    content="not json",
                    headers={"Content-Type": "application/json"},
                )
                assert resp.status_code == 400


class TestSeedDefaultScripts:
    """Tests for _seed_default_scripts() in config/loader.py."""

    def test_seeds_all_scripts(self, tmp_path) -> None:
        from scruxy.config.loader import _seed_default_scripts, _DEFAULT_SCRIPTS

        scripts_dir = tmp_path / "scripts"
        _seed_default_scripts(scripts_dir)

        assert scripts_dir.exists()
        for filename in _DEFAULT_SCRIPTS:
            assert (scripts_dir / filename).exists()

    def test_does_not_overwrite_existing(self, tmp_path) -> None:
        from scruxy.config.loader import _seed_default_scripts

        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        # Pre-populate one script with custom content
        custom_content = "# my custom script"
        (scripts_dir / "simple_name.py").write_text(custom_content, encoding="utf-8")

        _seed_default_scripts(scripts_dir)

        # Custom content should be preserved
        assert (scripts_dir / "simple_name.py").read_text(encoding="utf-8") == custom_content

    def test_creates_directory(self, tmp_path) -> None:
        from scruxy.config.loader import _seed_default_scripts

        scripts_dir = tmp_path / "nonexistent" / "scripts"
        _seed_default_scripts(scripts_dir)
        assert scripts_dir.exists()
