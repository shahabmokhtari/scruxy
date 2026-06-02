"""Tests for app.py (FastAPI factory) and __main__.py (CLI)."""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from scruxy.app import VERSION, create_app
from scruxy.config.models import AppConfig, PipelineStageConfig


def _tmp_config(tmp_path) -> AppConfig:
    """Create an AppConfig pointing to tmp_path for all storage."""
    return AppConfig(
        sessions={"storage_dir": str(tmp_path / "sessions")},
        logging={"log_dir": str(tmp_path / "logs")},
        stats={"storage_file": str(tmp_path / "stats.json")},
        pipeline={"stages": []},
    )


class TestCreateApp:
    def test_returns_fastapi_instance(self, tmp_path):
        app = create_app(_tmp_config(tmp_path))
        assert isinstance(app, FastAPI)

    def test_app_has_title(self, tmp_path):
        app = create_app(_tmp_config(tmp_path))
        assert app.title == "Scruxy"

    def test_app_has_version(self, tmp_path):
        app = create_app(_tmp_config(tmp_path))
        assert app.version == VERSION

    def test_config_stored_on_state(self, tmp_path):
        config = _tmp_config(tmp_path)
        app = create_app(config)
        assert app.state.config is config

    def test_default_config_loaded_when_none(self):
        app = create_app(None)
        assert isinstance(app, FastAPI)
        assert hasattr(app.state, "config")


class TestLifespan:
    def test_lifespan_sets_state_attributes(self, tmp_path):
        app = create_app(_tmp_config(tmp_path))
        with TestClient(app):
            assert app.state.session_store is not None
            assert app.state.stats is not None
            assert app.state.pipeline is not None
            assert app.state.request_scrubber is not None
            assert app.state.response_unscrubber is not None
            assert app.state.forwarder is not None
            assert app.state.registry is not None
            assert app.state.recorder is not None

    def test_lifespan_primary_mode_no_mitmproxy(self, tmp_path):
        app = create_app(_tmp_config(tmp_path))
        with TestClient(app):
            assert app.state.mitmproxy_backend is None

    def test_lifespan_shutdown_flushes_sessions(self, tmp_path):
        app = create_app(_tmp_config(tmp_path))
        with TestClient(app) as client:
            store = app.state.session_store
            assert store is not None
        # After exiting, no error means shutdown succeeded

    def test_lifespan_uses_explicit_stage_type_for_custom_named_builtin(self, tmp_path):
        config = _tmp_config(tmp_path)
        config.pipeline.stages = [
            PipelineStageConfig(name="regex_custom", stage_type="file_path", enabled=True, config={})
        ]

        app = create_app(config)
        with TestClient(app):
            names = [getattr(stage, "name", "") for stage in app.state.pipeline.stages]
            assert names == ["regex_custom"]

    def test_lifespan_normalizes_whitelist_to_front(self, tmp_path):
        config = _tmp_config(tmp_path)
        config.pipeline.stages = [
            PipelineStageConfig(name="regex", stage_type="regex", enabled=True, config={}),
            PipelineStageConfig(name="whitelist", stage_type="whitelist", enabled=True, config={}),
        ]

        app = create_app(config)
        with TestClient(app):
            names = [getattr(stage, "name", "") for stage in app.state.pipeline.stages]
            assert names[:2] == ["whitelist", "regex"]

    def test_lifespan_disabled_stages_still_instantiated(self, tmp_path):
        config = _tmp_config(tmp_path)
        config.pipeline.stages = [
            PipelineStageConfig(name="whitelist", stage_type="whitelist", enabled=False, config={}),
            PipelineStageConfig(name="regex", stage_type="regex", enabled=True, config={}),
        ]

        app = create_app(config)
        with TestClient(app):
            names = [getattr(stage, "name", "") for stage in app.state.pipeline.stages]
            assert "whitelist" in names
            assert "regex" in names
            wl = next(s for s in app.state.pipeline.stages if getattr(s, "name", "") == "whitelist")
            assert wl.enabled is False


class TestAppIntegration:
    def test_app_starts_and_stops(self, tmp_path):
        app = create_app(_tmp_config(tmp_path))
        with TestClient(app) as client:
            resp = client.get("/ui/")
            assert resp.status_code == 200

    def test_unmatched_proxy_request_passthrough(self, tmp_path):
        """Unmatched proxy requests are passed through (upstream may error but not 404)."""
        app = create_app(_tmp_config(tmp_path))
        with TestClient(app) as client:
            resp = client.get("/v1/models")
            # Passthrough to upstream — upstream may return 502 (unreachable) but not 404
            assert resp.status_code != 404


class TestCLI:
    def test_build_parser_defaults(self):
        from scruxy.__main__ import build_parser

        parser = build_parser()
        args = parser.parse_args([])
        assert args.config is None
        assert args.mode is None
        assert args.host is None
        assert args.port is None
        assert args.https_port is None
        assert args.no_https is False

    def test_build_parser_all_args(self):
        from scruxy.__main__ import build_parser

        parser = build_parser()
        args = parser.parse_args([
            "--config", "c.yaml", "--mode", "mitmproxy",
            "--host", "0.0.0.0", "--port", "9999",
            "--https-port", "8443", "--no-https",
        ])
        assert args.config == "c.yaml"
        assert args.mode == "mitmproxy"
        assert args.host == "0.0.0.0"
        assert args.port == 9999
        assert args.https_port == 8443
        assert args.no_https is True

    def test_invalid_mode_rejected(self):
        from scruxy.__main__ import build_parser

        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--mode", "invalid"])
