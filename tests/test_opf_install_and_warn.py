"""Lifespan must warn when both Presidio and OpenAI Privacy Filter
stages are enabled in the pipeline (they cover the same PII categories
and running both wastes CPU)."""
from __future__ import annotations

import inspect
import sys
from unittest.mock import MagicMock

import pytest


def test_lifespan_source_emits_warning_for_dual_ner_stages() -> None:
    """The source must reference the dual-stage detection and the
    warning so future refactors don't quietly drop it."""
    from scruxy import app as app_mod

    src = inspect.getsource(app_mod)
    assert "_has_presidio and _has_opf" in src, (
        "lifespan must check whether both presidio AND opf are enabled"
    )
    assert "wastes CPU" in src or "covers the same PII" in src, (
        "lifespan must explain WHY the dual-enable is suboptimal"
    )


def test_default_pipeline_has_opf_stage_disabled() -> None:
    """The default ``PipelineConfig`` must include an
    ``openai_privacy_filter`` stage entry with ``enabled=False`` so the
    UI exposes it without auto-loading the heavy ML dependency."""
    from scruxy.config.models import AppConfig

    cfg = AppConfig()
    opf = [s for s in cfg.pipeline.stages if s.name == "openai_privacy_filter"]
    assert len(opf) == 1, (
        "default pipeline must contain exactly one openai_privacy_filter stage"
    )
    assert opf[0].enabled is False, (
        "openai_privacy_filter must default to disabled (heavy ML dep)"
    )
    assert opf[0].config.get("device") == "cpu"


def test_pyproject_declares_opf_optional_extra() -> None:
    """``pyproject.toml`` must declare an ``opf`` extra so users can
    install the optional dependency via ``pip install 'scruxy[opf]'``.
    """
    from pathlib import Path

    here = Path(__file__).resolve().parent.parent
    pyproject = (here / "pyproject.toml").read_text(encoding="utf-8")
    assert "opf = [" in pyproject, (
        "pyproject.toml must declare an [opf] extra under "
        "[project.optional-dependencies]"
    )
    # Upstream's distribution name is ``opf`` (the package directory),
    # not ``openai-privacy-filter``.  Either form would resolve at
    # install time, but uv hard-rejects the alias mismatch, so we
    # require the exact upstream name in the pyproject extra.
    assert "opf @ git+https://github.com/openai/privacy-filter" in pyproject
    # And direct references must be explicitly allowed for hatchling.
    assert "allow-direct-references = true" in pyproject


def test_readme_documents_opf_install_and_enable() -> None:
    """README must explain how to install and enable the OPF plugin
    so users discover the optional path."""
    from pathlib import Path

    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(
        encoding="utf-8",
    )
    assert "OpenAI Privacy Filter" in readme
    assert "[opf]" in readme, "README must show the install command"
    assert "openai_privacy_filter" in readme, "README must reference the stage name"
    assert "device: cpu" in readme, "README must show config example"


@pytest.mark.asyncio
async def test_install_endpoint_skips_when_already_installed(
    monkeypatch, tmp_path,
) -> None:
    """When ``opf`` is already importable, the install endpoint must
    return immediately without invoking pip."""
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from scruxy.ui import routes as ui_routes
    import importlib.util as _util

    # Stub find_spec to claim opf is present.
    real_find = _util.find_spec

    def _fake_find_spec(name):
        if name == "opf":
            return MagicMock()
        return real_find(name)

    monkeypatch.setattr(_util, "find_spec", _fake_find_spec)

    app = FastAPI()
    app.include_router(ui_routes.router)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/ui/api/plugins/openai_privacy_filter/install")
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("installed") is True
    assert body.get("already_installed") is True


@pytest.mark.asyncio
async def test_install_endpoint_runs_pip_when_missing(
    monkeypatch, tmp_path,
) -> None:
    """When ``opf`` is missing, the endpoint must dispatch a pip install
    via subprocess and surface the result."""
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from scruxy.ui import routes as ui_routes
    import importlib.util as _util
    import subprocess as _sub

    # Force find_spec to claim opf is missing.
    real_find = _util.find_spec
    monkeypatch.setattr(
        _util, "find_spec",
        lambda name: None if name == "opf" else real_find(name),
    )

    # Stub subprocess.run to avoid actually invoking pip.
    fake_run = MagicMock()
    fake_run.return_value = MagicMock(
        returncode=0, stdout="installed", stderr="",
    )
    monkeypatch.setattr(_sub, "run", fake_run)

    app = FastAPI()
    app.include_router(ui_routes.router)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/ui/api/plugins/openai_privacy_filter/install")
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("installed") is True
    assert body.get("restart_required") is True
    fake_run.assert_called_once()


@pytest.mark.asyncio
async def test_install_endpoint_surfaces_pip_failure(
    monkeypatch,
) -> None:
    """When ``pip install`` fails, the endpoint must return 500 with
    the captured pip output and a manual-install hint."""
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from scruxy.ui import routes as ui_routes
    import importlib.util as _util
    import subprocess as _sub

    real_find = _util.find_spec
    monkeypatch.setattr(
        _util, "find_spec",
        lambda name: None if name == "opf" else real_find(name),
    )

    fake_run = MagicMock()
    fake_run.return_value = MagicMock(
        returncode=1, stdout="", stderr="ERROR: synthetic failure",
    )
    monkeypatch.setattr(_sub, "run", fake_run)

    app = FastAPI()
    app.include_router(ui_routes.router)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/ui/api/plugins/openai_privacy_filter/install")
    assert resp.status_code == 500
    body = resp.json()
    assert body.get("installed") is False
    assert "synthetic failure" in body.get("error", "")
    assert "pip install" in body.get("hint", "")


def test_serializer_exposes_install_status_for_opf() -> None:
    """The /api/plugins serializer must include an ``install_status``
    field for the OPF plugin so the UI can render an Install button."""
    from unittest.mock import MagicMock as _Mock
    from scruxy.plugin.openai_privacy_filter import OpenAIPrivacyFilterPlugin
    from scruxy.ui.routes import _serialize_detector_plugin

    p = OpenAIPrivacyFilterPlugin()
    p.setup({})  # Lazy init: no model load

    # Build a minimal Request-like object the serializer's helpers
    # can call (_find_stage_config, _get_display_name).
    class _StubApp:
        state = _Mock(spec=[])

    class _StubReq:
        app = _StubApp()
        scope = {"app": app}

    # Trim the helpers' dependency on app.state by stubbing.
    req = _Mock()
    req.app.state = _Mock(spec=[])
    payload = _serialize_detector_plugin(p, req)

    assert "install_status" in payload, (
        "OPF serializer must include install_status so the UI can show "
        "an Install button"
    )
    status = payload["install_status"]
    for key in ("package_installed", "import_failed", "runtime_loaded",
                "install_endpoint"):
        assert key in status
    assert status["install_endpoint"] == "/ui/api/plugins/openai_privacy_filter/install"


def test_serializer_omits_install_status_for_other_plugins() -> None:
    """Non-OPF plugins must NOT carry the install_status field."""
    from unittest.mock import MagicMock as _Mock
    from scruxy.plugin.whitelist import WhitelistPlugin
    from scruxy.ui.routes import _serialize_detector_plugin

    p = WhitelistPlugin()
    p.setup({"whitelist_file": ""})

    req = _Mock()
    req.app.state = _Mock(spec=[])
    payload = _serialize_detector_plugin(p, req)
    assert "install_status" not in payload
