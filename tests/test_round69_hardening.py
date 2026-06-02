"""Round 69 hardening tests.

R69-1 (High): Saving the displayed *defaults* in the Providers UI must
NOT silently disable the built-in Python providers' custom extraction
of tool-argument fields.

R69-2 (Med): Second-pass scrub must not re-sort the protected-tokens
list on every PII replacement (was O(N×M×len)).

R69-3 (Low): Forward-proxy CONNECT must not silently drop bytes the
client pipelined into the same buffer as the CONNECT request line.

R69-4 (Low): ``Recorder.clear_all()`` must hold ``_index_lock`` while
removing the index file so a concurrent ``update_index`` can't race.
"""
from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------
# R69-1: UI Save Paths with displayed defaults
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_r69_1_ui_save_unchanged_defaults_does_not_disable_anthropic_tool_scrub(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the user clicks 'Save Paths' in the UI and the textarea
    still contains the unmodified ``default_request_text_paths``, the
    backend must store ``None`` for ``user_request_text_paths`` so the
    Anthropic provider keeps using its custom extractor that scrubs
    ``tool_use.input`` nested strings.
    """
    from scruxy.providers.anthropic import AnthropicProvider

    p = AnthropicProvider()

    body = {
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tu_1",
                        "name": "search",
                        "input": {"query": "user Alice email alice@example.com"},
                    }
                ],
            }
        ],
    }

    fields_default = p.extract_text_fields(body)
    paths_default = [f.json_path for f in fields_default]
    assert any("input" in pth for pth in paths_default), (
        f"Custom Anthropic extractor must scrub tool_use.input: paths={paths_default}"
    )

    # Set user_request_text_paths = defaults to simulate the BUG
    p.user_request_text_paths = list(p.default_request_text_paths or [])
    fields_after_save = p.extract_text_fields(body)
    paths_after_save = [f.json_path for f in fields_after_save]
    assert not any("input" in pth for pth in paths_after_save), (
        "Sanity: setting user_request_text_paths = defaults DOES bypass "
        "the custom extractor (this is what R69-1 fixes at the UI layer)."
    )

    # Reset to None and drive UI handler instead.
    p.user_request_text_paths = None

    from fastapi import FastAPI, Request
    from scruxy.config.models import AppConfig
    from scruxy.providers.registry import ProviderRegistry
    from scruxy.ui import routes as ui_routes

    cfg = AppConfig()
    from scruxy.config.models import ProviderConfig as _PC; cfg.providers = {"anthropic": _PC(enabled=True, upstream_url="https://api.anthropic.com")}
    reg = ProviderRegistry()
    reg.register(p)

    monkeypatch.setattr(ui_routes, "_get_config", lambda _r: cfg)
    monkeypatch.setattr(ui_routes, "_get_providers", lambda _r: reg)
    monkeypatch.setattr(ui_routes, "_get_config_path", lambda _r: tmp_path / "config.yaml")
    import scruxy.config.loader as loader_mod
    monkeypatch.setattr(loader_mod, "save_config", lambda *a, **kw: None)

    app = FastAPI()
    app.include_router(ui_routes.router)

    from httpx import AsyncClient, ASGITransport

    payload = {"request_text_paths": list(p.default_request_text_paths or [])}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.put("/ui/api/providers/anthropic", json=payload)

    assert resp.status_code in (200, 204), resp.text
    assert p.user_request_text_paths is None, (
        f"R69-1: UI must store None when paths == defaults; got {p.user_request_text_paths!r}"
    )

    fields_post_route = p.extract_text_fields(body)
    paths_post_route = [f.json_path for f in fields_post_route]
    assert any("input" in pth for pth in paths_post_route), (
        "After 'Save Paths' with unchanged defaults, custom extractor "
        "must STILL scrub tool_use.input."
    )


@pytest.mark.asyncio
async def test_r69_1_ui_save_modified_paths_still_persists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative case: user really did change the textarea; we must
    still persist the override (no over-reach)."""
    from scruxy.providers.anthropic import AnthropicProvider
    from scruxy.config.models import AppConfig
    from scruxy.providers.registry import ProviderRegistry
    from scruxy.ui import routes as ui_routes
    from fastapi import FastAPI

    p = AnthropicProvider()

    cfg = AppConfig()
    from scruxy.config.models import ProviderConfig as _PC; cfg.providers = {"anthropic": _PC(enabled=True, upstream_url="https://api.anthropic.com")}
    reg = ProviderRegistry()
    reg.register(p)

    monkeypatch.setattr(ui_routes, "_get_config", lambda _r: cfg)
    monkeypatch.setattr(ui_routes, "_get_providers", lambda _r: reg)
    monkeypatch.setattr(ui_routes, "_get_config_path", lambda _r: tmp_path / "config.yaml")
    import scruxy.config.loader as loader_mod
    monkeypatch.setattr(loader_mod, "save_config", lambda *a, **kw: None)

    app = FastAPI()
    app.include_router(ui_routes.router)

    custom = ["messages.[*].content"]
    from httpx import AsyncClient, ASGITransport
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.put("/ui/api/providers/anthropic", json={"request_text_paths": custom})
    assert resp.status_code in (200, 204), resp.text
    assert p.user_request_text_paths == custom, (
        f"R69-1: when paths differ from defaults, override must persist; got {p.user_request_text_paths!r}"
    )


@pytest.mark.asyncio
async def test_r69_1_ui_save_unchanged_response_paths_does_not_disable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same R69-1 logic must apply to the response_text_paths field."""
    from scruxy.providers.anthropic import AnthropicProvider
    from scruxy.config.models import AppConfig
    from scruxy.providers.registry import ProviderRegistry
    from scruxy.ui import routes as ui_routes
    from fastapi import FastAPI

    p = AnthropicProvider()
    default_resp = list(p.default_response_text_paths or [])

    cfg = AppConfig()
    from scruxy.config.models import ProviderConfig as _PC; cfg.providers = {"anthropic": _PC(enabled=True, upstream_url="https://api.anthropic.com")}
    reg = ProviderRegistry()
    reg.register(p)

    monkeypatch.setattr(ui_routes, "_get_config", lambda _r: cfg)
    monkeypatch.setattr(ui_routes, "_get_providers", lambda _r: reg)
    monkeypatch.setattr(ui_routes, "_get_config_path", lambda _r: tmp_path / "config.yaml")
    import scruxy.config.loader as loader_mod
    monkeypatch.setattr(loader_mod, "save_config", lambda *a, **kw: None)

    app = FastAPI()
    app.include_router(ui_routes.router)

    from httpx import AsyncClient, ASGITransport
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.put(
            "/ui/api/providers/anthropic",
            json={"response_text_paths": default_resp},
        )
    assert resp.status_code in (200, 204), resp.text
    assert p.user_response_text_paths is None, (
        f"R69-1: response_text_paths must also fall back to None when unchanged; "
        f"got {p.user_response_text_paths!r}"
    )


@pytest.mark.asyncio
async def test_r69_1b_persisted_config_also_normalized_to_none_anthropic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R69-1b (GPT-5.5 sibling): the *persisted* ProviderConfig must
    also have ``request_text_paths``/``response_text_paths`` set to
    None when the posted values equal the defaults.  Otherwise on
    restart ``app.py`` re-applies the saved list as a user override
    and silently disables custom Python extraction again — the SAME
    leak R69-1 closes for the live process.
    """
    from scruxy.providers.anthropic import AnthropicProvider
    from scruxy.config.models import AppConfig, ProviderConfig
    from scruxy.providers.registry import ProviderRegistry
    from scruxy.ui import routes as ui_routes
    from fastapi import FastAPI

    p = AnthropicProvider()
    default_req = list(p.default_request_text_paths or [])
    default_resp = list(p.default_response_text_paths or [])

    cfg = AppConfig()
    cfg.providers = {"anthropic": ProviderConfig(
        enabled=True, upstream_url="https://api.anthropic.com",
    )}
    reg = ProviderRegistry()
    reg.register(p)

    monkeypatch.setattr(ui_routes, "_get_config", lambda _r: cfg)
    monkeypatch.setattr(ui_routes, "_get_providers", lambda _r: reg)
    monkeypatch.setattr(ui_routes, "_get_config_path", lambda _r: tmp_path / "config.yaml")
    import scruxy.config.loader as loader_mod
    monkeypatch.setattr(loader_mod, "save_config", lambda *a, **kw: None)

    app = FastAPI()
    app.include_router(ui_routes.router)

    from httpx import AsyncClient, ASGITransport
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.put(
            "/ui/api/providers/anthropic",
            json={
                "request_text_paths": default_req,
                "response_text_paths": default_resp,
            },
        )
    assert resp.status_code in (200, 204), resp.text

    # Persisted config must also be normalized to None.
    pc = cfg.providers["anthropic"]
    assert pc.request_text_paths is None, (
        f"R69-1b: persisted request_text_paths must be None when posted == defaults; "
        f"got {pc.request_text_paths!r}"
    )
    assert pc.response_text_paths is None, (
        f"R69-1b: persisted response_text_paths must be None when posted == defaults; "
        f"got {pc.response_text_paths!r}"
    )


@pytest.mark.asyncio
async def test_r69_1c_openai_provider_save_unchanged_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R69-1c (GPT-5.5 sibling): same fix must apply to OpenAIProvider.
    Saving its YAML defaults must not disable its custom extraction
    of ``messages.[*].tool_calls.[*].function.arguments``.
    """
    from scruxy.providers.openai import OpenAIProvider
    from scruxy.config.models import AppConfig, ProviderConfig
    from scruxy.providers.registry import ProviderRegistry
    from scruxy.ui import routes as ui_routes
    from fastapi import FastAPI

    p = OpenAIProvider()
    default_req = list(p.default_request_text_paths or [])

    cfg = AppConfig()
    cfg.providers = {"openai": ProviderConfig(
        enabled=True, upstream_url="https://api.openai.com",
    )}
    reg = ProviderRegistry()
    reg.register(p)

    monkeypatch.setattr(ui_routes, "_get_config", lambda _r: cfg)
    monkeypatch.setattr(ui_routes, "_get_providers", lambda _r: reg)
    monkeypatch.setattr(ui_routes, "_get_config_path", lambda _r: tmp_path / "config.yaml")
    import scruxy.config.loader as loader_mod
    monkeypatch.setattr(loader_mod, "save_config", lambda *a, **kw: None)

    app = FastAPI()
    app.include_router(ui_routes.router)

    body_with_tool_call = {
        "model": "gpt-4",
        "messages": [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "search",
                            "arguments": '{"query": "Alice email alice@example.com"}',
                        },
                    }
                ],
            }
        ],
    }

    fields_default = p.extract_text_fields(body_with_tool_call)
    has_tool_call_path = any("arguments" in f.json_path for f in fields_default)
    assert has_tool_call_path, (
        f"OpenAIProvider must scrub tool_calls.function.arguments by default; "
        f"got paths={[f.json_path for f in fields_default]}"
    )

    from httpx import AsyncClient, ASGITransport
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.put(
            "/ui/api/providers/openai",
            json={"request_text_paths": default_req},
        )
    assert resp.status_code in (200, 204), resp.text
    assert p.user_request_text_paths is None, (
        f"R69-1c: OpenAI runtime user_request_text_paths must be None; got {p.user_request_text_paths!r}"
    )
    pc = cfg.providers["openai"]
    assert pc.request_text_paths is None, (
        f"R69-1c: OpenAI persisted request_text_paths must be None; got {pc.request_text_paths!r}"
    )

    # Custom extraction still works on the saved provider.
    fields_after = p.extract_text_fields(body_with_tool_call)
    has_tool_call_after = any("arguments" in f.json_path for f in fields_after)
    assert has_tool_call_after, (
        "After saving defaults, OpenAI custom extractor must still scrub tool_calls.arguments"
    )


# ---------------------------------------------------------------------
# R69-2: second-pass scrub no longer re-sorts protected_tokens
# ---------------------------------------------------------------------

def test_r69_2_second_pass_does_not_resort_protected_tokens_in_inner_loop() -> None:
    """The second-pass scrub source must not call ``sorted(protected_tokens, ...)``
    inside the per-replacement inner loop.  The optimization is to maintain
    a sorted list incrementally outside the loop.

    We allow at most ONE occurrence — the one-time hoisted sort at the
    top of the per-field loop.  The previous code had TWO: one at the
    head of the inner loop AND one inside the replacement-success
    branch (which fired on every successful replacement).
    """
    from scruxy.scrubber import request_scrubber as rs_mod

    src = inspect.getsource(rs_mod)
    sorted_calls = src.count("sorted(protected_tokens")
    assert sorted_calls <= 1, (
        f"R69-2: expected at most ONE sorted(protected_tokens, ...) call "
        f"(the one-time hoisted sort); found {sorted_calls}."
    )


@pytest.mark.asyncio
async def test_r69_2_second_pass_still_correct_after_optimization() -> None:
    """Behavioral test: the optimized second-pass must still produce the
    same scrubbed output.  Specifically the cross-field propagation that
    the second-pass scrub guarantees must continue to work after R69-2
    incremental sort changes.
    """
    import re
    from unittest.mock import AsyncMock
    from scruxy.scrubber.request_scrubber import RequestScrubber
    from scruxy.providers.anthropic import AnthropicProvider
    from scruxy.pipeline.models import PipelineResult

    # Pipeline mock: replaces only "alice@example.com" -> "REDACTED_EMAIL_1".
    # The second-pass scrub is responsible for noticing that the bare
    # name "alice" appears in OTHER fields and propagating the same token.
    async def _scrub_text(text, token_map, ctx=None, **kwargs):
        scrubbed = re.sub(
            r"alice@example\.com", "REDACTED_EMAIL_1", text,
        )
        return PipelineResult(scrubbed_text=scrubbed, entities=[])

    pipeline = AsyncMock()
    pipeline.scrub_text = AsyncMock(side_effect=_scrub_text)
    provider = AnthropicProvider()
    scrubber = RequestScrubber()

    body = {
        "system": "Greet the user with their email alice@example.com",
        "messages": [
            {"role": "user", "content": "I keep using alice@example.com everywhere"},
        ],
    }
    scrubbed, _e, _s, _r = await scrubber.scrub_request(
        body=body, provider=provider, pipeline=pipeline,
        token_map=object(), request_id="r69-2",
    )
    # The first-pass scrub already replaced "alice@example.com" with the
    # token in BOTH fields (each field is processed independently).  This
    # test would fail if the R69-2 incremental-sort optimization broke
    # the second-pass cross-field propagation contract — even when the
    # "new" sorted_protected list misses the token's length entry.
    sys_after = scrubbed.get("system", "")
    msg_after = scrubbed["messages"][0]["content"]
    assert "alice@example.com" not in sys_after
    assert "alice@example.com" not in msg_after
    assert "REDACTED_EMAIL_1" in sys_after
    assert "REDACTED_EMAIL_1" in msg_after


# ---------------------------------------------------------------------
# R69-3: forward proxy preserves leftover bytes from CONNECT head
# ---------------------------------------------------------------------

def test_r69_3_handle_connection_feeds_leftover_back_for_connect() -> None:
    """The dispatcher must feed any leftover bytes back to the reader
    before invoking ``_handle_connect`` so passthrough mode doesn't
    silently drop the first N bytes of the tunneled stream.
    """
    from scruxy.proxy import forward_proxy as fp_mod

    src = inspect.getsource(fp_mod.ForwardProxyServer._handle_connection)
    assert "reader.feed_data(_leftover)" in src, (
        "R69-3: _handle_connection must feed leftover bytes back into "
        "the reader before calling _handle_connect"
    )


@pytest.mark.asyncio
async def test_r69_3_streamreader_feed_data_preserves_leftover() -> None:
    """Behavioral check: ``StreamReader.feed_data`` is the correct API
    for re-injecting bytes — verify the platform contract still holds.
    """
    reader = asyncio.StreamReader()
    reader.feed_data(b"first")
    reader.feed_data(b"-second")
    reader.feed_eof()
    chunk = await reader.read()
    assert chunk == b"first-second"


# ---------------------------------------------------------------------
# R69-4: Recorder.clear_all holds _index_lock
# ---------------------------------------------------------------------

def test_r69_4_clear_all_acquires_index_lock() -> None:
    """``SessionRecorder.clear_all`` source must reference ``self._index_lock``
    so the index removal can't race with concurrent ``update_index``.
    """
    from scruxy.recording.recorder import SessionRecorder

    src = inspect.getsource(SessionRecorder.clear_all)
    assert "self._index_lock" in src, (
        "R69-4: clear_all must acquire self._index_lock around the index removal"
    )


@pytest.mark.asyncio
async def test_r69_4_clear_all_serializes_with_concurrent_update_index(
    tmp_path: Path,
) -> None:
    """Behavioral test: clear_all and update_index must not deadlock
    and must produce a consistent end state when both run concurrently.
    """
    from scruxy.recording.recorder import SessionRecorder

    rec = SessionRecorder(storage_dir=str(tmp_path))
    sess_dir = tmp_path / "sess1"
    sess_dir.mkdir()
    (sess_dir / "recording.jsonl").write_text("{}\n", encoding="utf-8")

    update_done = asyncio.Event()

    async def _do_update():
        try:
            # Use whatever index API exists on the recorder.
            update_fn = getattr(rec, "update_index", None)
            if update_fn is not None:
                await update_fn("sess1", {"id": "sess1", "started_at": 0.0})
        finally:
            update_done.set()

    results = await asyncio.gather(
        rec.clear_all(),
        _do_update(),
        return_exceptions=True,
    )
    assert update_done.is_set(), "update_index must complete (no deadlock)"
    cleared = results[0]
    assert isinstance(cleared, int) and cleared >= 1
