"""Round 71 hardening tests.

R71-1 (High): chunk-size and Content-Length must use strict ASCII parsing.
R71-2 (High): _parse_headers must reject obs-fold continuation lines.
R71-3 (Med): Anthropic response extraction must walk text-bearing non-text blocks.
R71-4 (Med): OpenAI response extraction must handle list (multimodal) content.
R71-5 (Med): Forward-proxy CONNECT must canonicalize IPv6 brackets and strip userinfo.
R71-6 (Med): SSL ctx cache must canonicalize hostname before lookup.
R71-7 (Med): _looks_catastrophic ReDoS guard must apply on POST + app load + YAML.
R71-8 (Med): _is_placeholder must use strict regex match.
R71-10 (Low): TokenDB must close connection on init failure.
R71-11 (Low): CA key file must have strict mode unconditionally.
R71-12 (Low): Re-registering a token with conflicting metadata must warn.
R71-13 (Low): PluginStorage must reject Windows reserved names.
"""
from __future__ import annotations

import asyncio
import inspect
from pathlib import Path

import pytest


# ---------------------------------------------------------------------
# R71-1: strict int parsing for CL and chunk-size
# ---------------------------------------------------------------------

def test_r71_1_chunk_size_strict_ascii_hex() -> None:
    """The chunked-body parser source must contain the strict regex
    pre-check for chunk-size.  Without it ``int(b" +5", 16)`` returns
    5 (whitespace tolerant) and ``int(b"5_000", 16)`` may also accept
    on some Pythons → smuggling vs strict upstreams."""
    from scruxy.proxy import forward_proxy as fp_mod

    src = inspect.getsource(fp_mod._read_chunked_body)
    assert 'fullmatch(rb"[0-9A-Fa-f]+"' in src, (
        "R71-1: chunked body parser must use strict hex regex pre-check."
    )


def test_r71_1_content_length_strict_digits() -> None:
    """Content-Length parsing must use strict digit regex pre-check."""
    from scruxy.proxy import forward_proxy as fp_mod

    src = inspect.getsource(fp_mod)
    # Both call sites must have the strict pre-check.
    cl_strict_count = src.count('fullmatch(r"[0-9]+", content_length)')
    assert cl_strict_count >= 2, (
        f"R71-1: Content-Length must be strictly validated at all "
        f"call sites; found {cl_strict_count} of expected 2+."
    )


# ---------------------------------------------------------------------
# R71-2: obs-fold rejection
# ---------------------------------------------------------------------

def test_r71_2_parse_headers_rejects_obs_fold() -> None:
    """A continuation line starting with SP/HTAB must be rejected
    (RFC 9112 §5.2 forbids obsolete line folding).  Without this, an
    attacker can smuggle a Host or Authorization header past the
    sensitive-header guard by emitting it as a continuation line."""
    from scruxy.proxy.forward_proxy import _parse_headers, _set_strict_http_parsing

    _set_strict_http_parsing(True)
    try:
        raw = (
            "Host: example.com\r\n"
            "X-Foo: bar\r\n"
            "\tHost: evil.com\r\n"  # obs-fold injection
            "Content-Type: text/plain"
        )
        with pytest.raises(ValueError, match="line folding|continuation"):
            _parse_headers(raw)
    finally:
        _set_strict_http_parsing(False)


def test_r71_2_parse_headers_accepts_normal_input() -> None:
    """Normal multi-header input must still parse."""
    from scruxy.proxy.forward_proxy import _parse_headers

    raw = "Host: example.com\r\nContent-Type: application/json"
    headers = _parse_headers(raw)
    assert headers["host"] == "example.com"


# ---------------------------------------------------------------------
# R71-3: Anthropic response walks text-bearing non-text blocks
# ---------------------------------------------------------------------

def test_r71_3_anthropic_response_extracts_non_text_blocks() -> None:
    from scruxy.providers.anthropic import AnthropicProvider

    p = AnthropicProvider()
    body = {
        "id": "msg_1",
        "type": "message",
        "content": [
            {"type": "text", "text": "Standard text"},
            {"type": "code_execution_output", "text": "Output: alice@example.com"},
            {"type": "web_search_tool_result", "text": "Search hit: alice@example.com"},
        ],
    }
    fields = p.extract_response_text_fields(body)
    texts = [f.text_value for f in fields]
    assert any("Output:" in t for t in texts), (
        f"R71-3: code_execution_output not extracted: {texts}"
    )
    assert any("Search hit:" in t for t in texts), (
        f"R71-3: web_search_tool_result not extracted: {texts}"
    )


# ---------------------------------------------------------------------
# R71-4: OpenAI response handles list content
# ---------------------------------------------------------------------

def test_r71_4_openai_response_extracts_list_content() -> None:
    from scruxy.providers.openai import OpenAIProvider

    p = OpenAIProvider()
    body = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "First part: alice@example.com"},
                        {"type": "text", "text": "Second part: bob@example.com"},
                    ],
                }
            }
        ],
    }
    fields = p.extract_response_text_fields(body)
    texts = [f.text_value for f in fields]
    assert any("alice@example.com" in t for t in texts), (
        f"R71-4: list-content text part 1 not extracted: {texts}"
    )
    assert any("bob@example.com" in t for t in texts), (
        f"R71-4: list-content text part 2 not extracted: {texts}"
    )


# ---------------------------------------------------------------------
# R71-5: IPv6 brackets + userinfo canonicalization
# ---------------------------------------------------------------------

def test_r71_5_canonicalize_strips_ipv6_brackets() -> None:
    from scruxy.proxy.forward_proxy import _canonicalize_hostname

    assert _canonicalize_hostname("[::1]") == "::1"
    assert _canonicalize_hostname("[2001:db8::1]") == "2001:db8::1"
    assert _canonicalize_hostname("[fe80::1]") == "fe80::1"


def test_r71_5_canonicalize_strips_userinfo() -> None:
    from scruxy.proxy.forward_proxy import _canonicalize_hostname

    assert _canonicalize_hostname("user@example.com") == "example.com"
    assert _canonicalize_hostname("user:pass@api.openai.com") == "api.openai.com"
    assert _canonicalize_hostname("user:pass@api.openai.com.") == "api.openai.com"


def test_r71_5_parse_connect_authority() -> None:
    from scruxy.proxy.forward_proxy import _parse_connect_authority

    # Standard host:port
    h, p = _parse_connect_authority("api.openai.com:443")
    assert h == "api.openai.com"
    assert p == 443

    # IPv6 with port
    h, p = _parse_connect_authority("[::1]:443")
    assert h == "::1"
    assert p == 443

    # Missing port → defaults 443
    h, p = _parse_connect_authority("api.openai.com")
    assert h == "api.openai.com"
    assert p == 443

    # Invalid port → ValueError
    with pytest.raises(ValueError):
        _parse_connect_authority("host:99999")


# ---------------------------------------------------------------------
# R71-6: SSL ctx cache canonicalizes hostname
# ---------------------------------------------------------------------

def test_r71_6_ssl_ctx_cache_canonicalized() -> None:
    """The SSL ctx cache lookup source must call ``_canonicalize_hostname``
    before any cache or lock lookup."""
    from scruxy.proxy import forward_proxy as fp_mod

    src = inspect.getsource(fp_mod.ForwardProxyServer._get_or_create_ssl_ctx)
    assert "_canonicalize_hostname(hostname)" in src, (
        "R71-6: _get_or_create_ssl_ctx must canonicalize hostname "
        "before cache/lock lookup."
    )


# ---------------------------------------------------------------------
# R71-7: ReDoS guard sibling — POST + YAML + app
# ---------------------------------------------------------------------

def test_r71_7_yaml_provider_rejects_redos_session_regex() -> None:
    """A YAMLProvider constructed with a ReDoS-prone session regex
    must NOT compile it (the heuristic catches the pattern; the
    provider falls back to header-based extraction)."""
    from scruxy.providers.yaml_provider import YAMLProvider

    cfg = {
        "name": "test",
        "url_patterns": ["https://test.com/*"],
        "session_id_body_regex": "(a+)+$",  # classic ReDoS
    }
    p = YAMLProvider(cfg)
    # The compiled regex must NOT be present (heuristic rejected it).
    assert p._compiled_session_id_body_regex is None, (
        "R71-7: YAMLProvider must reject ReDoS-prone session_id_body_regex."
    )


def test_r71_7_app_load_redos_guard_present() -> None:
    """app.py load path must reference _looks_catastrophic for the
    session_id_body_regex override."""
    from scruxy import app as app_mod

    src = inspect.getsource(app_mod)
    assert "_looks_catastrophic" in src, (
        "R71-7: app.py must guard session_id_body_regex with _looks_catastrophic."
    )


@pytest.mark.asyncio
async def test_r71_7_post_rejects_redos_session_regex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scruxy.config.models import AppConfig
    from scruxy.providers.registry import ProviderRegistry
    from scruxy.ui import routes as ui_routes
    from fastapi import FastAPI

    cfg = AppConfig()
    cfg.providers = {}
    reg = ProviderRegistry()

    monkeypatch.setattr(ui_routes, "_get_config", lambda _r: cfg)
    monkeypatch.setattr(ui_routes, "_get_providers", lambda _r: reg)
    monkeypatch.setattr(ui_routes, "_get_config_path", lambda _r: tmp_path / "config.yaml")
    import scruxy.config.loader as loader_mod
    monkeypatch.setattr(loader_mod, "save_config", lambda *a, **kw: None)

    app = FastAPI()
    app.include_router(ui_routes.router)

    from httpx import AsyncClient, ASGITransport
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            "/ui/api/providers",
            json={
                "name": "newprov",
                "upstream_url": "https://test.com",
                "url_patterns": ["https://test.com/*"],
                "session_id_body_regex": "(a+)+$",
            },
        )
    assert resp.status_code == 400, resp.text
    assert "ReDoS" in resp.text or "catastrophic" in resp.text


# ---------------------------------------------------------------------
# R71-8: _is_placeholder strict
# ---------------------------------------------------------------------

def test_r71_8_is_placeholder_strict_match() -> None:
    """``_is_placeholder`` must NOT return True for over-broad spans
    that contain two real placeholders separated by other text."""
    from scruxy.pipeline.engine import _is_placeholder

    # Single valid placeholder → True
    assert _is_placeholder("§§§SCRX0001§§§") is True

    # Two placeholders separated by text → must be False
    assert _is_placeholder("§§§SCRX0001§§§ extra text §§§SCRX0002§§§") is False

    # Garbage between prefix/suffix → False
    assert _is_placeholder("§§§SCRXfoo§§§") is False  # not digits

    # Empty / non-placeholder → False
    assert _is_placeholder("") is False
    assert _is_placeholder("just text") is False


# ---------------------------------------------------------------------
# R71-10: TokenDB closes conn on init failure
# ---------------------------------------------------------------------

def test_r71_10_tokendb_closes_on_init_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If schema init / migration raises, the connection must be closed
    so the next ``open()`` retry can acquire the DB file."""
    from scruxy.tokenmap import db as db_mod

    db_path = tmp_path / "tokens.db"
    db = db_mod.TokenDB(db_path)

    # Sabotage: monkey-patch the module-level _SCHEMA constant to
    # invalid SQL so executescript raises.
    monkeypatch.setattr(db_mod, "_SCHEMA", "DEFINITELY NOT VALID SQL;")
    import sqlite3
    with pytest.raises(sqlite3.OperationalError):
        db.open()

    # Connection must be cleaned up.
    assert db._conn is None, "R71-10: connection must be closed on init failure"

    # Restore + re-open should now succeed.
    monkeypatch.undo()
    db.open()
    db.close()


# ---------------------------------------------------------------------
# R71-12: conflicting token metadata warns
# ---------------------------------------------------------------------

def test_r71_12_re_register_conflicting_metadata_warns(caplog: pytest.LogCaptureFixture) -> None:
    """Re-registering the same canonical PII with conflicting
    metadata (case_sensitive flip, etc.) must emit a warning so the
    operator notices the silent first-write-wins behavior."""
    import logging
    from scruxy.tokenmap.token_map import TokenMap

    tm = TokenMap()
    tok1 = tm.get_or_create_token("Alice", "PERSON", case_sensitive=True, use_word_boundary=True)
    assert tok1 is not None

    with caplog.at_level(logging.WARNING, logger="scruxy.tokenmap.token_map"):
        # Re-register with FLIPPED metadata
        tok2 = tm.get_or_create_token(
            "Alice", "PERSON",
            case_sensitive=False, use_word_boundary=False,
        )
    assert tok1 == tok2, "first-write wins for the actual token"
    assert any("different metadata" in rec.message for rec in caplog.records), (
        "R71-12: conflicting metadata must emit a warning"
    )


# ---------------------------------------------------------------------
# R71-13: PluginStorage rejects Windows reserved names
# ---------------------------------------------------------------------

def test_r71_13_plugin_storage_rejects_windows_reserved(tmp_path: Path) -> None:
    from scruxy.plugin.storage import PluginStorage

    for bad in ["CON", "NUL", "PRN", "AUX", "COM1", "LPT1", "con", "Nul"]:
        with pytest.raises(ValueError, match="Invalid plugin_name"):
            PluginStorage(str(tmp_path), bad)


def test_r71_13_plugin_storage_rejects_trailing_dot_or_space(tmp_path: Path) -> None:
    from scruxy.plugin.storage import PluginStorage

    for bad in ["foo.", "bar ", "myplugin."]:
        with pytest.raises(ValueError, match="Invalid plugin_name"):
            PluginStorage(str(tmp_path), bad)


def test_r71_13_plugin_storage_rejects_control_chars(tmp_path: Path) -> None:
    from scruxy.plugin.storage import PluginStorage

    for bad in ["foo\x00bar", "foo\nbar", "foo\rbar", "foo\tbar"]:
        with pytest.raises(ValueError, match="Invalid plugin_name"):
            PluginStorage(str(tmp_path), bad)
