"""Round 70 hardening tests.

R70-1 (High): Pre-filter substring matching must skip placeholder spans.
R70-2 (Med): Transfer-Encoding chunked detection must use last-token equality.
R70-3 (Med): Header parser must reject bare CR injection.
R70-4 (Med): OpenAI provider must extract message.refusal and function_call.arguments.
R70-5 (Med): _append_text must recreate parent dir under lock to avoid clear_all race.
R70-6 (Low): Anthropic provider must walk text-bearing blocks with non-text type.
R70-7 (Low): PUT /api/providers/{name} must reject ReDoS-prone session_id_body_regex.
R70-8 (Low): PUT /api/providers/{name} must validate name like POST does.
R70-9 (Low): Forward-proxy CONNECT MITM must reject pre-CONNECT bytes (not feed them).
R70-10 (Low): SSL ctx LRU eviction must skip in-use locks.
R70-12 (Low): CA must reject mismatched key/cert pair on load.
R70-13 (Low): CA hostname must be canonicalized (lowercase, strip trailing dot) before cache lookup.
R70-14 (High): Forward-proxy CONNECT must canonicalize hostname (trailing dot, IDNA).
"""
from __future__ import annotations

import asyncio
import inspect
from pathlib import Path

import pytest


# ---------------------------------------------------------------------
# R70-1 (High): pre-filter must skip placeholder spans
# ---------------------------------------------------------------------

def test_r70_1_prefilter_skips_placeholder_spans() -> None:
    """A short PII whose text is a substring of ``"SCRX"`` (e.g. ``"SC"``)
    must NOT corrupt previously-emitted ``§§§SCRX0001§§§`` placeholders.
    """
    from scruxy.pipeline.engine import PipelineEngine, _PlaceholderEntry

    class _StubTokenMap:
        scrub_map = {
            "alice@example.com": "REDACTED_EMAIL_1",
            "SC": "REDACTED_INITIALS_1",
        }
        token_meta = {
            "alice@example.com": {"case_sensitive": True, "word_boundary": False},
            "SC": {"case_sensitive": True, "word_boundary": False},
        }

    text_in = "Email alice@example.com about SC project."
    ph_entries: list = []
    result, matches, ph_counter = PipelineEngine._pre_filter_to_placeholders(
        text_in, _StubTokenMap(), ph_counter=0, ph_entries=ph_entries,
    )

    # The placeholder for the email must remain INTACT — its "SC"
    # substring must not be replaced with a second placeholder.
    assert "§§§SCRX0000§§§" in result, f"placeholder destroyed in {result!r}"
    # The standalone "SC" outside the placeholder MUST be replaced.
    assert "SC project" not in result, (
        f"standalone SC must still be matched outside placeholder; got {result!r}"
    )
    # Two distinct PIIs were matched.
    assert len(matches) == 2, f"both PIIs should match: {matches}"


def test_r70_1_placeholder_overlap_helper() -> None:
    """The new helper must correctly report overlap/non-overlap."""
    from scruxy.pipeline.engine import _placeholder_ranges, _overlaps_placeholder

    text = "abc §§§SCRX0001§§§ def §§§SCRX0002§§§ ghi"
    ranges = _placeholder_ranges(text)
    assert len(ranges) == 2
    # Inside first placeholder
    s = text.index("§§§SCRX0001§§§")
    assert _overlaps_placeholder(s + 3, s + 7, ranges) is True
    # Outside any placeholder
    abc_idx = text.index("abc")
    assert _overlaps_placeholder(abc_idx, abc_idx + 3, ranges) is False


# ---------------------------------------------------------------------
# R70-2 (Med): chunked detection uses last-token equality
# ---------------------------------------------------------------------

def test_r70_2_chunked_detection_no_substring_match() -> None:
    """The forward-proxy source must not contain the unsafe
    ``"chunked" in te`` substring check that opens a CL/TE smuggling
    primitive.  Only references in comments are allowed.
    """
    from scruxy.proxy import forward_proxy as fp_mod

    src = inspect.getsource(fp_mod)
    # Count only the executable form — `if "chunked" in te:` (with `if `).
    bad_count = src.count('if "chunked" in te:')
    assert bad_count == 0, (
        f'R70-2: `if "chunked" in te:` substring check still present '
        f"({bad_count} occurrences)."
    )
    # Token-equality variant must be present.
    assert 'te_codings[-1] == "chunked"' in src, (
        "R70-2: expected token-equality check on last coding."
    )


# ---------------------------------------------------------------------
# R70-3 (Med): _parse_headers rejects bare CR
# ---------------------------------------------------------------------

def test_r70_3_parse_headers_rejects_bare_cr() -> None:
    """Header lines containing a bare CR must be rejected when strict
    HTTP parsing is enabled."""
    from scruxy.proxy.forward_proxy import _parse_headers, _set_strict_http_parsing

    _set_strict_http_parsing(True)
    try:
        # Bare CR injects a fake Authorization header.
        raw = "Host: example.com\r\nX-Foo: bar\rAuthorization: Bearer leaked\r\nContent-Type: text/plain"
        with pytest.raises(ValueError, match="bare CR/LF"):
            _parse_headers(raw)
    finally:
        _set_strict_http_parsing(False)


def test_r70_3_parse_headers_accepts_clean_input() -> None:
    """Standard CRLF + LF inputs still parse correctly."""
    from scruxy.proxy.forward_proxy import _parse_headers

    raw = "Host: example.com\r\nContent-Type: application/json"
    headers = _parse_headers(raw)
    assert headers["host"] == "example.com"
    assert headers["content-type"] == "application/json"


# ---------------------------------------------------------------------
# R70-4 (Med): OpenAI extracts refusal + function_call
# ---------------------------------------------------------------------

def test_r70_4_openai_extracts_refusal_and_function_call() -> None:
    from scruxy.providers.openai import OpenAIProvider

    p = OpenAIProvider()
    body = {
        "model": "gpt-4",
        "messages": [
            {
                "role": "assistant",
                "content": None,
                "function_call": {
                    "name": "lookup",
                    "arguments": '{"email": "alice@example.com"}',
                },
                "refusal": "I can't share user PII like alice@example.com",
            }
        ],
    }
    fields = p.extract_text_fields(body)
    paths = [f.json_path for f in fields]
    assert any("function_call.arguments" in pth for pth in paths), (
        f"function_call.arguments not extracted: paths={paths}"
    )
    assert any("refusal" in pth for pth in paths), (
        f"refusal not extracted: paths={paths}"
    )


def test_r70_4_openai_response_extracts_refusal_and_function_call() -> None:
    from scruxy.providers.openai import OpenAIProvider

    p = OpenAIProvider()
    body = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "function_call": {
                        "name": "search",
                        "arguments": '{"q": "alice@example.com"}',
                    },
                    "refusal": "Won't share alice@example.com",
                }
            }
        ],
    }
    fields = p.extract_response_text_fields(body)
    paths = [f.json_path for f in fields]
    assert any("function_call.arguments" in pth for pth in paths), (
        f"response function_call.arguments not extracted: paths={paths}"
    )
    assert any("refusal" in pth for pth in paths), (
        f"response refusal not extracted: paths={paths}"
    )


# ---------------------------------------------------------------------
# R70-5 (Med): _append_text recreates parent dir under lock
# ---------------------------------------------------------------------

def test_r70_5_append_text_creates_parent_dir(tmp_path: Path) -> None:
    """If the parent directory has been removed (e.g. by clear_all),
    _append_text must recreate it inside the lock.
    """
    from scruxy.recording.recorder import _append_text

    target_dir = tmp_path / "session_x"
    # Note: dir does NOT exist — simulating post-clear_all state.
    assert not target_dir.exists()
    target_path = target_dir / "recording.jsonl"

    import threading
    lock = threading.Lock()
    _append_text(target_path, "test\n", lock)

    assert target_path.exists()
    assert target_path.read_text(encoding="utf-8") == "test\n"


# ---------------------------------------------------------------------
# R70-6 (Low): Anthropic walks text-bearing non-text blocks
# ---------------------------------------------------------------------

def test_r70_6_anthropic_extracts_text_from_unknown_system_blocks() -> None:
    from scruxy.providers.anthropic import AnthropicProvider

    p = AnthropicProvider()
    body = {
        "model": "claude-3",
        "system": [
            {"type": "text", "text": "Standard system text"},
            {"type": "code_execution_output", "text": "Output containing alice@example.com"},
        ],
        "messages": [{"role": "user", "content": "ok"}],
    }
    fields = p.extract_text_fields(body)
    texts = [f.text_value for f in fields]
    assert any("alice@example.com" in t for t in texts), (
        f"R70-6: non-text system block with text field not extracted: {texts}"
    )


# ---------------------------------------------------------------------
# R70-7 (Low): PUT rejects ReDoS-prone session_id_body_regex
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_r70_7_put_rejects_redos_session_regex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scruxy.providers.anthropic import AnthropicProvider
    from scruxy.config.models import AppConfig, ProviderConfig
    from scruxy.providers.registry import ProviderRegistry
    from scruxy.ui import routes as ui_routes
    from fastapi import FastAPI

    p = AnthropicProvider()
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
        # Classic ReDoS pattern: nested-quantifier on overlapping classes.
        resp = await ac.put(
            "/ui/api/providers/anthropic",
            json={"session_id_body_regex": "(a+)+$"},
        )
    assert resp.status_code == 400, resp.text
    assert "ReDoS" in resp.text or "catastrophic" in resp.text


# ---------------------------------------------------------------------
# R70-8 (Low): PUT validates provider name
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_r70_8_put_rejects_invalid_provider_name(
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
        # Names with spaces or dots must be rejected by the validator.
        # (Slash names route to a different endpoint and yield 404,
        # which is a separate defense — covered by FastAPI routing.)
        for bad in ["bad name", "bad.name", "bad@name"]:
            resp = await ac.put(f"/ui/api/providers/{bad}", json={"enabled": True})
            assert resp.status_code == 400, (
                f"name {bad!r} should be rejected as 400, got {resp.status_code}"
            )


# ---------------------------------------------------------------------
# R70-9 (Low): MITM rejects pre-CONNECT bytes
# ---------------------------------------------------------------------

def test_r70_9_mitm_rejects_pre_connect_leftover_bytes() -> None:
    """The CONNECT dispatcher source must reject leftover bytes when
    the host matches a provider (MITM mode), rather than feeding them
    into the reader where they'd bypass TLS termination."""
    from scruxy.proxy import forward_proxy as fp_mod

    src = inspect.getsource(fp_mod.ForwardProxyServer._handle_connection)
    assert "will_mitm" in src, (
        "R70-9: _handle_connection must distinguish MITM vs passthrough "
        "before deciding what to do with leftover bytes."
    )
    assert "400 Bad Request" in src, (
        "R70-9: MITM CONNECT with leftover bytes must respond 400."
    )


# ---------------------------------------------------------------------
# R70-10 (Low): SSL ctx LRU skips in-use locks
# ---------------------------------------------------------------------

def test_r70_10_ssl_ctx_eviction_skips_held_locks() -> None:
    """The eviction loop must check ``oldest_lock.locked()`` and skip
    entries whose per-host lock is currently held."""
    from scruxy.proxy import forward_proxy as fp_mod

    src = inspect.getsource(fp_mod.ForwardProxyServer._get_or_create_ssl_ctx)
    assert "oldest_lock.locked()" in src, (
        "R70-10: SSL ctx eviction must skip in-use locks via "
        "oldest_lock.locked() check."
    )


# ---------------------------------------------------------------------
# R70-12 (Low): CA verifies key matches cert
# ---------------------------------------------------------------------

def test_r70_12_ca_load_verifies_key_cert_match(tmp_path: Path) -> None:
    """Loading a CA where the on-disk private key doesn't match the
    on-disk certificate must raise."""
    from scruxy.cert.ca import CertificateAuthority

    # Generate two independent CAs in two different dirs, then swap
    # one CA's key file with the other's to create a mismatch.
    ca1_dir = tmp_path / "ca1"
    ca2_dir = tmp_path / "ca2"
    ca1 = CertificateAuthority(cert_dir=ca1_dir)  # generates key+cert
    ca2 = CertificateAuthority(cert_dir=ca2_dir)  # generates key+cert

    # Find the key/cert files emitted by the CA.
    key_files_1 = list(ca1_dir.glob("*.key"))
    key_files_2 = list(ca2_dir.glob("*.key"))
    assert key_files_1 and key_files_2

    # Overwrite ca1's key with ca2's key → mismatch
    key_files_1[0].write_bytes(key_files_2[0].read_bytes())

    with pytest.raises((ValueError, Exception), match="does not match"):
        CertificateAuthority(cert_dir=ca1_dir)


# ---------------------------------------------------------------------
# R70-13 (Low): CA hostname canonicalization
# ---------------------------------------------------------------------

def test_r70_13_ca_hostname_canonicalized(tmp_path: Path) -> None:
    """``Example.COM``, ``example.com.``, and ``example.com`` must
    return the SAME cached cert."""
    from scruxy.cert.ca import CertificateAuthority

    ca = CertificateAuthority(cert_dir=tmp_path)
    cert_a = ca.get_host_cert("Example.COM")
    cert_b = ca.get_host_cert("example.com.")
    cert_c = ca.get_host_cert("example.com")
    # All three must be the same object (LRU hit).
    assert cert_a is cert_b
    assert cert_b is cert_c


# ---------------------------------------------------------------------
# R70-14 (High): forward proxy host matching canonicalizes FQDN
# ---------------------------------------------------------------------

def test_r70_14_host_matches_provider_canonicalizes_trailing_dot() -> None:
    """``api.openai.com.`` (DNS-equivalent) must match the same
    provider as ``api.openai.com``."""
    from scruxy.proxy.forward_proxy import _host_matches_provider, _canonicalize_hostname

    # _canonicalize_hostname strips trailing dot and lowercases.
    assert _canonicalize_hostname("api.openai.com.") == "api.openai.com"
    assert _canonicalize_hostname("API.OpenAI.COM") == "api.openai.com"
    assert _canonicalize_hostname("api.openai.com..") == "api.openai.com"

    # _host_matches_provider must use canonical form on BOTH sides.
    class _StubProvider:
        enabled = True
        upstream_url = "https://api.openai.com/v1"
        url_patterns = []

    class _StubRegistry:
        providers = [_StubProvider()]

    reg = _StubRegistry()
    assert _host_matches_provider("api.openai.com", reg) is True
    assert _host_matches_provider("api.openai.com.", reg) is True
    assert _host_matches_provider("API.OpenAI.COM.", reg) is True
    assert _host_matches_provider("api.openai.com.evil.com", reg) is False
