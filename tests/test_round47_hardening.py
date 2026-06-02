"""Regression tests for the Round 47 full-codebase hardening fixes (A1-A17).

Each test class targets one finding from the aggregated review.  These
tests fail without the fix and pass with it — they are deliberately
written as the smallest possible reproducer for each defect so the
intent is obvious in code review.
"""
from __future__ import annotations

import asyncio
import gzip
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest


# ---------------------------------------------------------------------------
# A1 — Presidio cache key includes language/entities/threshold
# ---------------------------------------------------------------------------

class TestA1_PresidioCacheKey:
    """Cache must invalidate when language/entities/threshold change."""

    def test_cache_key_includes_language(self):
        from scruxy.plugin.presidio import PresidioPlugin
        plugin = PresidioPlugin()
        plugin.setup({
            "enabled": True, "language": "en",
            "entities": ["PERSON", "EMAIL_ADDRESS"],
            "score_threshold": 0.6, "post_filter": False,
        })
        text = "Contact alice@example.com about the change."
        # First call populates cache.
        _ = plugin.detect(text)
        # Second identical call hits cache.
        _ = plugin.detect(text)
        misses_after = plugin._cache_misses

        # Mutate language directly (bypass setup which would reset the
        # cache anyway).  This simulates a config change that altered
        # _language without invalidating the cache; the fix's job is to
        # ensure the cache key includes _language so the next detect()
        # is a miss, not a stale hit.
        plugin._language = "es"
        try:
            _ = plugin.detect(text)
        except Exception:
            # Spanish model may not be installed locally — but the
            # cache key MUST already have differed (= miss), which is
            # what we assert below.
            pass
        assert plugin._cache_misses > misses_after, (
            "Mutating _language must produce a cache miss (else stale en results)"
        )

    def test_cache_key_includes_threshold(self):
        from scruxy.plugin.presidio import PresidioPlugin
        plugin = PresidioPlugin()
        plugin.setup({
            "enabled": True, "language": "en",
            "entities": ["EMAIL_ADDRESS"],
            "score_threshold": 0.6, "post_filter": False,
        })
        text = "alice@example.com"
        _ = plugin.detect(text)
        misses_before = plugin._cache_misses
        # Tighten threshold — should invalidate
        plugin._score_threshold = 0.99
        _ = plugin.detect(text)
        assert plugin._cache_misses > misses_before


# ---------------------------------------------------------------------------
# A2 — CL+TE coexistence rejected (request smuggling)
# ---------------------------------------------------------------------------

class TestA2_ClTeRejected:
    def test_both_headers_rejected(self):
        from scruxy.proxy.forward_proxy import _parse_headers
        raw = (
            "Host: example.com\r\n"
            "Content-Length: 13\r\n"
            "Transfer-Encoding: chunked\r\n"
        )
        with pytest.raises(ValueError, match="smuggling|both"):
            _parse_headers(raw)

    def test_single_content_length_ok(self):
        from scruxy.proxy.forward_proxy import _parse_headers
        out = _parse_headers("Host: ex.com\r\nContent-Length: 5\r\n")
        # R59-1: keys stored lowercased.
        assert out.get("content-length") == "5"

    def test_single_transfer_encoding_ok(self):
        from scruxy.proxy.forward_proxy import _parse_headers
        out = _parse_headers("Host: ex.com\r\nTransfer-Encoding: chunked\r\n")
        assert out.get("transfer-encoding") == "chunked"

    def test_duplicate_cl_still_rejected(self):
        from scruxy.proxy.forward_proxy import _parse_headers
        with pytest.raises(ValueError, match="Duplicate"):
            _parse_headers("Content-Length: 1\r\nContent-Length: 2\r\n")


# ---------------------------------------------------------------------------
# A3 — Regex ReDoS protection (compile-time + runtime guard)
# ---------------------------------------------------------------------------

class TestA3_RegexReDoSGuard:
    def test_nested_quantifier_pattern_skipped(self):
        from scruxy.plugin.regex import RegexPlugin
        plugin = RegexPlugin()
        plugin.setup({
            "enabled": True,
            "patterns": [
                {
                    "name": "evil",
                    "entity_type": "EVIL",
                    "pattern": r"(a+)+$",
                    "score": 0.9,
                },
                {
                    "name": "good",
                    "entity_type": "GOOD",
                    "pattern": r"\d{3}",
                    "score": 0.5,
                },
            ],
        })
        # Only the good pattern should have compiled.
        names = {p.name for p in plugin._patterns}
        assert "evil" not in names
        assert "good" in names

    def test_duplicate_alternation_skipped(self):
        from scruxy.plugin.regex import RegexPlugin
        plugin = RegexPlugin()
        plugin.setup({
            "enabled": True,
            "patterns": [
                {"name": "alt", "entity_type": "X", "pattern": r"(a|a)+",
                 "score": 0.5},
            ],
        })
        assert plugin._patterns == []

    def test_looks_catastrophic_helper(self):
        from scruxy.plugin.regex import _looks_catastrophic
        assert _looks_catastrophic(r"(a+)+") is not None
        assert _looks_catastrophic(r"(.*)+") is not None
        assert _looks_catastrophic(r"\d{3}") is None
        assert _looks_catastrophic(r"[a-z]+") is None

    def test_prefix_overlap_alternation_rejected(self):
        """(a|aa)+ — overlapping alternation that GPT-5.5 flagged."""
        from scruxy.plugin.regex import _looks_catastrophic, RegexPlugin
        assert _looks_catastrophic(r"^(a|aa)+$") is not None
        plugin = RegexPlugin()
        plugin.setup({
            "enabled": True,
            "patterns": [
                {"name": "overlap", "entity_type": "X",
                 "pattern": r"^(a|aa)+$", "score": 0.5},
            ],
        })
        assert plugin._patterns == []

    def test_legitimate_disjunction_not_rejected(self):
        """(yes|no)+ — disjoint alternatives — should NOT be rejected."""
        from scruxy.plugin.regex import _looks_catastrophic
        assert _looks_catastrophic(r"(yes|no)+") is None
        assert _looks_catastrophic(r"(foo|bar)") is None

    def test_hard_timeout_catches_runaway_pattern(self, monkeypatch):
        """A pattern that bypasses the compile-time heuristic but
        catastrophically backtracks at runtime MUST be hard-interrupted
        by the regex engine's timeout (not just measured post-hoc)."""
        from scruxy.plugin import regex as rmod
        if not rmod._HAS_REGEX_LIB:
            pytest.skip("third-party 'regex' library not installed")

        # Disable the compile-time heuristic so we can prove the
        # runtime hard-timeout works in isolation.  In production, both
        # layers cooperate.
        monkeypatch.setattr(rmod, "_looks_catastrophic", lambda p: None)

        plugin = rmod.RegexPlugin()
        original_budget = rmod._PATTERN_TIME_BUDGET_S
        rmod._PATTERN_TIME_BUDGET_S = 0.05
        try:
            plugin.setup({
                "enabled": True,
                "patterns": [{
                    "name": "runaway",
                    "entity_type": "X",
                    # Classic catastrophic backtrack on adversarial input.
                    "pattern": r"(?:a|aa)+b",
                    "score": 0.5,
                }],
            })
            assert plugin._patterns, "Heuristic was disabled — pattern should compile"

            adversarial = "a" * 60 + "c"
            for _ in range(rmod._PATTERN_SLOW_DISABLE_THRESHOLD):
                _ = plugin.detect(adversarial)
            # R66-2 fix: auto-disable is now TRANSIENT (cooldown
            # via `_disabled_until`) instead of permanent
            # (`_disabled = True`).  Either condition means the
            # pattern is currently disabled.
            import time as _time_mod
            p = plugin._patterns[0]
            disabled_now = (
                p._disabled
                or (p._disabled_until and _time_mod.monotonic() < p._disabled_until)
            )
            assert disabled_now, (
                "After threshold consecutive timeouts the pattern must auto-disable "
                "(either permanent _disabled or transient _disabled_until)"
            )
        finally:
            rmod._PATTERN_TIME_BUDGET_S = original_budget

    def test_regex_library_is_available(self):
        """The hard-timeout fix requires the ``regex`` library."""
        from scruxy.plugin import regex as rmod
        assert rmod._HAS_REGEX_LIB, (
            "The 'regex' library must be installed for hard regex timeouts; "
            "check pyproject.toml dependencies"
        )


# ---------------------------------------------------------------------------
# A4 — Forward proxy fail-closed when token_map is None for matched provider
# ---------------------------------------------------------------------------

class TestA4_TokenMapFailClosed:
    @pytest.mark.asyncio
    async def test_matched_provider_with_none_token_map_returns_503(self):
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        provider = MagicMock()
        provider.name = "test"
        provider.upstream_url = "https://api.example.com"
        provider.extract_session_id = MagicMock(return_value="sess-x")
        provider.match_request_body_text_fields = MagicMock(return_value=[])

        registry = MagicMock()
        registry.match = MagicMock(return_value=provider)
        registry.match_disabled = MagicMock(return_value=None)

        # Session store always returns None to simulate transient SQLite hiccup.
        session_store = MagicMock()
        session_store.get_or_create_session = AsyncMock(return_value=None)

        request_scrubber = MagicMock()
        pipeline = MagicMock()

        server = ForwardProxyServer(
            host="127.0.0.1",
            port=0,
            ca=MagicMock(),
            registry=registry,
            pipeline=pipeline,
            session_store=session_store,
            request_scrubber=request_scrubber,
            response_unscrubber=MagicMock(),
        )

        status, headers, body = await server._scrub_and_forward(
            method="POST",
            url="https://api.example.com/v1/messages",
            headers={"content-type": "application/json"},
            body=b'{"messages": [{"role": "user", "content": "hi"}]}',
        )
        assert status == 503

    @pytest.mark.asyncio
    async def test_session_store_exception_returns_503(self):
        """Even if get_or_create_session raises, must fail closed."""
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        provider = MagicMock()
        provider.name = "test"
        provider.upstream_url = "https://api.example.com"
        provider.extract_session_id = MagicMock(return_value="sess-x")

        registry = MagicMock()
        registry.match = MagicMock(return_value=provider)
        registry.match_disabled = MagicMock(return_value=None)

        session_store = MagicMock()
        session_store.get_or_create_session = AsyncMock(
            side_effect=RuntimeError("disk full"),
        )

        server = ForwardProxyServer(
            host="127.0.0.1", port=0, ca=MagicMock(),
            registry=registry, pipeline=MagicMock(),
            session_store=session_store,
            request_scrubber=MagicMock(), response_unscrubber=MagicMock(),
        )

        status, _, _ = await server._scrub_and_forward(
            method="POST",
            url="https://api.example.com/v1/messages",
            headers={"content-type": "application/json"},
            body=b'{"messages": []}',
        )
        assert status == 503


# ---------------------------------------------------------------------------
# A5 — Forward proxy strict decompression for unsupported encodings
# ---------------------------------------------------------------------------

class TestA5_StrictDecompression:
    def test_unsupported_encoding_strict_raises(self):
        from scruxy.proxy.forward_proxy import _decompress_body, DecompressLimitExceeded
        with pytest.raises(DecompressLimitExceeded):
            _decompress_body(b"opaque", "zstd", strict=True)

    def test_unsupported_encoding_lenient_returns_raw(self):
        from scruxy.proxy.forward_proxy import _decompress_body
        assert _decompress_body(b"opaque", "zstd") == b"opaque"

    def test_corrupt_gzip_strict_raises(self):
        from scruxy.proxy.forward_proxy import _decompress_body, DecompressLimitExceeded
        with pytest.raises(DecompressLimitExceeded):
            _decompress_body(b"not actually gzipped here", "gzip", strict=True)

    def test_identity_passes_through(self):
        from scruxy.proxy.forward_proxy import _decompress_body
        assert _decompress_body(b"plain", "identity", strict=True) == b"plain"
        assert _decompress_body(b"plain", "identity") == b"plain"

    def test_brotli_always_fails_closed(self):
        from scruxy.proxy.forward_proxy import _decompress_body, DecompressLimitExceeded
        with pytest.raises(DecompressLimitExceeded):
            _decompress_body(b"\x00\x80abc", "br")
        with pytest.raises(DecompressLimitExceeded):
            _decompress_body(b"\x00\x80abc", "br", strict=True)


# ---------------------------------------------------------------------------
# A6 — UI tester/state added to sensitive GET allowlist
# ---------------------------------------------------------------------------

class TestA6_TesterStateSensitive:
    def test_tester_state_in_sensitive_list(self):
        # Inspect the source — _SENSITIVE_GET_PREFIXES is a closure local
        # so we read the file directly to assert presence.
        path = Path(__file__).parent.parent / "src" / "scruxy" / "ui" / "routes.py"
        src = path.read_text(encoding="utf-8")
        assert '"/ui/api/tester/state"' in src, (
            "Tester state endpoint must be in _SENSITIVE_GET_PREFIXES"
        )


# ---------------------------------------------------------------------------
# A7 — Reverse proxy body size cap
# ---------------------------------------------------------------------------

class TestA7_ReverseProxyBodyCap:
    @pytest.mark.asyncio
    async def test_oversized_streamed_body_returns_413(self):
        from fastapi import FastAPI
        from scruxy.proxy.routes import router, _MAX_REQUEST_BODY_SIZE

        app = FastAPI()
        # Provide a forwarder so we get past the 503 guard.
        app.state.forwarder = MagicMock()
        app.include_router(router)

        async def _big_stream():
            chunk = b"x" * (1024 * 1024)  # 1 MiB
            for _ in range(_MAX_REQUEST_BODY_SIZE // len(chunk) + 2):
                yield chunk

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post("/v1/messages", content=_big_stream())
        assert resp.status_code == 413

    @pytest.mark.asyncio
    async def test_oversized_advertised_content_length_rejected_early(self):
        # End-to-end: advertised Content-Length over the cap returns 413
        # BEFORE buffering any body.
        from fastapi import FastAPI
        from scruxy.proxy.routes import router, _MAX_REQUEST_BODY_SIZE

        app = FastAPI()
        app.state.forwarder = MagicMock()
        app.include_router(router)

        # Build a body of 1 byte but advertise an enormous Content-Length.
        # Use the underlying transport so httpx doesn't recompute the header.
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            req = client.build_request(
                "POST", "/v1/messages",
                headers={"content-length": str(_MAX_REQUEST_BODY_SIZE + 1)},
                content=b"x",
            )
            # Force the header value httpx computed
            req.headers["content-length"] = str(_MAX_REQUEST_BODY_SIZE + 1)
            resp = await client.send(req)
        assert resp.status_code == 413

    @pytest.mark.asyncio
    async def test_oversized_advertised_content_length_helper_raises(self):
        from scruxy.proxy.routes import _build_proxy_request, _MAX_REQUEST_BODY_SIZE, RequestBodyTooLarge

        class _FakeReq:
            method = "POST"
            url = "http://x/v1/messages"
            headers = {"content-length": str(_MAX_REQUEST_BODY_SIZE + 1)}
            async def stream(self):
                if False:
                    yield b""

        with pytest.raises(RequestBodyTooLarge):
            await _build_proxy_request(_FakeReq(), "v1/messages")


# ---------------------------------------------------------------------------
# A8 — Passthrough body capture default-off
# ---------------------------------------------------------------------------

class TestA8_PassthroughBodyCaptureDefaultOff:
    def test_routes_log_omits_body_by_default(self):
        # Static check: verify the toggle exists in routes.py.
        path = Path(__file__).parent.parent / "src" / "scruxy" / "proxy" / "routes.py"
        src = path.read_text(encoding="utf-8")
        assert "passthrough_capture_bodies" in src
        assert "capture_bodies = bool(getattr(state, \"passthrough_capture_bodies\", False))" in src

    def test_forward_proxy_capture_bodies_ref_exists(self):
        path = Path(__file__).parent.parent / "src" / "scruxy" / "proxy" / "forward_proxy.py"
        src = path.read_text(encoding="utf-8")
        assert "_passthrough_capture_bodies_ref" in src


# ---------------------------------------------------------------------------
# A9 — CONNECT relay idle timeout
# ---------------------------------------------------------------------------

class TestA9_ConnectRelayIdleTimeout:
    def test_relay_uses_wait_for(self):
        path = Path(__file__).parent.parent / "src" / "scruxy" / "proxy" / "forward_proxy.py"
        src = path.read_text(encoding="utf-8")
        # Idle timeout constant declared
        assert "_TUNNEL_IDLE_TIMEOUT_S" in src
        # Used in the relay loop
        assert "asyncio.wait_for(\n                            src.read" in src or \
               "wait_for(" in src and "src.read(_TUNNEL_BUF_SIZE)" in src


# ---------------------------------------------------------------------------
# A10 — Bounded LRU host cert cache
# ---------------------------------------------------------------------------

class TestA10_HostCertLRU:
    def test_cache_evicts_lru(self, tmp_path):
        from scruxy.cert.ca import CertificateAuthority
        ca = CertificateAuthority(tmp_path)
        # Shrink the cap for the test.
        ca._host_cache_max = 3
        for i in range(5):
            ca.get_host_cert(f"host{i}.example.com")
        assert len(ca._host_cache) == 3
        # Oldest two (host0, host1) should have been evicted.
        assert "host0.example.com" not in ca._host_cache
        assert "host1.example.com" not in ca._host_cache
        assert "host4.example.com" in ca._host_cache

    def test_cache_lru_promotes_on_access(self, tmp_path):
        from scruxy.cert.ca import CertificateAuthority
        ca = CertificateAuthority(tmp_path)
        ca._host_cache_max = 3
        ca.get_host_cert("a.example.com")
        ca.get_host_cert("b.example.com")
        ca.get_host_cert("c.example.com")
        # Access 'a' — promotes to most recent.
        ca.get_host_cert("a.example.com")
        # Insert a new one — should evict 'b', not 'a'.
        ca.get_host_cert("d.example.com")
        assert "a.example.com" in ca._host_cache
        assert "b.example.com" not in ca._host_cache


# ---------------------------------------------------------------------------
# A11 — Deep JSON deanonymization depth limit
# ---------------------------------------------------------------------------

class TestA11_DeepJsonDepthLimit:
    def test_deeply_nested_does_not_crash(self):
        from scruxy.scrubber.sse_stream_unscrubber import (
            _deanonymize_json_deep, _DEEP_JSON_MAX_DEPTH,
        )
        # Build a structure that nests 2× the cap.
        depth = _DEEP_JSON_MAX_DEPTH * 2
        node: Any = "REDACTED_X_1"
        for _ in range(depth):
            node = {"k": node}

        token_map = MagicMock()
        token_map.unscrub_map = {"REDACTED_X_1": "alice"}

        # Should NOT raise RecursionError.
        out = _deanonymize_json_deep(node, token_map)
        assert isinstance(out, dict)


# ---------------------------------------------------------------------------
# A12 — casefold() instead of lower() in second-pass rescan
# ---------------------------------------------------------------------------

class TestA12_CasefoldSecondPass:
    def test_request_scrubber_uses_casefold(self):
        path = Path(__file__).parent.parent / "src" / "scruxy" / "scrubber" / "request_scrubber.py"
        src = path.read_text(encoding="utf-8")
        # The .lower() call on the second-pass text MUST be gone in
        # favour of .casefold().  We pinpoint the rescan section.
        snippet = src[src.find("Use casefold()"):src.find("Use casefold()") + 1500]
        assert ".casefold()" in snippet
        # And ensure the old .lower() comparison is gone from this block.
        assert "all_scrubbed_lower = all_scrubbed_text.lower()" not in src


# ---------------------------------------------------------------------------
# A13 — Plugin auto-disable after consecutive timeouts
# ---------------------------------------------------------------------------

class TestA13_PluginAutoDisable:
    def test_consecutive_timeouts_disable_plugin(self, tmp_path):
        from scruxy.pipeline.plugin_stage import PluginStage

        # Write a slow plugin that sleeps longer than the timeout.
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "slow.py").write_text(
            "import time\n"
            "from scruxy.plugin.base import DetectorPlugin, PiiEntity\n"
            "class SlowPlugin(DetectorPlugin):\n"
            "    name = 'slow'\n"
            "    def setup(self, config):\n"
            "        pass\n"
            "    def detect(self, text, language=''):\n"
            "        time.sleep(1.0)\n"
            "        return []\n"
        )
        stage = PluginStage(str(plugin_dir), timeout_ms=10)
        stage._plugin_timeout_threshold = 2  # Disable after 2 timeouts
        stage.load_plugins()

        # Trigger 2 timeouts.
        for _ in range(2):
            stage.detect("hello", language="en")

        assert "slow" in stage._plugin_auto_disabled


# ---------------------------------------------------------------------------
# A14 — UI SSE connection cap
# ---------------------------------------------------------------------------

class TestA14_UiSseCap:
    def test_sse_connection_cap_constant_exists(self):
        from scruxy.ui import routes
        assert hasattr(routes, "_UI_SSE_MAX_CONNECTIONS")
        assert routes._UI_SSE_MAX_CONNECTIONS > 0
        assert hasattr(routes, "_ui_sse_active_count")

    @pytest.mark.asyncio
    async def test_over_cap_returns_503(self, monkeypatch):
        from scruxy.ui import routes as ui_routes
        # Force the global counter to the cap so the next request 503s.
        monkeypatch.setattr(ui_routes, "_UI_SSE_MAX_CONNECTIONS", 1)
        monkeypatch.setattr(ui_routes, "_ui_sse_active_count", 1)

        from fastapi import FastAPI
        app = FastAPI()
        # ui_routes.router already has prefix="/ui"
        app.include_router(ui_routes.router)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/ui/api/events")
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# A15 — SSE [DONE] framing yields blank chunk
# ---------------------------------------------------------------------------

class TestA15_SseDoneFraming:
    def test_done_branch_yields_blank_separator_in_source(self):
        """The [DONE] branch must yield a blank chunk after the flush
        event so the chunk + b'\\n' framing produces \\n\\n."""
        path = Path(__file__).parent.parent / "src" / "scruxy" / "scrubber" / "sse_stream_unscrubber.py"
        src = path.read_text(encoding="utf-8")
        # Find the [DONE] branch and verify it yields b"" right after
        # yielding the rebuilt synthesized data event.
        done_block_start = src.find("if event_data.strip() == \"[DONE]\":")
        assert done_block_start != -1
        done_block = src[done_block_start:done_block_start + 1500]
        assert "yield f\"data: {rebuilt}\".encode(\"utf-8\")" in done_block
        # The blank-chunk separator MUST appear inside the flush block,
        # before the [DONE] line is yielded.
        flush_yield = done_block.find("yield f\"data: {rebuilt}\".encode(\"utf-8\")")
        rest_after = done_block[flush_yield:]
        # Next non-blank meaningful line within ~10 lines should be `yield b""`
        assert "yield b\"\"" in rest_after.split("yield line.encode")[0]

    def test_post_loop_flush_yields_blank_separator(self):
        path = Path(__file__).parent.parent / "src" / "scruxy" / "scrubber" / "sse_stream_unscrubber.py"
        src = path.read_text(encoding="utf-8")
        # The post-loop end-of-stream flush has the same defect; verify
        # it also yields b"" after the synthesized data event.
        idx = src.find("# Flush remaining buffer content at end of stream")
        assert idx != -1
        block = src[idx:idx + 1500]
        assert "yield f\"data: {rebuilt}\".encode(\"utf-8\")" in block
        assert "yield b\"\"" in block

    @pytest.mark.asyncio
    async def test_done_actually_emits_blank_chunk(self):
        """Behavioural test: drive the unscrubber with a stream whose
        last data event has a trailing token-prefix held in the buffer."""
        from scruxy.scrubber.sse_stream_unscrubber import SSEStreamUnscrubber
        from scruxy.providers.base import SSETextField

        provider = MagicMock()
        def _parse(d):
            try:
                obj = json.loads(d)
                return SSETextField(text_value=obj.get("text", ""))
            except Exception:
                return None
        provider.parse_sse_event = _parse
        provider.rebuild_sse_event = lambda d, txt: json.dumps({"text": txt})

        # Use a real-style token that will be held back as a partial.
        # We build a minimal token_map with unscrub_map so the trie sees
        # "REDACTED_X_1" — the buffer will hold any prefix of that.
        class _TM:
            unscrub_map = {"REDACTED_X_1": "alice"}
            _unscrub = {"REDACTED_X_1": "alice"}
            _token_version = 1
        token_map = _TM()
        unscrubber = SSEStreamUnscrubber(provider, token_map)

        async def _stream():
            # The text ends with "REDACT" — a prefix of REDACTED_X_1, so
            # the rolling buffer holds "REDACT" back until [DONE].
            yield 'data: {"text": "Hello REDACT"}'
            yield 'data: [DONE]'

        out: list[bytes] = []
        async for chunk in unscrubber.process_sse_stream(_stream()):
            out.append(chunk)

        # The synthesized flush event AND a blank separator MUST appear
        # before the [DONE] line, so callers' "chunk + b'\\n'" framing
        # produces "\\n\\n" between them.
        done_idx = out.index(b"data: [DONE]")
        # Walk back from [DONE]: previous chunk should be b"" and the
        # one before that should be the synthesized flush event.
        assert out[done_idx - 1] == b"", out


# ---------------------------------------------------------------------------
# A16 — Forward proxy header read deadline
# ---------------------------------------------------------------------------

class TestA16_HeaderReadDeadline:
    @pytest.mark.asyncio
    async def test_slow_loris_header_read_returns_empty(self, monkeypatch):
        import scruxy.proxy.forward_proxy as fp

        # Shrink the deadline for the test.
        monkeypatch.setattr(fp, "_HEADER_READ_TIMEOUT_S", 0.5)

        # Build a fake reader that never sends the terminator.
        class _SlowReader:
            async def read(self, n):
                await asyncio.sleep(2.0)
                return b"X"

        server = fp.ForwardProxyServer(
            host="127.0.0.1", port=0, ca=MagicMock(),
            registry=MagicMock(), pipeline=MagicMock(),
            session_store=MagicMock(),
            request_scrubber=MagicMock(), response_unscrubber=MagicMock(),
        )

        head, leftover = await server._read_head(_SlowReader(), b"")
        assert head == ""
        assert leftover == b""

    @pytest.mark.asyncio
    async def test_chunked_body_read_honors_deadline(self):
        """A slow chunked body must not pin the worker forever."""
        from scruxy.proxy.forward_proxy import _read_chunked_body

        class _SlowReader:
            async def read(self, n):
                await asyncio.sleep(5.0)
                return b""

        loop = asyncio.get_event_loop()
        deadline = loop.time() + 0.3

        with pytest.raises(asyncio.TimeoutError):
            await _read_chunked_body(_SlowReader(), b"", deadline=deadline)


# ---------------------------------------------------------------------------
# A17 — JSON migration idempotent via _migrations table
# ---------------------------------------------------------------------------

class TestA17_MigrationIdempotent:
    def test_second_migration_is_skipped(self, tmp_path):
        from scruxy.tokenmap.db import TokenDB

        # Build a JSON token map.
        json_path = tmp_path / "token_map.json"
        json_path.write_text(json.dumps({
            "scrub": {"alice": "REDACTED_PERSON_1"},
            "entity_types": {"alice": "PERSON"},
            "counters": {"PERSON": 1},
        }))

        db_path = tmp_path / "tokens.db"
        db = TokenDB(str(db_path))
        db.open()
        try:
            n1 = db.migrate_from_json(json_path)
            assert n1 == 1

            # Simulate a crash that left the JSON in place (rename failed):
            # restore the source file and re-run.
            bak = json_path.with_suffix(".json.bak")
            if bak.exists():
                bak.rename(json_path)

            n2 = db.migrate_from_json(json_path)
            assert n2 == 0, "Second migration must be skipped (idempotent)"
        finally:
            db.close()

    def test_migration_marker_persisted(self, tmp_path):
        from scruxy.tokenmap.db import TokenDB

        json_path = tmp_path / "token_map.json"
        json_path.write_text(json.dumps({"scrub": {"a": "REDACTED_X_1"}}))
        db = TokenDB(str(tmp_path / "tokens.db"))
        db.open()
        try:
            db.migrate_from_json(json_path)
            row = db._c.execute(
                "SELECT name FROM _migrations WHERE name LIKE 'json_import:%'"
            ).fetchone()
            assert row is not None
        finally:
            db.close()
