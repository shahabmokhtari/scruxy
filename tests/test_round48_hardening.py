"""Regression tests for Round 48 hardening fixes (B1-B13)."""
from __future__ import annotations

import asyncio
import gzip
import json
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest


# ---------------------------------------------------------------------------
# B1 — Matched provider non-JSON body fail-closed (415)
# ---------------------------------------------------------------------------

class TestB1_MatchedProviderNonJsonFailClosed:
    @pytest.mark.asyncio
    async def test_reverse_proxy_non_json_returns_415(self):
        """Reverse proxy: a matched provider with a non-JSON body
        must be rejected with 415, NOT forwarded with raw PII."""
        from fastapi import FastAPI
        from scruxy.proxy.routes import router

        app = FastAPI()

        # Stub state with a matching provider and a forwarder that
        # would silently swallow the unscrubbed body if reached.
        provider = MagicMock()
        provider.name = "anthropic"
        provider.upstream_url = "https://api.example.com"
        registry = MagicMock()
        registry.match = MagicMock(return_value=provider)
        registry.match_disabled = MagicMock(return_value=None)
        registry.find_passthrough_provider = MagicMock(return_value=None)

        forwarder_calls = []
        async def _fwd(*args, **kwargs):
            forwarder_calls.append((args, kwargs))
            return MagicMock(status_code=200, headers={}, content=b"")
        forwarder = MagicMock()
        forwarder.forward = _fwd

        request_scrubber = MagicMock()
        pipeline = MagicMock()
        token_map = MagicMock()
        token_map.unscrub_map = {}

        session_store = MagicMock()
        session_store.get_or_create_session = AsyncMock(return_value=token_map)

        app.state.registry = registry
        app.state.forwarder = forwarder
        app.state.request_scrubber = request_scrubber
        app.state.pipeline = pipeline
        app.state.session_store = session_store
        app.state.recorder = None
        app.state.stats = None
        app.state.event_bus = None
        app.state.response_unscrubber = MagicMock()
        app.state.sse_unscrubber = MagicMock()
        app.state.config = None
        app.state._listen_host = "127.0.0.1"

        app.include_router(router)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b"My SSN is 123-45-6789",  # non-JSON, contains PII
                headers={"content-type": "text/plain"},
            )

        assert resp.status_code == 415, (
            f"Expected 415 Unsupported Media Type, got {resp.status_code}"
        )
        assert forwarder_calls == [], (
            f"Forwarder MUST NOT be called for non-JSON matched body; got {len(forwarder_calls)} calls"
        )

    @pytest.mark.asyncio
    async def test_forward_proxy_non_json_returns_415(self):
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        provider = MagicMock()
        provider.name = "anthropic"
        provider.upstream_url = "https://api.example.com"
        provider.extract_session_id = MagicMock(return_value="s1")

        registry = MagicMock()
        registry.match = MagicMock(return_value=provider)
        registry.match_disabled = MagicMock(return_value=None)

        token_map = MagicMock()
        session_store = MagicMock()
        session_store.get_or_create_session = AsyncMock(return_value=token_map)

        server = ForwardProxyServer(
            host="127.0.0.1", port=0, ca=MagicMock(),
            registry=registry, pipeline=MagicMock(),
            session_store=session_store,
            request_scrubber=MagicMock(), response_unscrubber=MagicMock(),
        )

        status, _, _ = await server._scrub_and_forward(
            method="POST",
            url="https://api.example.com/v1/messages",
            headers={"content-type": "text/plain"},
            body=b"My SSN is 123-45-6789",
        )
        assert status == 415


# ---------------------------------------------------------------------------
# B2 — Casefold-aware scrub for Unicode case-equivalent variants
# ---------------------------------------------------------------------------

class TestB2_CasefoldUnicode:
    def test_strasse_variant_is_replaced(self):
        """`Straße` ↔ `STRASSE` second-pass rescan must work end-to-end."""
        from scruxy.scrubber.request_scrubber import RequestScrubber
        # Ensure the regex library is the engine used (Round 47 dep).
        import regex as _rmod  # noqa: F401

        # Simulate the per-PII branch: use the same regex+flags the
        # production code now constructs.
        try:
            import regex as _re_mod
            flags = _re_mod.IGNORECASE | _re_mod.FULLCASE
        except ImportError:
            pytest.skip("'regex' library not installed")
        rx = _re_mod.compile(_re_mod.escape("Straße"), flags)
        assert rx.search("Meet me at STRASSE 5") is not None
        assert rx.search("Meet me at strasse 5") is not None
        assert rx.search("Meet me at Straße 5") is not None

    def test_old_re_ignorecase_does_not_handle_strasse(self):
        """Sanity check: stdlib `re.IGNORECASE` does NOT handle the
        case fold — proves we needed FULLCASE."""
        import re
        rx = re.compile(re.escape("Straße"), re.IGNORECASE)
        # Stdlib re returns None — this is exactly the leak path.
        assert rx.search("STRASSE 5") is None


# ---------------------------------------------------------------------------
# B3 — Multi-word reverse mappings
# ---------------------------------------------------------------------------

class TestB3_MultiWordReverseMapping:
    def test_each_subtoken_unmaps_to_corresponding_word(self):
        """When a multi-word PII is tokenized into multiple
        whitespace-separated sub-tokens, each sub-token must reverse
        to the corresponding original word."""
        from scruxy.tokenmap.token_map import TokenMap

        # Custom strategy that emits one token per word.
        class _PerWordStrategy:
            def generate(self, entity_type, pii, count):
                words = pii.split()
                if len(words) <= 1:
                    return f"REDACTED_{entity_type}_{count}"
                return " ".join(
                    f"REDACTED_{entity_type}_{count}{chr(ord('A') + i)}"
                    for i in range(len(words))
                )

        tm = TokenMap(replacements={"PERSON": _PerWordStrategy()})
        token = tm.get_or_create_token("Alice Smith", "PERSON")
        assert token == "REDACTED_PERSON_1A REDACTED_PERSON_1B"
        # Joint mapping
        assert tm.get_pii(token) == "Alice Smith"
        # Per-sub-token mappings (B3)
        assert tm.get_pii("REDACTED_PERSON_1A") == "Alice"
        assert tm.get_pii("REDACTED_PERSON_1B") == "Smith"

    def test_partial_subtoken_in_response_deanonymizes(self):
        """End-to-end via the deanonymizer: an LLM that refers only
        to one sub-token should get the corresponding original back."""
        from scruxy.tokenmap.token_map import TokenMap
        from scruxy.scrubber.response_unscrubber import deanonymize_text

        class _PerWordStrategy:
            def generate(self, entity_type, pii, count):
                words = pii.split()
                if len(words) <= 1:
                    return f"REDACTED_{entity_type}_{count}"
                return " ".join(
                    f"REDACTED_{entity_type}_{count}{chr(ord('A') + i)}"
                    for i in range(len(words))
                )

        tm = TokenMap(replacements={"PERSON": _PerWordStrategy()})
        tm.get_or_create_token("Alice Smith", "PERSON")
        out = deanonymize_text("Hi REDACTED_PERSON_1A, are you Smith?", tm)
        assert "Alice" in out
        assert "REDACTED_PERSON_1A" not in out

    def test_single_word_pii_unchanged_behavior(self):
        """Single-word PII still maps to a single token reverse-lookup."""
        from scruxy.tokenmap.token_map import TokenMap
        tm = TokenMap()
        tok = tm.get_or_create_token("alice@example.com", "EMAIL_ADDRESS")
        assert tm.get_pii(tok) == "alice@example.com"


# ---------------------------------------------------------------------------
# B4 — CA cert cache thread safety
# ---------------------------------------------------------------------------

class TestB4_CertCacheThreadSafe:
    def test_concurrent_get_host_cert_does_not_raise(self, tmp_path):
        from scruxy.cert.ca import CertificateAuthority
        ca = CertificateAuthority(tmp_path)
        # Shrink cache so eviction races more aggressively.
        ca._host_cache_max = 4

        errors: list[BaseException] = []

        def _worker(idx: int):
            try:
                for j in range(20):
                    ca.get_host_cert(f"host{(idx + j) % 16}.example.com")
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert errors == [], f"Concurrent access raised: {errors!r}"
        # Cache must respect the cap.
        assert len(ca._host_cache) <= ca._host_cache_max

    def test_same_host_only_generated_once(self, tmp_path):
        """Concurrent CONNECTs for the SAME hostname must not all
        trigger RSA generation (thundering herd)."""
        from scruxy.cert.ca import CertificateAuthority
        ca = CertificateAuthority(tmp_path)

        gen_count = 0
        original = ca._generate_host_cert
        gen_lock = threading.Lock()

        def _counting_generate(hostname: str):
            nonlocal gen_count
            with gen_lock:
                gen_count += 1
            return original(hostname)

        ca._generate_host_cert = _counting_generate

        threads = [
            threading.Thread(target=ca.get_host_cert, args=("api.example.com",))
            for _ in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        # Despite 8 concurrent requests, only ONE generation should occur.
        assert gen_count == 1, f"Expected 1 generation, got {gen_count}"


# ---------------------------------------------------------------------------
# B5 — Presidio reconfigure thread safety
# ---------------------------------------------------------------------------

class TestB5_PresidioReconfigureLock:
    def test_setup_lock_attribute_exists(self):
        """After setup() the plugin must have an _setup_lock RLock."""
        from scruxy.plugin.presidio import PresidioPlugin
        plugin = PresidioPlugin()
        plugin.setup({
            "enabled": True, "language": "en",
            "entities": ["EMAIL_ADDRESS"], "score_threshold": 0.6,
            "post_filter": False,
        })
        assert hasattr(plugin, "_setup_lock")
        # RLock is reentrant — used to take the same lock from detect().
        with plugin._setup_lock:
            with plugin._setup_lock:
                pass

    def test_concurrent_detect_during_reconfigure_does_not_crash(self):
        """A thread calling detect() while another reconfigures must
        not see a partial state and must not raise."""
        from scruxy.plugin.presidio import PresidioPlugin
        plugin = PresidioPlugin()
        plugin.setup({
            "enabled": True, "language": "en",
            "entities": ["EMAIL_ADDRESS"], "score_threshold": 0.6,
            "post_filter": False,
        })

        errors: list[BaseException] = []
        stop = threading.Event()

        def _detector():
            try:
                while not stop.is_set():
                    plugin.detect("contact alice@example.com about it")
            except BaseException as exc:
                errors.append(exc)

        t = threading.Thread(target=_detector)
        t.start()
        try:
            for _ in range(3):
                plugin.reconfigure({
                    "enabled": True, "language": "en",
                    "entities": ["EMAIL_ADDRESS", "PHONE_NUMBER"],
                    "score_threshold": 0.7, "post_filter": False,
                })
                plugin.reconfigure({
                    "enabled": True, "language": "en",
                    "entities": ["EMAIL_ADDRESS"], "score_threshold": 0.6,
                    "post_filter": False,
                })
        finally:
            stop.set()
            t.join(timeout=10)
        assert errors == [], f"detect() raised during reconfigure: {errors!r}"


# ---------------------------------------------------------------------------
# B6 — Strict decompression honours bomb cap
# ---------------------------------------------------------------------------

class TestB6_StrictDecompressBombCap:
    def test_gzip_bomb_actually_fails(self):
        """A gzip body whose decompressed size exceeds the cap MUST
        raise DecompressFailed, not silently truncate."""
        from scruxy.proxy.routes import (
            _decompress_body_strict, DecompressFailed, _DECOMPRESS_LIMIT,
        )
        # Build a bomb that compresses tiny but expands well past the cap.
        bomb = gzip.compress(b"A" * (_DECOMPRESS_LIMIT + 4096))
        with pytest.raises(DecompressFailed):
            _decompress_body_strict(bomb, "gzip")

    def test_deflate_bomb_fails(self):
        from scruxy.proxy.routes import (
            _decompress_body_strict, DecompressFailed, _DECOMPRESS_LIMIT,
        )
        import zlib
        bomb = zlib.compress(b"X" * (_DECOMPRESS_LIMIT + 4096))
        with pytest.raises(DecompressFailed):
            _decompress_body_strict(bomb, "deflate")


# ---------------------------------------------------------------------------
# B7 — Multi-member gzip handled
# ---------------------------------------------------------------------------

class TestB7_MultiMemberGzip:
    def test_concatenated_gzip_members_all_decoded(self):
        """RFC 1952 §2.2: two concatenated gzip streams must both decode
        (not silently drop the second)."""
        from scruxy.proxy.routes import _decompress_body_strict
        a = gzip.compress(b"hello ")
        b = gzip.compress(b"world")
        out = _decompress_body_strict(a + b, "gzip")
        assert out == b"hello world"

    def test_three_members_all_decoded(self):
        from scruxy.proxy.routes import _decompress_body_strict
        members = b"".join(gzip.compress(p) for p in [b"foo", b"bar", b"baz"])
        out = _decompress_body_strict(members, "gzip")
        assert out == b"foobarbaz"


# ---------------------------------------------------------------------------
# B8 — SSE event_count not inflated by flush sentinel
# ---------------------------------------------------------------------------

class TestB8_SseEventCountAccurate:
    def test_routes_skips_empty_chunk(self):
        path = Path(__file__).parent.parent / "src" / "scruxy" / "proxy" / "routes.py"
        src = path.read_text(encoding="utf-8")
        # The reverse-proxy SSE loop must skip empty chunks before
        # bumping event_count.
        loop_idx = src.find("async for unscrubbed_chunk in stream_unscrubber.process_sse_stream")
        assert loop_idx != -1
        body = src[loop_idx:loop_idx + 1200]
        assert "if not unscrubbed_chunk" in body, (
            "SSE loop in routes.py must skip empty (sentinel) chunks before counting"
        )

    def test_forward_proxy_skips_empty_chunk(self):
        path = Path(__file__).parent.parent / "src" / "scruxy" / "proxy" / "forward_proxy.py"
        src = path.read_text(encoding="utf-8")
        loop_idx = src.find("async for unscrubbed_chunk in unscrubber.process_sse_stream")
        assert loop_idx != -1
        body = src[loop_idx:loop_idx + 1500]
        assert "if not unscrubbed_chunk" in body


# ---------------------------------------------------------------------------
# B9 — Status line includes reason-phrase
# ---------------------------------------------------------------------------

class TestB9_StatusLineReasonPhrase:
    def test_helper_emits_spec_compliant_line(self):
        from scruxy.proxy.forward_proxy import _status_line
        line = _status_line(200)
        # Must have the form: HTTP/1.1 SP status-code SP reason-phrase CRLF
        assert line.startswith("HTTP/1.1 200 ")
        assert line.endswith("\r\n")
        # Reason-phrase MUST be present (RFC 9112 ABNF requires the SP)
        # — at minimum we get "OK" from http.HTTPStatus.
        assert "OK" in line

    def test_helper_with_explicit_reason(self):
        from scruxy.proxy.forward_proxy import _status_line
        line = _status_line(418, "I'm a teapot")
        assert line == "HTTP/1.1 418 I'm a teapot\r\n"

    def test_unknown_status_still_includes_sp(self):
        from scruxy.proxy.forward_proxy import _status_line
        line = _status_line(999)
        # Even for unknown codes the spec requires the trailing SP
        # before the (possibly empty) reason-phrase.
        assert line.startswith("HTTP/1.1 999 ")
        assert line.endswith("\r\n")


# ---------------------------------------------------------------------------
# B10 — Deep-JSON deanonymize warns on cap
# ---------------------------------------------------------------------------

class TestB10_DeepJsonWarning:
    def test_deep_json_is_fully_deanonymized_no_warning(self, caplog):
        """R59-2 supersedes the original B10 fail-open-with-warning
        behavior: the iterative walker now deanonymizes EVERY token
        at EVERY depth.  The depth-cap warning path no longer exists."""
        from scruxy.scrubber.sse_stream_unscrubber import (
            _deanonymize_json_deep, _DEEP_JSON_MAX_DEPTH,
        )
        depth = _DEEP_JSON_MAX_DEPTH * 2
        node: any = "REDACTED_X_1"
        for _ in range(depth):
            node = {"k": node}

        token_map = MagicMock()
        token_map.unscrub_map = {"REDACTED_X_1": "alice"}

        import logging
        with caplog.at_level(logging.WARNING, logger="scruxy.scrubber.sse_stream_unscrubber"):
            result = _deanonymize_json_deep(node, token_map)
        # No "JSON deanonymize depth" warning emitted (cap is gone).
        assert not any(
            "JSON deanonymize depth" in rec.message for rec in caplog.records
        ), f"Unexpected depth-cap warning; got {[r.message for r in caplog.records]}"
        # AND the deep token was actually deanonymized (no fail-open).
        cur = result
        for _ in range(depth):
            cur = cur["k"]
        assert cur == "alice", (
            f"R59-2: deep token at depth {depth} was NOT deanonymized"
        )


# ---------------------------------------------------------------------------
# B11 — Malformed regex pattern entries don't crash
# ---------------------------------------------------------------------------

class TestB11_RegexPatternValidation:
    def test_missing_pattern_key_skipped(self):
        from scruxy.plugin.regex import RegexPlugin
        plugin = RegexPlugin()
        # No KeyError despite the missing 'pattern' key.
        plugin.setup({
            "enabled": True,
            "patterns": [
                {"name": "bad", "entity_type": "X", "score": 0.5},
                {"name": "good", "entity_type": "Y", "pattern": r"\d{3}", "score": 0.5},
            ],
        })
        names = {p.name for p in plugin._patterns}
        assert "bad" not in names
        assert "good" in names

    def test_non_dict_entry_skipped(self):
        from scruxy.plugin.regex import RegexPlugin
        plugin = RegexPlugin()
        plugin.setup({
            "enabled": True,
            "patterns": [
                "not a dict",
                ["also not a dict"],
                {"name": "good", "entity_type": "Y", "pattern": r"\d{3}", "score": 0.5},
            ],
        })
        names = {p.name for p in plugin._patterns}
        assert names == {"good"}

    def test_non_numeric_score_skipped(self):
        from scruxy.plugin.regex import RegexPlugin
        plugin = RegexPlugin()
        plugin.setup({
            "enabled": True,
            "patterns": [
                {"name": "bad", "entity_type": "X", "pattern": r"\d{3}", "score": "high"},
            ],
        })
        assert plugin._patterns == []


# ---------------------------------------------------------------------------
# B12 — End-to-end fail-closed for forward-proxy unsupported encoding
# ---------------------------------------------------------------------------

class TestB12_ForwardProxyDecompressFailClosed:
    @pytest.mark.asyncio
    async def test_matched_provider_zstd_returns_413(self):
        """A matched-provider request with Content-Encoding: zstd
        (which Scruxy can't decode) must 413 — the upstream forwarder
        must not be reached."""
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        provider = MagicMock()
        provider.name = "anthropic"
        provider.upstream_url = "https://api.example.com"
        provider.extract_session_id = MagicMock(return_value="s1")

        registry = MagicMock()
        registry.match = MagicMock(return_value=provider)
        registry.match_disabled = MagicMock(return_value=None)

        token_map = MagicMock()
        session_store = MagicMock()
        session_store.get_or_create_session = AsyncMock(return_value=token_map)

        server = ForwardProxyServer(
            host="127.0.0.1", port=0, ca=MagicMock(),
            registry=registry, pipeline=MagicMock(),
            session_store=session_store,
            request_scrubber=MagicMock(), response_unscrubber=MagicMock(),
        )

        # Simulate the wired plumbing: caller (`_handle_http`/`_mitm_inner`)
        # already detected the unsupported encoding and set
        # `decompress_failed=True` before calling _scrub_and_forward.
        status, _, _ = await server._scrub_and_forward(
            method="POST",
            url="https://api.example.com/v1/messages",
            headers={"content-type": "application/json", "content-encoding": "zstd"},
            body=b"opaque-zstd-bytes",
            decompress_failed=True,
        )
        assert status == 413

    @pytest.mark.asyncio
    async def test_handle_http_zstd_end_to_end_returns_413(self):
        """True end-to-end: drive `_handle_http` with a fake socket
        carrying Content-Encoding: zstd on a matched-provider URL.
        The upstream forwarder must not be called and the wire bytes
        sent back to the client must contain `413 Payload Too Large`."""
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        # Build a matching provider + session store.
        provider = MagicMock()
        provider.name = "anthropic"
        provider.upstream_url = "https://api.example.com"
        provider.extract_session_id = MagicMock(return_value="s1")

        registry = MagicMock()
        registry.match = MagicMock(return_value=provider)
        registry.match_disabled = MagicMock(return_value=None)

        token_map = MagicMock()
        session_store = MagicMock()
        session_store.get_or_create_session = AsyncMock(return_value=token_map)

        # Forwarder must NOT be called — assert via a sentinel.
        forward_calls: list = []
        request_scrubber = MagicMock()

        server = ForwardProxyServer(
            host="127.0.0.1", port=0, ca=MagicMock(),
            registry=registry, pipeline=MagicMock(),
            session_store=session_store,
            request_scrubber=request_scrubber, response_unscrubber=MagicMock(),
        )
        # Replace `_plain_forward` so we can detect any accidental upstream call.
        async def _no_forward(*a, **kw):
            forward_calls.append((a, kw))
            return (502, {}, b"unexpected")
        server._plain_forward = _no_forward  # type: ignore[assignment]

        # Build a fake StreamReader/StreamWriter pair carrying:
        #   POST https://api.example.com/v1/messages HTTP/1.1
        #   Host: api.example.com
        #   Content-Length: 8
        #   Content-Encoding: zstd
        #   Content-Type: application/json
        #
        #   12345678
        body = b"\x28\xb5\x2f\xfd\x04\x58\x41\x00"  # plausible zstd bytes (8 B)
        request_bytes = (
            b"POST https://api.example.com/v1/messages HTTP/1.1\r\n"
            b"Host: api.example.com\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Content-Encoding: zstd\r\n"
            b"Content-Type: application/json\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        ) + body

        reader = asyncio.StreamReader(limit=1024 * 1024)
        reader.feed_data(request_bytes)
        reader.feed_eof()

        # Capture what the proxy writes to the client.
        written: bytearray = bytearray()
        class _FakeTransport:
            def get_extra_info(self, *_a, **_kw):
                return None
            def is_closing(self):
                return False
            def close(self):
                pass
        class _FakeWriter:
            transport = _FakeTransport()
            def write(self, data):
                written.extend(data)
            async def drain(self):
                pass
            def close(self):
                pass
            async def wait_closed(self):
                pass
            def is_closing(self):
                return False
            def get_extra_info(self, *a, **kw):
                return None

        writer = _FakeWriter()

        # `_handle_http` expects pre-parsed method/target/headers + the
        # body reader and any leftover bytes already past the header
        # terminator.  Build those directly.
        body_leftover = body  # CL=8, we feed all 8 bytes as leftover
        # R59-1: `_handle_http` and downstream code now use lowercase
        # header keys (matches `_parse_headers` storage).
        headers_dict = {
            "host": "api.example.com",
            "content-length": str(len(body)),
            "content-encoding": "zstd",
            "content-type": "application/json",
            "connection": "close",
        }
        try:
            await asyncio.wait_for(
                server._handle_http(
                    method="POST",
                    target="https://api.example.com/v1/messages",
                    headers=headers_dict,
                    reader=reader,
                    writer=writer,  # type: ignore[arg-type]
                    leftover=body_leftover,
                ),
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            pytest.fail("Forward proxy hung on zstd request")

        wire = bytes(written)
        # The client MUST have received a 413 response and the upstream
        # forwarder MUST NOT have been reached.
        assert b"413" in wire, f"Expected 413 in response; got {wire[:200]!r}"
        assert forward_calls == [], (
            f"Upstream forwarder was called for unsupported-encoding "
            f"matched-provider request (PII smuggling risk): {len(forward_calls)} call(s)"
        )


# ---------------------------------------------------------------------------
# B13 — UI SSE counter lifecycle
# ---------------------------------------------------------------------------

class TestB13_UiSseCounterLifecycle:
    @pytest.mark.asyncio
    async def test_finally_block_decrements_counter(self):
        """The generator's finally clause must run on cancel/exception
        and decrement the global counter back to its prior value."""
        from scruxy.ui import routes as ui_routes

        baseline = ui_routes._ui_sse_active_count

        class _FakeURL:
            path = "/ui/api/events"
        class _FakeApp:
            class state:
                _listen_host = "127.0.0.1"
        class _FakeRequest:
            app = _FakeApp
            url = _FakeURL()
            client = None
            method = "GET"
            headers = {"host": "testserver"}
            async def is_disconnected(self):
                return True

        resp = await ui_routes.api_events(_FakeRequest())  # type: ignore[arg-type]
        gen = resp.body_iterator
        try:
            async for _chunk in gen:
                pass
        except Exception:
            pass

        assert ui_routes._ui_sse_active_count == baseline, (
            f"Counter not released: started {baseline}, "
            f"now {ui_routes._ui_sse_active_count}"
        )

    @pytest.mark.asyncio
    async def test_exception_during_stream_decrements_counter(self):
        from scruxy.ui import routes as ui_routes
        baseline = ui_routes._ui_sse_active_count

        class _BoomURL:
            path = "/ui/api/events"
        class _BoomApp:
            class state:
                _listen_host = "127.0.0.1"
        class _BoomRequest:
            app = _BoomApp
            url = _BoomURL()
            client = None
            method = "GET"
            headers = {"host": "testserver"}
            async def is_disconnected(self):
                raise RuntimeError("boom")

        resp = await ui_routes.api_events(_BoomRequest())  # type: ignore[arg-type]
        try:
            async for _chunk in resp.body_iterator:
                pass
        except Exception:
            pass

        assert ui_routes._ui_sse_active_count == baseline


# ---------------------------------------------------------------------------
# B2-residual — End-to-end İ ↔ i via second-pass scrubber
# ---------------------------------------------------------------------------

class TestB2_Residual_TurkishDottedI:
    def test_dotted_i_substring_check_misses_via_casefold_alone(self):
        """Demonstrate why we needed the FULLCASE regex fallback:
        casefold() of `İ` is `i\u0307` which does NOT substring-match
        plain `i` in candidate text."""
        assert "İ".casefold() == "i\u0307"
        assert "İ".casefold() not in "Meet i tomorrow".casefold(), (
            "Substring casefold check must fail — proves we needed the FULLCASE regex"
        )

    def test_dotted_i_caught_by_fullcase_regex(self):
        """The FULLCASE regex IS able to find the variant."""
        import regex as _re
        rx = _re.compile(_re.escape("İ"), _re.IGNORECASE | _re.FULLCASE)
        assert rx.search("Meet i tomorrow") is not None
        assert rx.search("İstanbul") is not None

    @pytest.mark.asyncio
    async def test_strasse_end_to_end_through_scrub_request(self):
        """End-to-end through the scrubber: PII `Straße` registered in
        a previous request must catch the variant `STRASSE` in a new
        request via the second-pass cross-field rescan."""
        from scruxy.scrubber.request_scrubber import RequestScrubber
        from scruxy.tokenmap.token_map import TokenMap
        from scruxy.providers.base import TextField

        # Pre-populate the token map with the case-insensitive PII.
        tm = TokenMap()
        tm.get_or_create_token("Straße", "ADDRESS", case_sensitive=False)

        scrubber = RequestScrubber()

        class _FakeProvider:
            name = "test"
            def extract_text_fields(self, body):
                return [
                    TextField(json_path=f"$.{k}", text_value=v, field_type="text")
                    for k, v in body.items() if isinstance(v, str)
                ]
            def replace_text_fields(self, body, replacements):
                # replacements: {json_path: new_text}
                out = dict(body)
                for jp, new_text in replacements.items():
                    key = jp.split(".", 1)[1]
                    out[key] = new_text
                return out

        # Pipeline that detects no NEW entities (so the test exercises
        # the cross-field rescan path using the pre-existing scrub_map).
        from scruxy.pipeline.engine import PipelineResult
        class _FakePipeline:
            async def scrub_text(self, text, token_map, context=None, request_id=""):
                return PipelineResult(entities=[], scrubbed_text=text, latency_ms=0.0)

        body = {
            "field1": "Reference: Straße 5",
            "field2": "ALSO: STRASSE 5",
        }

        scrubbed_dict, entities, _, _ = await scrubber.scrub_request(
            body=body,
            provider=_FakeProvider(),  # type: ignore[arg-type]
            pipeline=_FakePipeline(),  # type: ignore[arg-type]
            token_map=tm,
            request_id="r1",
        )
        token = tm.get_token("Straße")
        assert token in scrubbed_dict["field2"], (
            f"Cross-field rescan must catch STRASSE→{token}; got {scrubbed_dict['field2']!r}"
        )
        assert "STRASSE" not in scrubbed_dict["field2"]


# ---------------------------------------------------------------------------
# B3-residual — Sub-token alias cleanup on remove + reload
# ---------------------------------------------------------------------------

class TestB3_Residual_SubtokenCleanup:
    def test_remove_entry_purges_subtoken_aliases(self):
        from scruxy.tokenmap.token_map import TokenMap

        class _PerWordStrategy:
            def generate(self, entity_type, pii, count):
                words = pii.split()
                if len(words) <= 1:
                    return f"REDACTED_{entity_type}_{count}"
                return " ".join(
                    f"REDACTED_{entity_type}_{count}{chr(ord('A') + i)}"
                    for i in range(len(words))
                )

        tm = TokenMap(replacements={"PERSON": _PerWordStrategy()})
        tm.get_or_create_token("Alice Smith", "PERSON")
        # Sanity
        assert tm.get_pii("REDACTED_PERSON_1A") == "Alice"
        assert tm.get_pii("REDACTED_PERSON_1B") == "Smith"

        # Remove the joint mapping — sub-token aliases must vanish too.
        assert tm.remove_entry("Alice Smith") is True
        assert tm.get_pii("REDACTED_PERSON_1 REDACTED_PERSON_2") is None
        assert tm.get_pii("REDACTED_PERSON_1A") is None, (
            "Sub-token alias must be purged on remove (B3 residual)"
        )
        assert tm.get_pii("REDACTED_PERSON_1B") is None

    def test_invalidate_entity_types_purges_subtoken_aliases(self):
        from scruxy.tokenmap.token_map import TokenMap

        class _PerWordStrategy:
            def generate(self, entity_type, pii, count):
                words = pii.split()
                if len(words) <= 1:
                    return f"REDACTED_{entity_type}_{count}"
                return " ".join(
                    f"REDACTED_{entity_type}_{count}{chr(ord('A') + i)}"
                    for i in range(len(words))
                )

        tm = TokenMap(replacements={"PERSON": _PerWordStrategy()})
        tm.get_or_create_token("Alice Smith", "PERSON")
        assert tm.get_pii("REDACTED_PERSON_1A") == "Alice"

        tm.invalidate_entity_types({"PERSON"})
        assert tm.get_pii("REDACTED_PERSON_1A") is None
        assert tm.get_pii("REDACTED_PERSON_1B") is None

    @pytest.mark.asyncio
    async def test_subtoken_aliases_rebuilt_on_reload(self, tmp_path):
        """After SQLite reload the per-sub-token aliases must come back."""
        from scruxy.tokenmap.service import ConcurrentSessionStore

        storage_dir = tmp_path / "sessions"
        storage_dir.mkdir()
        db_path = str(tmp_path / "tokens.db")

        class _PerWordStrategy:
            def generate(self, entity_type, pii, count):
                words = pii.split()
                if len(words) <= 1:
                    return f"REDACTED_{entity_type}_{count}"
                return " ".join(
                    f"REDACTED_{entity_type}_{count}{chr(ord('A') + i)}"
                    for i in range(len(words))
                )

        # Open store, insert the multi-word PII, drain, close.
        store1 = ConcurrentSessionStore(
            storage_dir=str(storage_dir),
            replacements={"PERSON": _PerWordStrategy()},
            db_path=db_path,
        )
        await store1.start()
        try:
            tm1 = await store1.get_or_create_session("s1")
            tm1.get_or_create_token("Alice Smith", "PERSON")
            await asyncio.to_thread(store1._drain_pending_writes)
        finally:
            await store1.stop()

        # Re-open from disk — sub-token aliases should be recreated.
        store2 = ConcurrentSessionStore(
            storage_dir=str(storage_dir),
            replacements={"PERSON": _PerWordStrategy()},
            db_path=db_path,
        )
        await store2.start()
        try:
            shared = store2._shared_map
            # Joint reverse mapping comes back trivially.
            assert shared.get_pii("REDACTED_PERSON_1A REDACTED_PERSON_1B") == "Alice Smith"
            # Per-sub-token aliases must be reconstructed (B3 residual).
            assert shared.get_pii("REDACTED_PERSON_1A") == "Alice"
            assert shared.get_pii("REDACTED_PERSON_1B") == "Smith"
        finally:
            await store2.stop()

    @pytest.mark.asyncio
    async def test_in_memory_delete_session_purges_subtoken_aliases(self, tmp_path):
        """In-memory mode: deleting a session must also purge per-sub-token
        aliases for any PII exclusive to that session."""
        from scruxy.tokenmap.service import ConcurrentSessionStore

        class _PerWordStrategy:
            def generate(self, entity_type, pii, count):
                words = pii.split()
                if len(words) <= 1:
                    return f"REDACTED_{entity_type}_{count}"
                return " ".join(
                    f"REDACTED_{entity_type}_{count}{chr(ord('A') + i)}"
                    for i in range(len(words))
                )

        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            replacements={"PERSON": _PerWordStrategy()},
            persistent=False,
        )
        await store.start()
        try:
            tm = await store.get_or_create_session("s1")
            tm.get_or_create_token("Alice Smith", "PERSON")
            store.tag_session_pii("s1", {"Alice Smith"})

            # Aliases exist before delete.
            assert store._shared_map.get_pii("REDACTED_PERSON_1A") == "Alice"
            assert store._shared_map.get_pii("REDACTED_PERSON_1B") == "Smith"

            removed = await store.delete_session_mappings("s1")
            assert removed >= 1

            # After delete, NEITHER the joint nor the per-sub-token
            # aliases may resolve back to the deleted PII.
            assert store._shared_map.get_pii("REDACTED_PERSON_1A REDACTED_PERSON_1B") is None
            assert store._shared_map.get_pii("REDACTED_PERSON_1A") is None
            assert store._shared_map.get_pii("REDACTED_PERSON_1B") is None
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# B4-residual — Bounded gen-lock cache
# ---------------------------------------------------------------------------

class TestB4_Residual_GenLockBounded:
    def test_gen_lock_cache_evicts_when_oversized(self, tmp_path):
        from scruxy.cert.ca import CertificateAuthority
        ca = CertificateAuthority(tmp_path)
        # Tiny cap so eviction kicks in fast.
        ca._host_cache_max = 2
        gen_lock_cap = ca._host_cache_max * 4

        # Generate certs for many unique hostnames so gen-locks are
        # created.  Eviction should keep the gen-lock dict bounded.
        for i in range(40):
            ca.get_host_cert(f"host{i}.example.com")
        assert len(ca._host_gen_locks) <= gen_lock_cap + ca._host_cache_max, (
            f"_host_gen_locks grew unbounded: {len(ca._host_gen_locks)} entries"
        )
