"""Regression tests for Round 63 hardening fixes (R63-1..R63-7)."""
from __future__ import annotations

import asyncio
import inspect
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# R63-1 — MITM keep-alive carries leftover for bodiless requests
# ---------------------------------------------------------------------------

class TestR63_1_BodilessLeftoverCarried:
    def test_source_carries_leftover_for_zero_cl(self):
        """The MITM keep-alive loop must carry `leftover` to
        `_carry_buf` for both Content-Length: 0 AND no-CL+no-TE
        requests, NOT discard it."""
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        src = inspect.getsource(ForwardProxyServer._mitm_tunnel)
        # The CL=0 branch must set _carry_buf to leftover.
        assert "_carry_buf = leftover" in src, (
            "R63-1: MITM keep-alive doesn't carry leftover for bodiless requests"
        )


# ---------------------------------------------------------------------------
# R63-2 — MITM start_tls has timeout
# ---------------------------------------------------------------------------

class TestR63_2_StartTLSTimeout:
    def test_start_tls_uses_wait_for(self):
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        src = inspect.getsource(ForwardProxyServer._mitm_tunnel)
        # Find the start_tls call and verify wait_for around it.
        idx = src.find("loop.start_tls(")
        assert idx > 0
        snippet = src[max(0, idx - 200):idx + 200]
        assert "asyncio.wait_for" in snippet, (
            "R63-2: MITM start_tls() must be wrapped in asyncio.wait_for"
        )
        assert "_CONNECT_TIMEOUT_S" in snippet, (
            "R63-2: MITM start_tls timeout should use _CONNECT_TIMEOUT_S"
        )

    def test_timeoutexcept_is_caught(self):
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        src = inspect.getsource(ForwardProxyServer._mitm_tunnel)
        # asyncio.TimeoutError must be in an exception clause near start_tls.
        idx = src.find("loop.start_tls(")
        assert idx > 0
        snippet = src[idx:idx + 800]
        assert "asyncio.TimeoutError" in snippet, (
            "R63-2: TLS handshake timeout must be caught"
        )


# ---------------------------------------------------------------------------
# R63-3 — `_is_blocked_local_admin_path` iterates unquote
# ---------------------------------------------------------------------------

class TestR63_3_AdminPathDoubleDecodeBlocked:
    def test_double_encoded_admin_path_blocked(self):
        from scruxy.proxy.forward_proxy import _is_blocked_local_admin_path

        # Sanity: literal /ui/api/events is blocked.
        assert _is_blocked_local_admin_path("/ui/api/events")
        # Single-encoded (already worked).
        assert _is_blocked_local_admin_path("/%2fui%2fapi%2fevents")
        # R63-3 fix: double-encoded must also be blocked.
        assert _is_blocked_local_admin_path("/%252fui%252fapi%252fevents"), (
            "R63-3: double-encoded admin path was NOT blocked"
        )
        # Triple-encoded too.
        assert _is_blocked_local_admin_path("/%25252fui%25252fapi%25252fevents"), (
            "R63-3: triple-encoded admin path was NOT blocked"
        )
        # Non-admin path (sanity) — must remain not-blocked.
        assert not _is_blocked_local_admin_path("/v1/messages")


# ---------------------------------------------------------------------------
# R63-4 — SSE incremented initialized
# ---------------------------------------------------------------------------

class TestR63_4_SSEIncrementedInitialized:
    def test_event_generator_initializes_incremented(self):
        from scruxy.ui import routes
        # Find the _event_generator inside this module.
        src = inspect.getsource(routes)
        # The init must appear before any branch that yields/returns.
        # Check the function source contains `incremented = False`.
        assert "incremented = False" in src, (
            "R63-4: incremented must be initialized to False before any branch"
        )


# ---------------------------------------------------------------------------
# R63-5 — bool/None keys coerced JSON-compatibly
# ---------------------------------------------------------------------------

class TestR63_5_BoolNoneKeysJSONCompatible:
    def test_bool_key_uses_lowercase_true(self):
        """A dict key `True` must be coerced to `"true"` (matching
        json.dumps), not `"True"` (which would mismatch the
        post-replace round-trip lookup)."""
        from scruxy.providers.anthropic import _walk_json_strings

        val = {True: "alice@example.com"}
        fields: list = []
        _walk_json_strings(val, "$.input", fields, "tool_use")
        assert len(fields) == 1
        # Path segment must be "true", not "True".
        assert ".true" in fields[0].json_path, (
            f"R63-5: bool key not json-compatible; got {fields[0].json_path!r}"
        )

    def test_none_key_uses_null(self):
        from scruxy.providers.anthropic import _walk_json_strings

        val = {None: "bob@example.com"}
        fields: list = []
        _walk_json_strings(val, "$.input", fields, "tool_use")
        assert len(fields) == 1
        assert ".null" in fields[0].json_path, (
            f"R63-5: None key not json-compatible; got {fields[0].json_path!r}"
        )


# ---------------------------------------------------------------------------
# R63-6 — Iterated unquote fails closed on non-convergence
# ---------------------------------------------------------------------------

class TestR63_6_UnquoteFailsClosedOnNonConvergence:
    @pytest.mark.asyncio
    async def test_pathological_encoding_rejected(self):
        """Construct a path that requires >8 unquote rounds — must
        return 400 instead of slipping through partially decoded."""
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        provider = MagicMock()
        provider.name = "anthropic"
        provider.upstream_url = "https://api.example.com"
        provider.extract_session_id = MagicMock(return_value="s1")
        registry = MagicMock()
        registry.match = MagicMock(return_value=provider)
        registry.match_disabled = MagicMock(return_value=None)

        server = ForwardProxyServer(
            host="127.0.0.1", port=0, ca=MagicMock(),
            registry=registry, pipeline=MagicMock(),
            session_store=None,
            request_scrubber=None, response_unscrubber=MagicMock(),
        )

        # Build a path with 10 layers of encoding for ".".
        # Layer 0: "."  Layer 1: "%2e"  Layer 2: "%252e"  ...
        # Layer N: "%" + "25"*(N-1) + "2e"
        N = 10
        encoded_dot = "%" + "25" * (N - 1) + "2e"
        path = f"/v1/messages/{encoded_dot}{encoded_dot}/models"

        status, _hdr, _body = await server._scrub_and_forward(
            method="POST",
            url=f"https://api.example.com{path}",
            headers={"content-type": "application/json"},
            body=b'{"x":"y"}',
        )
        assert status == 400, (
            f"R63-6: pathological encoding NOT rejected; got {status}"
        )


# ---------------------------------------------------------------------------
# R63-7 — Reverse proxy traversal guard has behavioral test
# ---------------------------------------------------------------------------

class TestR63_7_ReverseProxyTraversalBehavioral:
    @pytest.mark.asyncio
    async def test_reverse_proxy_double_encoded_traversal_rejected(self):
        """R63-7 supersedes R62-6 source-grep test — drives the
        actual `proxy_catch_all` handler with `%252e%252e`."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from scruxy.proxy.routes import router

        app = FastAPI()
        app.include_router(router)
        # Inject minimal forwarder to pass the early forwarder-None guard.
        app.state.forwarder = MagicMock()

        client = TestClient(app, raise_server_exceptions=False)
        # Note: TestClient may normalize URLs. Use a path with `..` as
        # part of the literal path segments which Starlette does not
        # auto-resolve.  Use the percent-encoded form to test the unquote.
        # Starlette typically decodes `%2e%2e` to `..` before our handler
        # so the existing literal-`..` guard catches it.  Either way we
        # must get 400, NOT a 404 from passthrough hitting wrong endpoint.
        for path_variant in ["/v1/foo/%2e%2e/models", "/v1/foo/%252e%252e/models"]:
            resp = client.post(path_variant, json={"x": "y"})
            # R64-6 fix: assert exactly 400 — accepting 404 would
            # silently mask a regression where the traversal guard
            # stops firing and the request falls through to a
            # generic 404 from the passthrough.
            assert resp.status_code == 400, (
                f"R63-7/R64-6: reverse proxy traversal not blocked: {path_variant} -> {resp.status_code}"
            )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
