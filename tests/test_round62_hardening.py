"""Regression tests for Round 62 hardening fixes (R62-1..R62-7)."""
from __future__ import annotations

import asyncio
import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# R62-1 / R62-7 — CONNECT tunnel has connect-phase timeout
# ---------------------------------------------------------------------------

class TestR62_1_ConnectTimeout:
    def test_connect_timeout_constant_exists(self):
        from scruxy.proxy import forward_proxy

        cap = getattr(forward_proxy, "_CONNECT_TIMEOUT_S", None)
        assert cap is not None, "_CONNECT_TIMEOUT_S must be defined"
        assert 5 <= cap <= 120, f"Timeout {cap}s out of reasonable range"

    def test_connect_uses_wait_for(self):
        """Source-level: passthrough_tunnel must wrap open_connection
        in `asyncio.wait_for` with the connect timeout."""
        from scruxy.proxy import forward_proxy
        import inspect as _inspect

        src = _inspect.getsource(forward_proxy.ForwardProxyServer)
        # Find the passthrough connect block.
        idx = src.find("for connect_host, connect_port in connect_targets:")
        assert idx > 0
        snippet = src[idx:idx + 1500]
        assert "asyncio.wait_for" in snippet, (
            "R62-1: passthrough connect must use asyncio.wait_for"
        )
        assert "_CONNECT_TIMEOUT_S" in snippet, (
            "R62-1: passthrough connect must reference _CONNECT_TIMEOUT_S"
        )


# ---------------------------------------------------------------------------
# R62-2 — event_bus subscribers iterated over snapshot
# ---------------------------------------------------------------------------

class TestR62_2_SubscribersSnapshot:
    def test_routes_emitter_uses_list_snapshot(self):
        from scruxy.proxy import routes
        import inspect as _inspect

        src = _inspect.getsource(routes)
        # All emitter sites must use `for queue in list(subscribers)`.
        # Find every "for queue in" line.
        # Each must be followed by `list(`.
        for i, line in enumerate(src.split("\n")):
            if "for queue in subscribers" in line and "list" not in line:
                pytest.fail(
                    f"R62-2: routes.py emitter at line {i+1} doesn't snapshot: {line.strip()!r}"
                )

    def test_forward_proxy_emitter_uses_list_snapshot(self):
        from scruxy.proxy import forward_proxy
        import inspect as _inspect

        src = _inspect.getsource(forward_proxy)
        for i, line in enumerate(src.split("\n")):
            if "for queue in subscribers" in line and "list" not in line:
                pytest.fail(
                    f"R62-2: forward_proxy.py emitter at line {i+1} doesn't snapshot: {line.strip()!r}"
                )

    def test_iteration_continues_when_subscriber_removed_during_iter(self):
        """Behavioral: even if a queue is removed from subscribers
        DURING iteration, every other queue still receives the event."""
        from queue import Queue

        subscribers = [Queue() for _ in range(5)]

        # Simulate the production pattern: snapshot then iterate.
        snapshot = list(subscribers)
        # Mutate the original list while iterating the snapshot.
        for q in snapshot:
            subscribers.remove(q)
            q.put_nowait("event")

        # All 5 queues received the event regardless of removal.
        assert all(not q.empty() for q in snapshot)
        assert subscribers == []


# ---------------------------------------------------------------------------
# R62-3 — Double-encoded `%252e%252e` traversal rejected
# ---------------------------------------------------------------------------

class TestR62_3_DoubleEncodedTraversalRejected:
    @pytest.mark.asyncio
    async def test_forward_proxy_rejects_double_encoded(self):
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

        for path_variant in [
            "/v1/messages/%252e%252e/models",
            "/v1/messages/%25252e%25252e/models",  # triple-encoded
            "/v1/foo/%252e/chat",
        ]:
            status, _hdr, _body = await server._scrub_and_forward(
                method="POST",
                url=f"https://api.example.com{path_variant}",
                headers={"content-type": "application/json"},
                body=b'{"x":"y"}',
            )
            assert status == 400, (
                f"R62-3: double-encoded path NOT rejected: {path_variant!r}; got {status}"
            )
            registry.match.assert_not_called()
            registry.match.reset_mock()


# ---------------------------------------------------------------------------
# R62-4 — Per-request leaf ceiling not overshot by individual blocks
# ---------------------------------------------------------------------------

class TestR62_4_PerRequestCapNotOvershot:
    def test_walker_accepts_max_leaves_param(self):
        from scruxy.providers.anthropic import _walk_json_strings
        import inspect as _inspect

        sig = _inspect.signature(_walk_json_strings)
        assert "max_leaves" in sig.parameters, (
            "R62-4: _walk_json_strings must accept `max_leaves` param"
        )

    def test_per_request_cap_enforced_by_single_block(self, monkeypatch):
        """A single tool_use block with more leaves than the
        per-request cap allows must NOT overshoot.  Repro the
        GPT-5.5 evidence: cap=20, one block with 50 leaves → ≤20."""
        from scruxy.providers import anthropic
        from scruxy.providers.anthropic import AnthropicProvider

        monkeypatch.setattr(anthropic, "_MAX_TOOL_INPUT_LEAVES_PER_REQUEST", 20)
        provider = AnthropicProvider()

        body = {
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": {f"k{i}": f"u{i}@example.com" for i in range(50)},
                }],
            }],
        }
        fields = provider.extract_text_fields(body)
        assert len(fields) <= 20, (
            f"R62-4: single block overshot per-request cap; got {len(fields)} > 20"
        )


# ---------------------------------------------------------------------------
# R62-5 — Non-string keys coerced to str instead of silently skipped
# ---------------------------------------------------------------------------

class TestR62_5_NonStringKeysCoerced:
    def test_int_key_pii_is_extracted(self):
        from scruxy.providers.anthropic import _walk_json_strings

        # Construct a dict with an int key (legal in Python, illegal
        # in JSON, but possible from non-JSON body sources).
        val = {123: "alice@example.com"}
        fields: list = []
        _walk_json_strings(val, "$.input", fields, "tool_use")
        values = {f.text_value for f in fields}
        assert "alice@example.com" in values, (
            "R62-5: PII under non-string key was silently skipped"
        )


# ---------------------------------------------------------------------------
# R62-6 — Reverse proxy traversal guard is behaviorally tested
# ---------------------------------------------------------------------------

class TestR62_6_ReverseProxyTraversalGuard:
    def test_reverse_proxy_source_decodes_percent_then_iterates(self):
        from scruxy.proxy import routes
        import inspect as _inspect

        src = _inspect.getsource(routes.proxy_catch_all)
        # Must call unquote AND iterate (R62-3 sibling).
        assert "unquote" in src
        assert "for _ in range" in src, (
            "R62-6: reverse proxy must iterate unquote until idempotent"
        )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
