"""Regression tests for Round 60 hardening fixes (R60-1..R60-9)."""
from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# R60-1 — Per-block leaf cap (no shared budget across tool_use blocks)
# ---------------------------------------------------------------------------

class TestR60_1_PerBlockLeafCap:
    def test_walker_uses_local_counter_not_len_fields(self):
        """The cap must be enforced via a LOCAL counter, not
        `len(fields)` (which is shared across calls)."""
        from scruxy.providers import anthropic

        src = inspect.getsource(anthropic._walk_json_strings)
        # Must NOT use `len(fields) >=` for the cap check.
        assert "len(fields) >=" not in src, (
            "R60-1: cap still uses len(fields) — shared across calls"
        )
        assert "leaves_added" in src, (
            "R60-1: walker should use a local `leaves_added` counter"
        )

    def test_first_block_truncation_does_not_block_second(self):
        """Build a request with TWO `tool_use` blocks: the first
        is at the leaf cap, the second has a single leaf with PII.
        The second block's PII MUST still be extracted."""
        from scruxy.providers.anthropic import AnthropicProvider, _MAX_TOOL_INPUT_LEAVES

        provider = AnthropicProvider()
        # Block 1: 100k benign leaves (≥ cap).
        block1_input = {f"k{i}": f"v{i}" for i in range(_MAX_TOOL_INPUT_LEAVES + 100)}
        # Block 2: a single PII leaf.
        block2_input = {"pii": "alice@example.com"}

        body = {
            "messages": [{
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "input": block1_input},
                    {"type": "tool_use", "input": block2_input},
                ],
            }],
        }
        fields = provider.extract_text_fields(body)
        values = {f.text_value for f in fields}
        assert "alice@example.com" in values, (
            "R60-1: second-block PII NOT extracted — shared cap still bypasses scrubbing"
        )


# ---------------------------------------------------------------------------
# R60-2 — Copilot Chat tool_calls.arguments extracted on REQUEST side
# ---------------------------------------------------------------------------

class TestR60_2_CopilotChatToolCallsRequestExtracted:
    def test_yaml_includes_input_tool_calls_arguments(self):
        import yaml
        cfg = yaml.safe_load(Path("default_config/providers/copilot_chat.yaml").read_text())
        assert "$.messages[*].tool_calls[*].function.arguments" in cfg["request_text_paths"]

    @pytest.mark.asyncio
    async def test_function_arguments_extracted_via_yaml_provider(self):
        from scruxy.providers.yaml_provider import YAMLProvider
        import yaml

        cfg = yaml.safe_load(Path("default_config/providers/copilot_chat.yaml").read_text())
        provider = YAMLProvider(cfg)

        body = {
            "messages": [{
                "role": "assistant",
                "tool_calls": [{
                    "function": {"arguments": "email alice@example.com"}
                }],
            }],
        }
        fields = provider.extract_text_fields(body)
        values = {f.text_value for f in fields}
        assert any("alice@example.com" in v for v in values), (
            f"R60-2: tool_calls.function.arguments NOT extracted; got {values}"
        )


# ---------------------------------------------------------------------------
# R60-3 — OpenAI/YAML providers no longer recurse on deepcopy
# ---------------------------------------------------------------------------

class TestR60_3_OpenAIYAMLDeepcopySafe:
    def test_openai_replace_uses_json_roundtrip(self):
        from scruxy.providers import openai as openai_mod

        src = inspect.getsource(openai_mod.OpenAIProvider.replace_text_fields)
        assert "json.dumps(body)" in src or "json.loads(json.dumps" in src or "_json.dumps" in src, (
            "R60-3: OpenAI replace_text_fields should use JSON round-trip"
        )

    def test_yaml_replace_uses_json_roundtrip(self):
        from scruxy.providers import yaml_provider

        src = inspect.getsource(yaml_provider.YAMLProvider.replace_text_fields)
        assert "json.dumps(body)" in src or "json.loads(json.dumps" in src or "_json.dumps" in src, (
            "R60-3: YAML replace_text_fields should use JSON round-trip"
        )

    def test_openai_replace_handles_deep_input(self):
        """A 900-level nested OpenAI body must NOT crash replace_text_fields."""
        from scruxy.providers.openai import OpenAIProvider

        provider = OpenAIProvider()
        leaf: object = "alice@example.com"
        nested: object = leaf
        for _ in range(900):
            nested = {"k": nested}
        body = {"messages": [{"role": "user", "content": "hi"}], "deep": nested}
        # Should NOT raise RecursionError.
        out = provider.replace_text_fields(body, {})
        assert "deep" in out
        assert "messages" in out


# ---------------------------------------------------------------------------
# R60-4 — Path traversal rejected before provider matching
# ---------------------------------------------------------------------------

class TestR60_4_PathTraversalRejected:
    def test_reverse_proxy_source_has_traversal_guard(self):
        """Source-level: `proxy_catch_all` must contain a `..`/`.`
        segment guard BEFORE provider matching.  Note: Starlette
        also normalizes paths upstream of FastAPI handlers, but this
        explicit guard provides defense-in-depth (e.g. for ASGI
        servers that don't normalize)."""
        from scruxy.proxy import routes

        src = inspect.getsource(routes.proxy_catch_all)
        assert "_path_segments" in src and "traversal" in src.lower(), (
            "R60-4: reverse proxy missing explicit traversal guard"
        )

    def test_forward_proxy_source_has_traversal_guard(self):
        """Source-level: `_scrub_and_forward` must contain a
        traversal-segment check BEFORE provider matching.  The
        forward proxy parses raw HTTP and does NOT get free
        normalization from Starlette."""
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        src = inspect.getsource(ForwardProxyServer._scrub_and_forward)
        # Find the guard.
        assert "traversal" in src.lower() or '".." in _path_segments' in src, (
            "R60-4: forward proxy missing traversal guard"
        )

    @pytest.mark.asyncio
    async def test_forward_proxy_rejects_dotdot_path(self):
        """Behavioral: `_scrub_and_forward` with a `..` path must
        return 400 before provider matching."""
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

        # Path with `..` segment.
        status, _hdr, _body = await server._scrub_and_forward(
            method="POST",
            url="https://api.example.com/v1/messages/../models",
            headers={"content-type": "application/json"},
            body=b'{"x": "y"}',
        )
        assert status == 400, (
            f"R60-4: forward proxy did not reject `..` path; got {status}"
        )


# ---------------------------------------------------------------------------
# R60-5 — Set-Cookie stripped from scrubbed responses
# ---------------------------------------------------------------------------

class TestR60_5_SetCookieStripped:
    def test_set_cookie_in_strip_set(self):
        from scruxy.proxy.forwarder import STRIP_RESPONSE_HEADERS

        assert "set-cookie" in STRIP_RESPONSE_HEADERS, (
            "R60-5: set-cookie should be stripped from scrubbed responses"
        )

    def test_passthrough_does_not_strip_set_cookie(self):
        """Passthrough should preserve cookies byte-for-byte."""
        from scruxy.proxy.forwarder import PASSTHROUGH_STRIP_RESPONSE_HEADERS

        assert "set-cookie" not in PASSTHROUGH_STRIP_RESPONSE_HEADERS, (
            "R60-5: passthrough must NOT strip set-cookie"
        )


# ---------------------------------------------------------------------------
# R60-6 — JSON migration writer rejects empty token rows
# ---------------------------------------------------------------------------

class TestR60_6_JSONMigrationRejectsEmpty:
    def test_migrate_skips_empty_pii_or_token(self, tmp_path):
        """A JSON token map containing empty pii or token entries
        must be skipped during migration (defense-in-depth on R58-3 + R59-4)."""
        from scruxy.tokenmap.db import TokenDB
        import json as _json

        json_path = tmp_path / "token_map.json"
        json_path.write_text(_json.dumps({
            "scrub": {
                "alice@example.com": "REDACTED_EMAIL_1",
                "": "REDACTED_X_1",        # empty pii — must skip
                "valid@example.com": "",    # empty token — must skip
                "bob@example.com": "REDACTED_EMAIL_2",
            },
            "entity_types": {},
            "counters": {"EMAIL": 2},
        }))

        db = TokenDB(tmp_path / "test.db")
        db.open()
        imported = db.migrate_from_json(json_path)
        # Only the 2 valid rows are imported.
        assert imported == 2
        # Verify in-DB.
        rows = db._c.execute("SELECT original, scrubbed FROM tokens ORDER BY original").fetchall()
        keys = {r["original"] for r in rows}
        assert keys == {"alice@example.com", "bob@example.com"}


# ---------------------------------------------------------------------------
# R60-7 — JSON round-trip documented (low priority — just contract note)
# ---------------------------------------------------------------------------

class TestR60_7_JSONRoundTripDocumented:
    def test_anthropic_replace_documents_json_roundtrip_caveat(self):
        """The replace_text_fields docstring (or comment) should
        mention the JSON round-trip behavior so future callers
        understand the contract."""
        from scruxy.providers import anthropic
        src = inspect.getsource(anthropic.AnthropicProvider.replace_text_fields)
        assert "json" in src.lower() and ("loads" in src.lower() or "dumps" in src.lower()), (
            "R60-7: replace_text_fields should reference json round-trip"
        )


# ---------------------------------------------------------------------------
# R60-8 — Working stack also bounded
# ---------------------------------------------------------------------------

class TestR60_8_StackBounded:
    def test_stack_cap_constant_exists(self):
        from scruxy.providers import anthropic

        cap = getattr(anthropic, "_MAX_TOOL_INPUT_STACK", None)
        assert cap is not None
        assert 100_000 <= cap <= 5_000_000

    def test_walker_checks_stack_size(self):
        from scruxy.providers import anthropic

        src = inspect.getsource(anthropic._walk_json_strings)
        assert "_MAX_TOOL_INPUT_STACK" in src, (
            "R60-8: walker must check stack size"
        )


# ---------------------------------------------------------------------------
# R60-9 — Truncation warning includes context
# ---------------------------------------------------------------------------

class TestR60_9_WarningHasContext:
    def test_leaf_cap_warning_includes_base_path(self, caplog):
        """When the leaf cap fires, the WARNING log must include
        `base_path` (so ops can identify which tool_use block was
        truncated)."""
        from scruxy.providers.anthropic import _walk_json_strings, _MAX_TOOL_INPUT_LEAVES

        big_input = {f"k{i}": f"v{i}@example.com" for i in range(_MAX_TOOL_INPUT_LEAVES + 5)}
        fields: list = []
        import logging
        with caplog.at_level(logging.WARNING, logger="scruxy.providers.anthropic"):
            _walk_json_strings(big_input, "$.test.path", fields, "tool_use")

        relevant = [r for r in caplog.records if "exceeded" in r.getMessage()]
        assert relevant, "Expected warning to fire"
        msg = relevant[0].getMessage()
        assert "$.test.path" in msg, (
            f"R60-9: warning lacks base_path context: {msg!r}"
        )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
