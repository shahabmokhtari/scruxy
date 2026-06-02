"""Regression tests for Round 59 hardening fixes (R59-1..R59-8)."""
from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest


# ---------------------------------------------------------------------------
# R59-1 — `_parse_headers` is case-insensitive (smuggling guard)
# ---------------------------------------------------------------------------

class TestR59_1_CaseInsensitiveHeaders:
    def test_uppercase_transfer_encoding_detected_by_smuggling_guard(self):
        """`TRANSFER-ENCODING: chunked` + `Content-Length: 5` must
        STILL raise (smuggling defence) — the guard already lowercases
        for the sensitive set, but the storage was case-sensitive
        which made the body reader miss the TE header."""
        from scruxy.proxy.forward_proxy import _parse_headers

        raw = "TRANSFER-ENCODING: chunked\nContent-Length: 5\n"
        with pytest.raises(ValueError, match="(?i)Content-Length and Transfer-Encoding"):
            _parse_headers(raw)

    def test_uppercase_te_visible_to_body_reader(self):
        """Single `TRANSFER-ENCODING: chunked` (no CL) must be
        retrievable via lowercase key — body reader uses `.get("transfer-encoding")`."""
        from scruxy.proxy.forward_proxy import _parse_headers

        raw = "TRANSFER-ENCODING: chunked\n"
        parsed = _parse_headers(raw)
        assert parsed.get("transfer-encoding") == "chunked", (
            "R59-1: uppercase TE not visible via lowercase lookup"
        )

    def test_case_variant_duplicate_detected_for_sensitive(self):
        """`Content-Length` + `content-length` (different case) must
        STILL be rejected as smuggling."""
        from scruxy.proxy.forward_proxy import _parse_headers

        raw = "Content-Length: 5\ncontent-length: 5\n"
        with pytest.raises(ValueError, match="(?i)duplicate"):
            _parse_headers(raw)

    def test_case_variant_duplicate_merged_for_non_sensitive(self):
        """`Cookie` + `cookie` must merge (not produce two dict keys)."""
        from scruxy.proxy.forward_proxy import _parse_headers

        raw = "Cookie: a=1\ncookie: b=2\n"
        parsed = _parse_headers(raw)
        # Only one key, lowercased.
        assert "cookie" in parsed
        assert "Cookie" not in parsed
        cookie = parsed["cookie"]
        assert "a=1" in cookie
        assert "b=2" in cookie
        # R59-3 — semicolon delimiter.
        assert "; " in cookie


# ---------------------------------------------------------------------------
# R59-2 — `_deanonymize_json_deep` is iterative + extracts deep tokens
# ---------------------------------------------------------------------------

class TestR59_2_DeanonymizeIterative:
    def test_deanonymize_json_deep_is_iterative(self):
        """Source-level: must NOT recurse on itself."""
        from scruxy.scrubber import sse_stream_unscrubber

        src = inspect.getsource(sse_stream_unscrubber._deanonymize_json_deep)
        # Function body must not call itself.
        body = src.split(":", 1)[1]
        assert "_deanonymize_json_deep(" not in body, (
            "R59-2: function still recurses on itself"
        )
        assert "while" in body or "stack" in body.lower(), (
            "R59-2: function should be iterative (use stack/while)"
        )

    def test_deep_token_is_deanonymized(self):
        """A REDACTED token at depth 500 must be unscrubbed (not
        leaked through fail-open as in the old recursive version)."""
        from scruxy.scrubber.sse_stream_unscrubber import _deanonymize_json_deep

        class _MockTokenMap:
            unscrub_map = {"REDACTED_EMAIL_1": "alice@example.com"}

        # Build {"k": {"k": ... 500 deep ... {"leaf": "REDACTED_EMAIL_1"}}}
        leaf: object = {"leaf": "REDACTED_EMAIL_1"}
        nested: object = leaf
        for _ in range(500):
            nested = {"k": nested}

        result = _deanonymize_json_deep(nested, _MockTokenMap())
        # Walk down to the leaf in the result.
        cur = result
        for _ in range(500):
            cur = cur["k"]
        assert cur["leaf"] == "alice@example.com", (
            "R59-2: deep token at depth 500 NOT deanonymized"
        )


# ---------------------------------------------------------------------------
# R59-3 — Cookie header joined with semicolon (RFC 6265)
# ---------------------------------------------------------------------------

class TestR59_3_CookieSemicolon:
    def test_cookie_uses_semicolon_delimiter(self):
        from scruxy.proxy.forward_proxy import _parse_headers

        raw = "Cookie: session=abc\nCookie: csrf=xyz\n"
        parsed = _parse_headers(raw)
        cookie = parsed["cookie"]
        # Order doesn't matter, but delimiter must be `; `.
        assert cookie == "session=abc; csrf=xyz", (
            f"R59-3: wrong delimiter; got {cookie!r}"
        )
        assert ", " not in cookie, (
            f"R59-3: Cookie still using comma: {cookie!r}"
        )

    def test_non_cookie_uses_comma_delimiter(self):
        from scruxy.proxy.forward_proxy import _parse_headers

        raw = "X-Custom: a\nX-Custom: b\n"
        parsed = _parse_headers(raw)
        assert parsed["x-custom"] == "a, b"


# ---------------------------------------------------------------------------
# R59-4 — DB load rejects empty token rows
# ---------------------------------------------------------------------------

class TestR59_4_DBRejectsEmptyToken:
    def test_load_skips_empty_scrubbed_row(self):
        """Source-level: `_load_from_db` must skip rows where
        `scrubbed` or `original` is empty (R58-3 applied to persisted state)."""
        from scruxy.tokenmap import service

        src = inspect.getsource(service.ConcurrentSessionStore)
        load_src_idx = src.find("def _load_from_db")
        assert load_src_idx > 0, "_load_from_db not found"
        load_src = src[load_src_idx:load_src_idx + 4000]
        # The new guard must be present.
        assert "if not pii or not token" in load_src, (
            "R59-4: empty-token guard not present in _load_from_db"
        )


# ---------------------------------------------------------------------------
# R59-5 — `$.input[*].arguments` added to YAML configs
# ---------------------------------------------------------------------------

class TestR59_5_InputArgumentsPath:
    def _yaml(self, name: str) -> dict:
        import yaml
        return yaml.safe_load((Path("default_config/providers") / f"{name}.yaml").read_text())

    def test_openai_responses_includes_input_arguments(self):
        cfg = self._yaml("openai_responses")
        assert "$.input[*].arguments" in cfg["request_text_paths"]

    def test_copilot_responses_includes_input_arguments(self):
        cfg = self._yaml("copilot_responses")
        assert "$.input[*].arguments" in cfg["request_text_paths"]

    @pytest.mark.asyncio
    async def test_function_call_arguments_extracted(self):
        """A `function_call` echo with PII in `arguments` must be
        extracted by the YAML provider."""
        from scruxy.providers.yaml_provider import YAMLProvider
        import yaml

        cfg = yaml.safe_load(Path("default_config/providers/openai_responses.yaml").read_text())
        provider = YAMLProvider(cfg)

        body = {
            "input": [
                {
                    "type": "function_call",
                    "call_id": "call_1",
                    "arguments": '{"to":"alice@example.com"}',
                }
            ]
        }
        fields = provider.extract_text_fields(body)
        values = {f.text_value for f in fields}
        assert any("alice@example.com" in v for v in values), (
            f"R59-5: function_call.arguments not extracted; got {values}"
        )


# ---------------------------------------------------------------------------
# R59-6 — Deep deepcopy no longer crashes (JSON round-trip)
# ---------------------------------------------------------------------------

class TestR59_6_DeepDeepcopySafe:
    @pytest.mark.asyncio
    async def test_scrub_request_handles_deep_input_at_default_recursion_limit(self):
        """A 900-level nested body must not RecursionError in
        scrub_request — `copy.deepcopy` was replaced with iterative
        `json.loads(json.dumps(body))`.  Runs at DEFAULT recursion
        limit (no `sys.setrecursionlimit` boost)."""
        import sys
        from scruxy.providers.anthropic import AnthropicProvider
        from scruxy.scrubber.request_scrubber import RequestScrubber
        from scruxy.pipeline.models import PipelineResult

        async def _scrub_text(text, token_map, ctx=None, **kwargs):
            import re
            return PipelineResult(
                scrubbed_text=re.sub(
                    r"[\w.+-]+@[\w-]+\.[\w.-]+", "REDACTED_EMAIL_X", text,
                ),
                entities=[],
            )

        pipeline = AsyncMock()
        pipeline.scrub_text = AsyncMock(side_effect=_scrub_text)
        provider = AnthropicProvider()
        scrubber = RequestScrubber()

        leaf: object = "deep.alice@example.com"
        nested: object = leaf
        for _ in range(900):
            nested = {"k": nested}

        body = {
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": {"deep": nested},
                }],
            }],
        }
        # MUST NOT touch sys.setrecursionlimit.
        old_limit = sys.getrecursionlimit()
        try:
            scrubbed_body, _entities, _stages, _reused = await scrubber.scrub_request(
                body=body, provider=provider, pipeline=pipeline,
                token_map=object(), request_id="r1",
            )
            # PII is scrubbed.
            assert "deep.alice@example.com" not in json.dumps(scrubbed_body), (
                "R59-6: deep PII leaked"
            )
        finally:
            assert sys.getrecursionlimit() == old_limit, (
                "Test must not permanently modify recursion limit"
            )


# ---------------------------------------------------------------------------
# R59-7 — `_walk_json_strings` has a leaf-count cap
# ---------------------------------------------------------------------------

class TestR59_7_LeafCountCap:
    def test_leaf_cap_constant_exists(self):
        from scruxy.providers import anthropic

        cap = getattr(anthropic, "_MAX_TOOL_INPUT_LEAVES", None)
        assert cap is not None, "_MAX_TOOL_INPUT_LEAVES must exist"
        assert 10_000 <= cap <= 1_000_000, f"Cap {cap} out of range"

    def test_pathological_leaf_count_is_truncated(self):
        """A flat dict with millions of string leaves must NOT cause
        OOM — the walker stops at the cap."""
        from scruxy.providers.anthropic import _walk_json_strings, _MAX_TOOL_INPUT_LEAVES

        # Build a flat dict slightly over the cap.
        big_input = {f"k{i}": f"v{i}@example.com" for i in range(_MAX_TOOL_INPUT_LEAVES + 100)}
        fields: list = []
        _walk_json_strings(big_input, "$.deep", fields, "tool_use")
        # Must have stopped at or near the cap, not extracted all 100k+.
        assert len(fields) <= _MAX_TOOL_INPUT_LEAVES, (
            f"R59-7: cap not enforced; got {len(fields)} leaves"
        )


# ---------------------------------------------------------------------------
# R59-8 — `_walk_json_strings` parameter cleanup
# ---------------------------------------------------------------------------

class TestR59_8_WalkerParameterCleanup:
    def test_walker_signature_no_unused_depth_param(self):
        """`_depth` parameter was kept for backward compat in R58-2
        but never used — clean it up."""
        from scruxy.providers import anthropic
        import inspect as _inspect

        sig = _inspect.signature(anthropic._walk_json_strings)
        assert "_depth" not in sig.parameters, (
            "R59-8: unused _depth parameter still present"
        )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
