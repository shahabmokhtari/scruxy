"""Regression tests for Round 58 hardening fixes (R58-1..R58-7)."""
from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# R58-1 — OpenAI/Copilot Responses API tool outputs are scrubbed/deanonymized
# ---------------------------------------------------------------------------

class TestR58_1_ResponsesAPIToolOutputs:
    def _yaml_paths(self, name: str) -> dict:
        import yaml
        path = Path("default_config/providers") / f"{name}.yaml"
        return yaml.safe_load(path.read_text())

    def test_openai_responses_extracts_input_output(self):
        """R58-1 fix: $.input[*].output must be in request_text_paths."""
        cfg = self._yaml_paths("openai_responses")
        assert "$.input[*].output" in cfg["request_text_paths"], (
            "R58-1: $.input[*].output missing from openai_responses.yaml — "
            "function_call_output PII forwarded raw"
        )

    def test_copilot_responses_extracts_input_output(self):
        cfg = self._yaml_paths("copilot_responses")
        assert "$.input[*].output" in cfg["request_text_paths"], (
            "R58-1: $.input[*].output missing from copilot_responses.yaml"
        )

    def test_openai_responses_deanonymizes_output_arguments(self):
        cfg = self._yaml_paths("openai_responses")
        assert "$.output[*].arguments" in cfg["response_text_paths"], (
            "R58-1: $.output[*].arguments missing — function_call args "
            "in non-streaming responses are not deanonymized"
        )

    def test_copilot_responses_deanonymizes_output_arguments(self):
        cfg = self._yaml_paths("copilot_responses")
        assert "$.output[*].arguments" in cfg["response_text_paths"]

    @pytest.mark.asyncio
    async def test_function_call_output_is_extracted_by_yaml_provider(self):
        """End-to-end: load the openai_responses YAML provider and
        confirm a `function_call_output` body has its `output` field
        extracted as a TextField."""
        from scruxy.providers.yaml_provider import YAMLProvider
        import yaml

        cfg_path = Path("default_config/providers/openai_responses.yaml")
        cfg = yaml.safe_load(cfg_path.read_text())
        provider = YAMLProvider(cfg)

        body = {
            "input": [
                {
                    "type": "function_call_output",
                    "call_id": "call_1",
                    "output": "customer alice@example.com",
                }
            ]
        }
        fields = provider.extract_text_fields(body)
        values = {f.text_value for f in fields}
        assert "customer alice@example.com" in values, (
            f"R58-1: function_call_output.output not extracted; got {values}"
        )


# ---------------------------------------------------------------------------
# R58-2 — Anthropic depth cap NO LONGER fail-open (iterative walker)
# ---------------------------------------------------------------------------

class TestR58_2_IterativeWalkerNoFailOpen:
    def test_walker_is_iterative(self):
        """Source-level: `_walk_json_strings` must use a stack, not
        recurse on itself.  This eliminates the fail-open behavior
        entirely — there's no depth cap to hit."""
        from scruxy.providers import anthropic

        src = inspect.getsource(anthropic._walk_json_strings)
        # No recursive self-call.
        recurse_calls = src.count("_walk_json_strings(")
        # The function definition counts as 1 occurrence.
        assert recurse_calls <= 1, (
            f"R58-2: _walk_json_strings still recurses ({recurse_calls} "
            "self-calls); must be iterative"
        )
        # Must use an explicit stack.
        assert "stack" in src.lower() or "while" in src, (
            "R58-2: iterative walker should use a stack/while loop"
        )

    def test_deep_pii_below_old_depth_cap_is_extracted(self):
        """Build a 1000-level nested dict (deep enough to exceed the
        old _MAX_TOOL_INPUT_DEPTH=200 cap) and confirm the deep
        leaf PII is extracted, not silently dropped."""
        from scruxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        leaf: object = "alice@example.com"
        nested: object = leaf
        for _ in range(1000):
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
        fields = provider.extract_text_fields(body)
        values = {f.text_value for f in fields}
        assert "alice@example.com" in values, (
            "R58-2: deep PII (>200 levels) not extracted — fail-open"
        )

    @pytest.mark.asyncio
    async def test_production_scrub_path_does_not_leak_deep_pii(self):
        """End-to-end: scrub a request with deep PII.  The scrubbed
        body must NOT contain the raw email even at depth >200
        (the old R57-2 fail-open cap)."""
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

        # Use depth 250 — past the old R57-2 cap (200) but still
        # within Python's default recursion limit when combined with
        # request_scrubber.deepcopy.
        leaf: object = "deep.alice@example.com"
        nested: object = leaf
        for _ in range(250):
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
        # Bump recursion limit slightly for the request_scrubber's
        # internal deepcopy (a separate concern from R58-2's iterative
        # walker fix).
        import sys
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(5000)
        try:
            scrubbed_body, _entities, _stages, _reused = await scrubber.scrub_request(
                body=body, provider=provider, pipeline=pipeline,
                token_map=object(), request_id="r1",
            )
            assert "deep.alice@example.com" not in json.dumps(scrubbed_body), (
                "R58-2: deep PII leaked through production scrub path"
            )
        finally:
            sys.setrecursionlimit(old_limit)


# ---------------------------------------------------------------------------
# R58-3 — Empty token from custom ReplacementStrategy is rejected
# ---------------------------------------------------------------------------

class TestR58_3_EmptyTokenRejected:
    def test_empty_string_replacement_returns_none(self):
        """A ReplacementStrategy returning ``""`` must be rejected
        the same as one returning ``None``.  Otherwise the empty
        token causes infinite-loop in `_build_occupied_ranges` and
        response corruption in `deanonymize_text`."""
        from scruxy.tokenmap.token_map import TokenMap

        class _EmptyStrategy:
            def generate(self, entity_type, pii, count):
                return ""

        tm = TokenMap(replacements={"EMAIL": _EmptyStrategy()})
        token = tm.get_or_create_token("alice@example.com", "EMAIL")
        assert token is None, (
            f"R58-3: empty-string token NOT rejected — got {token!r}"
        )

    def test_build_occupied_ranges_does_not_infinite_loop_on_empty_token(self):
        """Even if an empty token were ever passed in by accident,
        downstream code should be robust.  This test asserts the
        guard in get_or_create_token prevents the empty token from
        ever reaching the danger zone."""
        from scruxy.tokenmap.token_map import TokenMap

        class _MixedStrategy:
            def __init__(self):
                self.calls = 0

            def generate(self, entity_type, pii, count):
                self.calls += 1
                # First call returns empty (rejected); subsequent OK.
                return "" if self.calls == 1 else None

        tm = TokenMap(replacements={"EMAIL": _MixedStrategy()})
        # Empty rejected → returns None.
        assert tm.get_or_create_token("a@b.com", "EMAIL") is None
        # No infinite loop, no corruption.


# ---------------------------------------------------------------------------
# R58-4 — Plugin teardown is called on lifespan shutdown
# ---------------------------------------------------------------------------

class TestR58_4_PluginTeardownOnShutdown:
    def test_lifespan_invokes_pipeline_stage_teardown(self):
        """Source-level: `lifespan` must iterate `pipeline.stages`
        and call `teardown()` on each stage that has one."""
        from scruxy import app as app_module

        src = inspect.getsource(app_module.lifespan)
        assert "pipeline.stages" in src or "stages" in src, (
            "R58-4: lifespan should iterate pipeline.stages"
        )
        assert "teardown" in src, (
            "R58-4: lifespan should call stage.teardown()"
        )


# ---------------------------------------------------------------------------
# R58-5 — Multi-value request headers are preserved
# ---------------------------------------------------------------------------

class TestR58_5_MultiValueHeadersPreserved:
    def test_duplicate_cookie_headers_concatenated(self):
        """Two `Cookie` lines must be combined per RFC 6265 §5.4
        (semicolon-delimited) — NOT comma per R59-3 fix."""
        from scruxy.proxy.forward_proxy import _parse_headers

        raw = "Cookie: session=abc\nCookie: csrf=xyz\n"
        parsed = _parse_headers(raw)
        # R59-1: keys stored lowercased.
        cookie = parsed.get("cookie", "")
        assert "session=abc" in cookie, "First Cookie value lost"
        assert "csrf=xyz" in cookie, "Second Cookie value lost"
        # R59-3: cookies must be `; `-separated, not `, `.
        assert "; " in cookie, (
            f"R59-3: Cookie joined with wrong delimiter: {cookie!r}"
        )

    def test_other_duplicate_headers_concatenated(self):
        """Generic duplicate non-Cookie headers concatenate with `, `."""
        from scruxy.proxy.forward_proxy import _parse_headers

        raw = "X-Custom: a\nX-Custom: b\n"
        parsed = _parse_headers(raw)
        # R59-1: keys stored lowercased.
        val = parsed.get("x-custom", "")
        assert "a" in val and "b" in val
        assert ", " in val, f"R59-3: non-Cookie should join with `, `: {val!r}"

    def test_sensitive_framing_headers_still_rejected_on_duplicate(self):
        """Content-Length / Transfer-Encoding duplicates must STILL
        raise (request smuggling defence)."""
        from scruxy.proxy.forward_proxy import _parse_headers

        raw = "Content-Length: 10\nContent-Length: 20\n"
        with pytest.raises(ValueError):
            _parse_headers(raw)


# ---------------------------------------------------------------------------
# R58-6 — Implicit (R58-2 also resolves: no log emits raw path)
# R58-7 — Dead else-branch removed from cap-flush
# ---------------------------------------------------------------------------

class TestR58_7_NoDeadElseBranch:
    def test_forward_proxy_cap_flush_no_else_branch(self):
        """The cap-flush body must NOT contain `else: yield buf;
        buf = b""` after the holdback slice — the outer `len > 1MiB`
        guard already ensures `len > 4KiB` so the else was unreachable."""
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        src = inspect.getsource(ForwardProxyServer._scrub_and_forward)
        # Find the cap-flush block and check it doesn't have the
        # nested `if len(buf) > _MAX_TOKEN_HOLDBACK_BYTES` guard
        # any more.
        cap_idx = src.find("SSE residual buffer exceeded")
        assert cap_idx > 0
        snippet = src[cap_idx:cap_idx + 800]
        assert "if len(buf) > _MAX_TOKEN_HOLDBACK_BYTES" not in snippet, (
            "R58-7: dead inner cap-check still present"
        )

    def test_reverse_proxy_cap_flush_no_else_branch(self):
        from scruxy.proxy.routes import _handle_sse_response

        src = inspect.getsource(_handle_sse_response)
        cap_idx = src.find("SSE residual buffer exceeded")
        assert cap_idx > 0
        snippet = src[cap_idx:cap_idx + 800]
        assert "if len(buf) > _MAX_TOKEN_HOLDBACK_BYTES" not in snippet


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
