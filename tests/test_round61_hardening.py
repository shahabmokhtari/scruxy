"""Regression tests for Round 61 hardening fixes (R61-1..R61-5)."""
from __future__ import annotations

import asyncio
import inspect
import json
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# R61-1 — Stack cap enforced per-append; flat oversized input still extracts
# ---------------------------------------------------------------------------

class TestR61_1_StackCapPerAppend:
    def test_flat_oversized_dict_extracts_capped_leaves_not_zero(self, monkeypatch):
        """A flat dict larger than the stack cap must still extract
        leaves up to the cap — NOT return with `leaves_added==0`."""
        from scruxy.providers import anthropic
        from scruxy.providers.anthropic import _walk_json_strings

        # Lower the stack cap to make the test deterministic and fast.
        monkeypatch.setattr(anthropic, "_MAX_TOOL_INPUT_STACK", 100)

        # Build a flat dict with 200 keys (well over the cap).
        flat = {f"k{i}": f"user{i}@example.com" for i in range(200)}
        fields: list = []
        _walk_json_strings(flat, "$.input", fields, "tool_use")

        # MUST extract some leaves (not zero — that would be R61-1 bug).
        assert len(fields) > 0, (
            "R61-1: walker returned with 0 leaves on flat oversized input "
            "— PII would be forwarded raw upstream"
        )
        # Must respect the stack cap (i.e. not all 200).
        assert len(fields) <= 100, (
            f"R61-1: stack cap not enforced; got {len(fields)} > 100"
        )

    def test_flat_oversized_list_extracts_capped_leaves_not_zero(self, monkeypatch):
        from scruxy.providers import anthropic
        from scruxy.providers.anthropic import _walk_json_strings

        monkeypatch.setattr(anthropic, "_MAX_TOOL_INPUT_STACK", 50)
        flat = [f"user{i}@example.com" for i in range(150)]
        fields: list = []
        _walk_json_strings(flat, "$.input", fields, "tool_use")

        assert len(fields) > 0
        assert len(fields) <= 50

    def test_at_cap_boundary_extracts_full_capacity(self, monkeypatch):
        """Inputs just at the cap should extract everything."""
        from scruxy.providers import anthropic
        from scruxy.providers.anthropic import _walk_json_strings

        monkeypatch.setattr(anthropic, "_MAX_TOOL_INPUT_STACK", 100)
        flat = {f"k{i}": f"v{i}@example.com" for i in range(50)}  # under cap
        fields: list = []
        _walk_json_strings(flat, "$.input", fields, "tool_use")
        assert len(fields) == 50, f"Expected 50, got {len(fields)}"


# ---------------------------------------------------------------------------
# R61-2 — Forward proxy traversal guard handles percent-encoded variants
# ---------------------------------------------------------------------------

class TestR61_2_PercentEncodedTraversalRejected:
    @pytest.mark.asyncio
    async def test_forward_proxy_rejects_percent_encoded_dotdot(self):
        """A path with `%2e%2e` must return 400 BEFORE provider matching."""
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
            "/v1/messages/%2e%2e/models",
            "/v1/messages/%2E%2E/models",
            "/v1/foo/%2e/chat/completions",
        ]:
            status, _hdr, _body = await server._scrub_and_forward(
                method="POST",
                url=f"https://api.example.com{path_variant}",
                headers={"content-type": "application/json"},
                body=b'{"x":"y"}',
            )
            assert status == 400, (
                f"R61-2: forward proxy did not reject {path_variant!r}; got {status}"
            )
            # Provider matching must NOT have been reached.
            registry.match.assert_not_called()
            registry.match.reset_mock()


# ---------------------------------------------------------------------------
# R61-3 — Per-request total leaf ceiling across tool_use blocks
# ---------------------------------------------------------------------------

class TestR61_3_PerRequestLeafCeiling:
    def test_per_request_constant_exists(self):
        from scruxy.providers import anthropic

        cap = getattr(anthropic, "_MAX_TOOL_INPUT_LEAVES_PER_REQUEST", None)
        assert cap is not None, "_MAX_TOOL_INPUT_LEAVES_PER_REQUEST must exist"
        assert cap >= 100_000

    def test_request_with_many_blocks_capped_at_request_total(self, monkeypatch):
        """Many tool_use blocks each adding leaves must cap at the
        per-request total (not allow unbounded accumulation)."""
        from scruxy.providers import anthropic
        from scruxy.providers.anthropic import AnthropicProvider

        # Lower cap for the test.
        monkeypatch.setattr(anthropic, "_MAX_TOOL_INPUT_LEAVES_PER_REQUEST", 20)

        provider = AnthropicProvider()
        # Build a request with 10 tool_use blocks each containing 5 PII strings = 50 leaves total.
        content_blocks = [
            {"type": "tool_use", "input": {f"k{i}": f"user{b}_{i}@example.com" for i in range(5)}}
            for b in range(10)
        ]
        body = {"messages": [{"role": "assistant", "content": content_blocks}]}
        fields = provider.extract_text_fields(body)

        # Capped at per-request total (allow some slop for boundary).
        assert len(fields) <= 25, (
            f"R61-3: per-request cap not enforced; got {len(fields)} leaves"
        )


# ---------------------------------------------------------------------------
# R61-4 — Doubled JSON round-trip removed
# ---------------------------------------------------------------------------

class TestR61_4_NoDoubledJSONRoundTrip:
    def test_request_scrubber_does_not_call_json_dumps_on_body(self):
        """Source-level: `scrub_request` must NOT call `json.dumps(body)`
        — providers do their own deep-copy."""
        from scruxy.scrubber import request_scrubber

        src = inspect.getsource(request_scrubber.RequestScrubber.scrub_request)
        # Walk: find the section after second-pass scrub.
        # The R59-6 round-trip used `json.dumps(body)` literally;
        # post-R61-4 it should NOT appear in this method.
        # Allow `json.dumps` for other purposes if any (e.g. logging),
        # but specifically the body deep-copy line must be gone.
        assert "json.dumps(body)" not in src, (
            "R61-4: scrub_request still calls json.dumps(body) — "
            "doubled round-trip with provider.replace_text_fields"
        )

    @pytest.mark.asyncio
    async def test_scrub_request_still_does_not_mutate_original(self):
        """Regression: the contract that `scrub_request` returns a
        NEW body and does not mutate the original must still hold
        even after R61-4 removed the explicit deep-copy."""
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

        body = {
            "messages": [{"role": "user", "content": "Email me at alice@example.com"}],
        }
        original_content = body["messages"][0]["content"]
        scrubbed, _e, _s, _r = await scrubber.scrub_request(
            body=body, provider=provider, pipeline=pipeline,
            token_map=object(), request_id="r1",
        )
        # Original body unchanged.
        assert body["messages"][0]["content"] == original_content
        # Scrubbed body has the replacement.
        assert "REDACTED_EMAIL_X" in scrubbed["messages"][0]["content"]


# ---------------------------------------------------------------------------
# R61-5 — R60-8 stack cap test is now BEHAVIORAL (covered by R61-1 above)
# ---------------------------------------------------------------------------

# R61-5 is satisfied by TestR61_1_StackCapPerAppend's behavioral
# tests above — they exercise the production walker with a real
# oversized container and assert the cap actually fires correctly
# (vs. the prior R60-8 test which only grep'd the source for the
# constant string).


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
