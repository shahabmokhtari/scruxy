"""Regression tests for Round 56 hardening fixes (R56-1, R56-2)."""
from __future__ import annotations

import asyncio
import inspect
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# R56-1 — Anthropic tool_use.input nested PII is scrubbed recursively
# ---------------------------------------------------------------------------

class TestR56_1_AnthropicToolUseNestedScrub:
    def test_request_extract_walks_nested_dict(self):
        """A nested dict inside `tool_use.input` must produce TextField
        entries for every string leaf, not just top-level ones."""
        from scruxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        body = {
            "model": "claude-3",
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": {
                        "top": "bob@example.com",
                        "outer": {"email": "alice@example.com"},
                    },
                }],
            }],
        }
        fields = provider.extract_text_fields(body)

        values = {f.text_value for f in fields}
        assert "bob@example.com" in values, "Top-level string missed"
        assert "alice@example.com" in values, (
            "Nested string was NOT extracted (R56-1: real PII leaks upstream)"
        )

    def test_request_extract_walks_nested_list(self):
        """A list of strings inside `tool_use.input` must be walked too."""
        from scruxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        body = {
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": {
                        "items": ["a@example.com", "b@example.com"],
                    },
                }],
            }],
        }
        fields = provider.extract_text_fields(body)

        values = {f.text_value for f in fields}
        assert "a@example.com" in values
        assert "b@example.com" in values

    def test_response_extract_walks_nested_dict(self):
        """Same nested walk on the response side so REDACTED tokens
        in nested `tool_use.input` are deanonymized correctly."""
        from scruxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        body = {
            "content": [{
                "type": "tool_use",
                "input": {
                    "top": "REDACTED_EMAIL_ADDRESS_1",
                    "outer": {"email": "REDACTED_EMAIL_ADDRESS_2"},
                },
            }],
        }
        fields = provider.extract_response_text_fields(body)

        values = {f.text_value for f in fields}
        assert "REDACTED_EMAIL_ADDRESS_1" in values
        assert "REDACTED_EMAIL_ADDRESS_2" in values

    def test_replace_round_trips_nested(self):
        """End-to-end: extract → replace → re-extract must give back
        the replaced values at the correct nested locations."""
        from scruxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        body = {
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": {
                        "top": "bob@example.com",
                        "outer": {"email": "alice@example.com"},
                    },
                }],
            }],
        }
        fields = provider.extract_text_fields(body)
        # Replace each PII with a token.
        replacements = {
            f.json_path: f"REDACTED_EMAIL_{i}" for i, f in enumerate(fields)
        }
        out = provider.replace_text_fields(body, replacements)

        # The nested `outer.email` must be replaced.
        nested = out["messages"][0]["content"][0]["input"]["outer"]["email"]
        assert nested.startswith("REDACTED_EMAIL_"), (
            f"Nested replacement did not happen — got {nested!r}"
        )
        top = out["messages"][0]["content"][0]["input"]["top"]
        assert top.startswith("REDACTED_EMAIL_")

    def test_keys_with_dots_are_extracted_via_escape(self):
        """R57-1 supersedes the original R56-1 skip behavior:
        keys containing ``.`` (and ``[``, ``]``, ``~``) are now
        losslessly escaped via ``_escape_path_segment`` so PII at
        such keys is extracted, scrubbed, and replaced — NOT
        silently forwarded raw."""
        from scruxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        body = {
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": {
                        "valid": "alice@example.com",
                        "key.with.dots": "extracted@example.com",
                        "key[0]": "bracketed@example.com",
                    },
                }],
            }],
        }
        fields = provider.extract_text_fields(body)
        values = {f.text_value for f in fields}
        assert "alice@example.com" in values
        assert "extracted@example.com" in values
        assert "bracketed@example.com" in values

        # Round-trip: replacements must reach the original nested keys.
        replacements = {
            f.json_path: f"REDACTED_EMAIL_{i}" for i, f in enumerate(fields)
        }
        out = provider.replace_text_fields(body, replacements)
        nested_input = out["messages"][0]["content"][0]["input"]
        assert nested_input["valid"].startswith("REDACTED_EMAIL_")
        assert nested_input["key.with.dots"].startswith("REDACTED_EMAIL_")
        assert nested_input["key[0]"].startswith("REDACTED_EMAIL_")

    @pytest.mark.asyncio
    async def test_production_request_scrubber_path_with_nested(self):
        """Drive the actual production scrub_request path with a
        nested tool_use.input.  The scrubbed body must have NO raw
        email at any depth."""
        from scruxy.providers.anthropic import AnthropicProvider
        from scruxy.scrubber.request_scrubber import RequestScrubber
        from scruxy.pipeline.models import PipelineResult
        from unittest.mock import AsyncMock

        # Mock pipeline that scrubs emails by deterministic substitution.
        async def _scrub_text(text, token_map, ctx=None, **kwargs):
            import re
            scrubbed = re.sub(
                r"[\w.+-]+@[\w-]+\.[\w.-]+", "REDACTED_EMAIL_X", text,
            )
            return PipelineResult(scrubbed_text=scrubbed, entities=[])

        pipeline = AsyncMock()
        pipeline.scrub_text = AsyncMock(side_effect=_scrub_text)

        provider = AnthropicProvider()
        scrubber = RequestScrubber()

        body = {
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": {
                        "top": "bob@example.com",
                        "outer": {"email": "alice@example.com"},
                    },
                }],
            }],
        }
        scrubbed_body, entities, _stage_timings, _reused = await scrubber.scrub_request(
            body=body,
            provider=provider,
            pipeline=pipeline,
            token_map=object(),
            request_id="r1",
        )

        import json
        scrubbed_json = json.dumps(scrubbed_body)
        assert "alice@example.com" not in scrubbed_json, (
            f"R56-1: nested email leaked: {scrubbed_json}"
        )
        assert "bob@example.com" not in scrubbed_json
        # Both substitutions actually happened.
        assert scrubbed_body["messages"][0]["content"][0]["input"]["top"] == "REDACTED_EMAIL_X"
        assert scrubbed_body["messages"][0]["content"][0]["input"]["outer"]["email"] == "REDACTED_EMAIL_X"


# ---------------------------------------------------------------------------
# R56-2 — SSE buffer cap holds back trailing bytes to avoid token bisection
# ---------------------------------------------------------------------------

class TestR56_2_SSECapHoldsBackTokenTail:
    def test_holdback_constant_exists_in_both_modules(self):
        from scruxy.proxy import forward_proxy, routes

        assert hasattr(forward_proxy, "_MAX_TOKEN_HOLDBACK_BYTES")
        assert hasattr(routes, "_MAX_TOKEN_HOLDBACK_BYTES")
        assert (
            forward_proxy._MAX_TOKEN_HOLDBACK_BYTES
            == routes._MAX_TOKEN_HOLDBACK_BYTES
        )
        assert forward_proxy._MAX_TOKEN_HOLDBACK_BYTES >= 64

    def test_forward_proxy_uses_holdback_in_sse_cap(self):
        """The cap-flush block must reference the holdback constant
        and yield only `buf[:-_MAX_TOKEN_HOLDBACK_BYTES]`, not the full
        buf.  Source-level structural assertion."""
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        src = inspect.getsource(ForwardProxyServer._scrub_and_forward)
        assert "_MAX_TOKEN_HOLDBACK_BYTES" in src, (
            "forward_proxy _sse_lines does not use _MAX_TOKEN_HOLDBACK_BYTES"
        )
        assert "yield buf[:-_MAX_TOKEN_HOLDBACK_BYTES]" in src, (
            "forward_proxy _sse_lines must yield buf with holdback slice"
        )

    def test_reverse_proxy_uses_holdback_in_sse_cap(self):
        from scruxy.proxy.routes import _handle_sse_response

        src = inspect.getsource(_handle_sse_response)
        assert "_MAX_TOKEN_HOLDBACK_BYTES" in src, (
            "reverse-proxy _sse_lines does not use _MAX_TOKEN_HOLDBACK_BYTES"
        )
        assert "yield buf[:-_MAX_TOKEN_HOLDBACK_BYTES]" in src

    @pytest.mark.asyncio
    async def test_token_at_cap_boundary_survives_via_holdback(self):
        """Behavioral simulation of the post-R56-2 cap-flush logic:
        a `REDACTED_EMAIL_42` token literal positioned exactly at the
        cap boundary must re-join the next chunk on the next iteration
        rather than be split."""
        from scruxy.proxy.forward_proxy import (
            _MAX_SSE_LINE_BUFFER_BYTES,
            _MAX_TOKEN_HOLDBACK_BYTES,
        )

        # Build a buffer that's just over cap, ending with a partial token.
        token = b"REDACTED_EMAIL_ADDRESS_42"
        # Position the token to straddle the cap boundary.
        prefix = b"x" * (_MAX_SSE_LINE_BUFFER_BYTES + 1 - len(token) // 2)
        first_chunk = prefix + token[: len(token) // 2]
        # Simulate the second chunk completes the token + adds a newline.
        second_chunk = token[len(token) // 2:] + b"\n"

        async def _aiter():
            yield first_chunk
            yield second_chunk

        # Reproduce the post-R56-2 cap-and-holdback logic.
        async def _sse_lines_simulation():
            buf = b""
            yielded = []
            async for raw_chunk in _aiter():
                buf += raw_chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    yielded.append(line)
                if len(buf) > _MAX_SSE_LINE_BUFFER_BYTES:
                    if len(buf) > _MAX_TOKEN_HOLDBACK_BYTES:
                        yielded.append(buf[:-_MAX_TOKEN_HOLDBACK_BYTES])
                        buf = buf[-_MAX_TOKEN_HOLDBACK_BYTES:]
                    else:
                        yielded.append(buf)
                        buf = b""
            if buf:
                yielded.append(buf)
            return yielded

        result = await _sse_lines_simulation()

        # The full token literal must appear in exactly one yielded
        # segment (not split across two).
        intact_in_segments = sum(1 for seg in result if token in seg)
        assert intact_in_segments == 1, (
            f"R56-2: token was bisected — found in {intact_in_segments} segments"
        )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
