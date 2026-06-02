"""Regression tests for Round 57 hardening fixes (R57-1, R57-2, R57-3)."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# R57-1 — Anthropic dotted/bracketed keys are scrubbed (not silently skipped)
# ---------------------------------------------------------------------------

class TestR57_1_AnthropicDottedKeysScrubbed:
    def test_extract_walks_keys_with_dots_brackets_tildes(self):
        """All special-char keys must be extracted, not skipped."""
        from scruxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        body = {
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": {
                        "user.email": "alice@example.com",
                        "key[0]": "bob@example.com",
                        "weird~name": "carol@example.com",
                        "nested": {"key[0]": "dave@example.com"},
                    },
                }],
            }],
        }
        fields = provider.extract_text_fields(body)
        values = {f.text_value for f in fields}
        assert "alice@example.com" in values, "key with `.` was skipped"
        assert "bob@example.com" in values, "key with `[` was skipped"
        assert "carol@example.com" in values, "key with `~` was skipped"
        assert "dave@example.com" in values, "nested key with `[` was skipped"

    def test_replace_round_trips_special_keys(self):
        """End-to-end: the replacement must land back at the original
        special-char keys, not at the escaped path string."""
        from scruxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        body = {
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": {
                        "user.email": "alice@example.com",
                        "key[0]": "bob@example.com",
                        "outer": {"inner.field": "carol@example.com"},
                    },
                }],
            }],
        }
        fields = provider.extract_text_fields(body)
        replacements = {
            f.json_path: f"REDACTED_EMAIL_{i}" for i, f in enumerate(fields)
        }
        out = provider.replace_text_fields(body, replacements)
        nested = out["messages"][0]["content"][0]["input"]
        assert nested["user.email"].startswith("REDACTED_EMAIL_")
        assert nested["key[0]"].startswith("REDACTED_EMAIL_")
        assert nested["outer"]["inner.field"].startswith("REDACTED_EMAIL_")

    def test_response_extract_walks_special_keys(self):
        """Same fix on the response side so REDACTED tokens at
        special-char keys are deanonymized."""
        from scruxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        body = {
            "content": [{
                "type": "tool_use",
                "input": {
                    "user.email": "REDACTED_EMAIL_1",
                    "key[0]": "REDACTED_EMAIL_2",
                },
            }],
        }
        fields = provider.extract_response_text_fields(body)
        values = {f.text_value for f in fields}
        assert "REDACTED_EMAIL_1" in values
        assert "REDACTED_EMAIL_2" in values

    def test_escape_unescape_round_trip(self):
        """Direct unit test of the escape helpers — every special char
        must round-trip losslessly."""
        from scruxy.providers.anthropic import (
            _escape_path_segment, _unescape_path_segment,
        )

        for raw in [
            "simple",
            "user.email",
            "key[0]",
            "weird~name",
            "all.special[chars]~test",
            "",
            ".",
            "[",
            "~",
            "]",
            "...",
            "~0~1~2~3",  # raw-looking-like-escapes must also round-trip
        ]:
            escaped = _escape_path_segment(raw)
            assert _unescape_path_segment(escaped) == raw, (
                f"Round-trip failed for {raw!r}: escaped={escaped!r}, "
                f"unescaped={_unescape_path_segment(escaped)!r}"
            )

    @pytest.mark.asyncio
    async def test_production_request_scrubber_path_with_dotted_keys(self):
        """The original GPT-5.5 reproducer: nested PII under
        `user.email` and `key[0]` must NOT appear in scrubbed body."""
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
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": {
                        "user.email": "alice@example.com",
                        "safe": "bob@example.com",
                        "nested": {"key[0]": "carol@example.com"},
                    },
                }],
            }],
        }
        scrubbed_body, _entities, _stages, _reused = await scrubber.scrub_request(
            body=body,
            provider=provider,
            pipeline=pipeline,
            token_map=object(),
            request_id="r1",
        )

        import json
        scrubbed_json = json.dumps(scrubbed_body)
        for raw in ("alice@example.com", "bob@example.com", "carol@example.com"):
            assert raw not in scrubbed_json, (
                f"R57-1: {raw!r} leaked through scrub: {scrubbed_json}"
            )


# ---------------------------------------------------------------------------
# R57-2 — `_walk_json_strings` has a recursion-depth cap
# ---------------------------------------------------------------------------

class TestR57_2_WalkJsonStringsDepthCap:
    def test_max_depth_constant_exists(self):
        from scruxy.providers import anthropic

        cap = getattr(anthropic, "_MAX_TOOL_INPUT_DEPTH", None)
        assert cap is not None, "_MAX_TOOL_INPUT_DEPTH must be defined"
        assert 50 <= cap <= 1000, f"Depth cap {cap} out of reasonable range"

    def test_deeply_nested_input_does_not_recursionerror_AND_extracts_deep_pii(self):
        """Build a 5000-level-nested dict and confirm extraction
        does NOT raise RecursionError AND ALSO extracts the deeply-
        nested PII leaf.

        R58-2 supersedes the original R57-2 depth-cap behavior:
        the walker is now iterative, so deep PII is no longer
        silently fail-open dropped — it's extracted and scrubbed."""
        from scruxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()

        # Build {"k": {"k": ... 5000 deep ... {"leaf": "alice@example.com"}}}
        leaf: object = {"leaf": "alice@example.com"}
        nested: object = leaf
        for _ in range(5000):
            nested = {"k": nested}

        body = {
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": nested,
                }],
            }],
        }
        # Must NOT raise RecursionError.
        fields = provider.extract_text_fields(body)
        assert isinstance(fields, list)
        # R58-2 fix: deep PII MUST be extracted (no fail-open).
        values = {f.text_value for f in fields}
        assert "alice@example.com" in values, (
            "R58-2: deep PII at 5000 levels NOT extracted — fail-open leak"
        )


# ---------------------------------------------------------------------------
# R57-3 — SSE cap holdback covers long tokens (>128 bytes)
# ---------------------------------------------------------------------------

class TestR57_3_SSEHoldbackForLongTokens:
    def test_holdback_constant_is_at_least_4kb(self):
        from scruxy.proxy import forward_proxy, routes

        for module in (forward_proxy, routes):
            cap = module._MAX_TOKEN_HOLDBACK_BYTES
            assert cap >= 4096, (
                f"R57-3: {module.__name__}._MAX_TOKEN_HOLDBACK_BYTES "
                f"= {cap}, must be >= 4096 to cover script-replacement tokens"
            )

    def test_constants_match_across_modules(self):
        from scruxy.proxy import forward_proxy, routes

        assert (
            forward_proxy._MAX_TOKEN_HOLDBACK_BYTES
            == routes._MAX_TOKEN_HOLDBACK_BYTES
        ), "Forward and reverse proxy holdback constants must match"

    @pytest.mark.asyncio
    async def test_long_token_at_cap_boundary_survives(self):
        """A 1KB token literal positioned at the cap boundary must
        re-join the next chunk for the unscrubber's trie matcher.
        With the old 128-byte holdback this would bisect; with the
        new 4KB holdback it survives."""
        from scruxy.proxy.forward_proxy import (
            _MAX_SSE_LINE_BUFFER_BYTES,
            _MAX_TOKEN_HOLDBACK_BYTES,
        )

        # Build a 1024-byte custom token (script-replacement style).
        long_token = b"REDACTED_CUSTOM_" + b"x" * 1000 + b"_END"
        assert len(long_token) > 128, "Token must be >128 bytes to test R57-3"
        # Position it exactly at the cap boundary.
        prefix = b"y" * (_MAX_SSE_LINE_BUFFER_BYTES + 1 - len(long_token) // 2)
        first_chunk = prefix + long_token[: len(long_token) // 2]
        second_chunk = long_token[len(long_token) // 2:] + b"\n"

        async def _aiter():
            yield first_chunk
            yield second_chunk

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
        intact_segments = sum(1 for seg in result if long_token in seg)
        assert intact_segments == 1, (
            f"R57-3: long token bisected — found in {intact_segments} segments"
        )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
