"""Regression tests for Round 67 hardening fixes (R67-1..R67-10)."""
from __future__ import annotations

import asyncio
import inspect
import time
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# R67-1 — RegexPlugin counts non-timeout exceptions toward slow-run threshold
# ---------------------------------------------------------------------------

class TestR67_1_RegexExceptionCountedAsSlow:
    def test_non_timeout_exception_increments_slow_runs(self):
        """A pattern.regex.finditer that raises a non-Timeout
        exception (e.g. RuntimeError) must increment _slow_runs so
        the cooldown still triggers — not silently fail-OPEN."""
        from scruxy.plugin.regex import RegexPlugin
        from scruxy.plugin.regex import _PATTERN_SLOW_DISABLE_THRESHOLD

        plugin = RegexPlugin()
        plugin.setup({
            "enabled": True,
            "patterns": [{
                "name": "p1", "entity_type": "X",
                "pattern": "alice", "score": 0.9,
            }],
        })
        target = plugin._patterns[0]

        # Replace the compiled regex with one that raises on finditer.
        class _ExplodingRegex:
            def finditer(self, *a, **kw):
                raise RuntimeError("injected fault")
        target.regex = _ExplodingRegex()

        # Drive detect: should NOT raise, should increment slow_runs.
        for _ in range(_PATTERN_SLOW_DISABLE_THRESHOLD):
            results = plugin.detect("alice should be detected", language="en")
            assert results == []  # no entities (the exception happened)

        # After threshold: the cooldown should be active.
        cooldown_active = (
            target._disabled or target._disabled_until > time.monotonic()
        )
        assert cooldown_active, (
            "R67-1: non-timeout exception should still trigger cooldown "
            "(currently fail-OPEN: pattern silently produces no detections)"
        )


# ---------------------------------------------------------------------------
# R67-2 — Presidio cache_size=0 doesn't crash
# ---------------------------------------------------------------------------

class TestR67_2_PresidioCacheSizeZero:
    def test_cache_size_zero_does_not_crash(self):
        """Source-level: detect() must guard the cache-store with
        `if self._cache_max_size > 0` so cache_size=0 doesn't
        StopIteration on `next(iter({}))`."""
        from scruxy.plugin import presidio

        src = inspect.getsource(presidio.PresidioPlugin.detect)
        assert "if self._cache_max_size > 0" in src, (
            "R67-2: cache-store must guard against cache_size <= 0"
        )


# ---------------------------------------------------------------------------
# R67-3 — Engine pre-filter empty-PII guard
# ---------------------------------------------------------------------------

class TestR67_3_EnginePrefilterEmptyPII:
    def test_empty_pii_in_scrub_map_does_not_infinite_loop(self):
        """Inject an empty key into scrub_map and verify pre_filter
        skips it (mirrors request_scrubber's `if not pii: continue`)."""
        from scruxy.pipeline.engine import PipelineEngine

        # Mock token map with an empty PII key.
        class _MockTM:
            scrub_map = {"": "REDACTED_X_1", "alice": "REDACTED_X_2"}
            unscrub_map = {"REDACTED_X_1": "", "REDACTED_X_2": "alice"}
            token_meta = {"": {}, "alice": {}}
            entity_types = {"": "X", "alice": "X"}
            def get_entity_type(self, pii):
                return self.entity_types.get(pii, "X")

        engine = PipelineEngine(stages=[])
        # _pre_filter_to_placeholders takes (text, token_map, ph_counter, ph_entries).
        result, matches, ph_counter = engine._pre_filter_to_placeholders(
            "alice goes home", _MockTM(), 0, [],
        )
        # Must complete without infinite loop.
        assert "alice" not in result or "REDACTED_X_2" in result


# ---------------------------------------------------------------------------
# R67-4 — SSEChunkBuffer auto-derives max_token_length from token map
# ---------------------------------------------------------------------------

class TestR67_4_SSEChunkBufferDerivesMaxTokenLen:
    def test_long_token_in_map_lifts_max_token_length(self):
        from scruxy.tokenmap.deanonymizer import SSEChunkBuffer

        # Mock token map with a token longer than the legacy 40-char cap.
        long_tok = "REDACTED_CUSTOM_" + "x" * 100  # 116 chars
        class _MockTM:
            unscrub_map = {long_tok: "alice"}
            scrub_map = {"alice": long_tok}
            token_meta = {"alice": {}}

        buf = SSEChunkBuffer(_MockTM())
        assert buf._max_token_length >= len(long_tok), (
            f"R67-4: max_token_length not derived from map; "
            f"got {buf._max_token_length} < {len(long_tok)}"
        )


# ---------------------------------------------------------------------------
# R67-5 — Forwarder closes 3xx-no-Location response
# ---------------------------------------------------------------------------

class TestR67_5_ForwarderClosesNoLocationResponse:
    def test_source_closes_3xx_no_location(self):
        from scruxy.proxy.forwarder import UpstreamForwarder

        src = inspect.getsource(UpstreamForwarder.forward)
        # Look for the no-Location branch.
        idx = src.find("if not location:")
        assert idx > 0
        snippet = src[idx:idx + 800]
        assert "await response.aread" in snippet and "await response.aclose" in snippet, (
            "R67-5: 3xx-no-Location must aread+aclose to release the stream"
        )


# ---------------------------------------------------------------------------
# R67-6 — Presidio post-filter doesn't log raw spans
# ---------------------------------------------------------------------------

class TestR67_6_PostFilterNoPIIInLogs:
    def test_post_filter_logs_no_raw_span(self):
        from scruxy.plugin import presidio

        src = inspect.getsource(presidio)
        # Find _apply_post_filter and verify no "%r" is used to log
        # a `span` variable.
        idx = src.find("def _apply_post_filter")
        assert idx > 0
        body = src[idx:idx + 5000]
        # The pattern `"%r"` followed by `span` in args is the bug.
        assert "logger.debug(\"Post-filter: rejected %r" not in body, (
            "R67-6: post-filter must not log raw PII span via %r"
        )


# ---------------------------------------------------------------------------
# R67-7 — PluginStorage rejects path-traversal plugin names
# ---------------------------------------------------------------------------

class TestR67_7_PluginStoragePathTraversal:
    def test_traversal_plugin_name_rejected(self, tmp_path):
        from scruxy.plugin.storage import PluginStorage

        for bad_name in ["../etc", "..", ".", "foo/bar", "foo\\bar"]:
            with pytest.raises(ValueError):
                PluginStorage(str(tmp_path), bad_name)

    def test_normal_plugin_name_accepted(self, tmp_path):
        from scruxy.plugin.storage import PluginStorage

        ps = PluginStorage(str(tmp_path), "my_plugin")
        assert ps._dir.parent == tmp_path


# ---------------------------------------------------------------------------
# R67-8 — Pre-filter case-variant doesn't fragment token map
# ---------------------------------------------------------------------------

class TestR67_8_PrefilterCanonicalPiiText:
    def test_prefilter_uses_canonical_pii_not_match_group(self):
        from scruxy.pipeline import engine

        src = inspect.getsource(engine.PipelineEngine._pre_filter_to_placeholders)
        # The fix replaced `pii_text=m.group()` with `pii_text=pii`.
        assert "pii_text=pii" in src, (
            "R67-8: pre-filter must use canonical PII, not m.group()"
        )
        # And m.group() should NOT appear as the value of pii_text.
        assert "pii_text=m.group()" not in src, (
            "R67-8: pre-filter still uses case-variant m.group() for token lookup"
        )


# ---------------------------------------------------------------------------
# R67-10 — cert/ca eviction uses single loop
# ---------------------------------------------------------------------------

class TestR67_10_CertEvictionSingleLoop:
    def test_eviction_is_single_loop(self):
        from scruxy.cert.ca import CertificateAuthority

        src = inspect.getsource(CertificateAuthority.get_host_cert)
        # The split loops should be collapsed.
        assert "stale[: max(1, len(stale) // 2)]" not in src, (
            "R67-10: stale-half split should be removed (collapsed to single loop)"
        )
        # A single `for h in stale:` should remain.
        assert "for h in stale:" in src


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
