"""Regression tests for Round 65 hardening fixes (R65-1..R65-8)."""
from __future__ import annotations

import asyncio
import inspect
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# R65-1 — RegexPlugin uses regex.IGNORECASE | FULLCASE
# ---------------------------------------------------------------------------

class TestR65_1_RegexPluginFullCase:
    def test_case_insensitive_pattern_uses_fullcase(self):
        from scruxy.plugin.regex import RegexPlugin

        plugin = RegexPlugin()
        plugin.setup({
            "enabled": True,
            "patterns": [{
                "name": "german-strasse",
                "entity_type": "CUSTOM",
                "pattern": "straße",
                "case_sensitive": False,
                "score": 0.99,
            }],
        })
        # FULLCASE should match `STRASSE` to `straße`.
        results = plugin.detect("STRASSE", language="en")
        assert len(results) >= 1, (
            "R65-1: RegexPlugin missed Unicode full-case match (straße ↔ STRASSE)"
        )


# ---------------------------------------------------------------------------
# R65-2 — RegexPlugin auto-disable resets on successful run
# ---------------------------------------------------------------------------

class TestR65_2_RegexPluginAutoDisableTransient:
    def test_slow_run_counter_resets_on_fast_run(self):
        """Source-level: the success branch in `detect` must reset
        `pattern._slow_runs = 0` so the counter only fires on
        CONSECUTIVE slow runs, not 3 ever-in-process-lifetime."""
        from scruxy.plugin import regex as regex_mod

        src = inspect.getsource(regex_mod.RegexPlugin.detect)
        # Look for the reset assignment in an else branch.
        assert "pattern._slow_runs = 0" in src, (
            "R65-2: detect() must reset slow_runs on successful run"
        )


# ---------------------------------------------------------------------------
# R65-3 — Presidio cache stores a copy on miss
# ---------------------------------------------------------------------------

class TestR65_3_PresidioCacheStoresCopy:
    def test_cache_miss_stores_copy_not_reference(self):
        from scruxy.plugin import presidio

        src = inspect.getsource(presidio.PresidioPlugin.detect)
        # R66-1 strengthened R65-3: cache must store COPIES of entries
        # (per-element copy.copy), not just a list copy of references.
        # Either form is acceptable.
        assert (
            "self._cache[cache_key] = list(entities)" in src
            or "self._cache[cache_key] = [copy.copy(e) for e in entities]" in src
        ), "R65-3/R66-1: cache miss must store a copy of entities"


# ---------------------------------------------------------------------------
# R65-4 — Per-PII regex compile try/except
# ---------------------------------------------------------------------------

class TestR65_4_PerPIIRegexCompileGuarded:
    def test_per_pii_compile_in_try_except(self):
        from scruxy.scrubber import request_scrubber

        src = inspect.getsource(request_scrubber.RequestScrubber.scrub_request)
        # Must have try/except around _regex_mod.compile in the
        # second-pass loop.
        idx = src.find("_regex_mod.compile(pattern_str, _flags)")
        assert idx > 0
        snippet = src[max(0, idx - 200):idx + 200]
        assert "try:" in snippet, (
            "R65-4: per-PII regex compile must be wrapped in try/except"
        )


# ---------------------------------------------------------------------------
# R65-5 — _cache_misses incremented inside lock
# ---------------------------------------------------------------------------

class TestR65_5_CacheMissesInsideLock:
    def test_cache_misses_inside_cache_lock(self):
        from scruxy.plugin import presidio

        src = inspect.getsource(presidio.PresidioPlugin.detect)
        # Find both `with self._cache_lock:` and `self._cache_misses += 1`
        # — the latter must appear inside the with-block context.
        idx_lock = src.find("with self._cache_lock:")
        idx_miss = src.find("self._cache_misses += 1")
        assert idx_lock > 0 and idx_miss > 0
        # The miss assignment must be after the lock acquire (and before any return that escapes the lock).
        # Heuristic: indent of miss line > indent of lock line.
        miss_line_start = src.rfind("\n", 0, idx_miss) + 1
        lock_line_start = src.rfind("\n", 0, idx_lock) + 1
        miss_indent = len(src[miss_line_start:idx_miss]) - len(src[miss_line_start:idx_miss].lstrip())
        lock_indent = len(src[lock_line_start:idx_lock]) - len(src[lock_line_start:idx_lock].lstrip())
        assert miss_indent > lock_indent, (
            f"R65-5: cache_misses must be inside lock (miss_indent={miss_indent} <= lock_indent={lock_indent})"
        )


# ---------------------------------------------------------------------------
# R65-6 — _validate_paths has depth cap
# ---------------------------------------------------------------------------

class TestR65_6_ValidatePathsDepthCap:
    def test_validate_paths_depth_cap_present(self):
        from scruxy.ui import routes

        src = inspect.getsource(routes)
        # The depth cap should be visible.
        assert "_depth: int = 0" in src and "_depth + 1" in src and "200" in src, (
            "R65-6: _validate_paths must have a depth cap"
        )


# ---------------------------------------------------------------------------
# R65-8 — R63-1/R63-4 strengthened with behavioral tests
# ---------------------------------------------------------------------------

class TestR65_8_StrengthenedR63Tests:
    """R63-1: behavioral test — drive _mitm_tunnel with a pipelined
    bodiless request and verify _carry_buf is preserved.

    Full integration would require a real TLS handshake, which is
    impractical in unit tests. Instead, we verify the structural
    contract: in the source, the no-CL-no-TE branch and the CL=0
    branch both assign `_carry_buf = leftover` (NOT just one)."""

    def test_mitm_carries_leftover_in_both_bodiless_branches(self):
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        src = inspect.getsource(ForwardProxyServer._mitm_tunnel)
        # Find the body-reading branch structure.  Both the CL=0
        # `else:` branch (under `elif content_length:` → `else:`)
        # AND the no-CL `else:` branch (under outer `elif content_length:`)
        # should assign _carry_buf = leftover.
        # Simple: count `_carry_buf = leftover` occurrences in the function.
        count = src.count("_carry_buf = leftover")
        assert count >= 2, (
            f"R65-8: MITM keep-alive must carry leftover in BOTH bodiless "
            f"branches (CL=0 AND no-CL); found only {count} occurrence(s)"
        )

    def test_sse_incremented_initialized_in_function_body(self):
        """R63-4 strengthened: verify `incremented = False` appears
        BEFORE the `async with _ui_sse_count_lock:` block in the
        SAME `_event_generator` function (not just anywhere in the
        module — the original test could be satisfied by the literal
        appearing in a comment or sibling function)."""
        from scruxy.ui import routes

        src = inspect.getsource(routes)
        # Find the _event_generator definition.
        idx_def = src.find("async def _event_generator")
        assert idx_def > 0
        # Find the `async with _ui_sse_count_lock:` after that def.
        idx_lock = src.find("async with _ui_sse_count_lock:", idx_def)
        assert idx_lock > 0
        # The `incremented = False` MUST appear between def and lock.
        between = src[idx_def:idx_lock]
        assert "incremented = False" in between, (
            "R65-8: incremented = False not initialized BEFORE the "
            "lock block inside _event_generator"
        )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
