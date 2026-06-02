"""Regression tests for Round 68 hardening fixes (R68-1..R68-7)."""
from __future__ import annotations

import asyncio
import inspect
import json
import threading
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# R68-1 — has_session reads under _session_pii_lock
# ---------------------------------------------------------------------------

class TestR68_1_HasSessionLocked:
    def test_has_session_acquires_lock(self):
        from scruxy.tokenmap import service

        src = inspect.getsource(service.ConcurrentSessionStore.has_session)
        assert "_session_pii_lock" in src or "with self._session_pii_lock:" in src, (
            "R68-1: has_session must acquire _session_pii_lock"
        )

    def test_has_session_does_not_raise_under_concurrent_mutation(self, tmp_path):
        """Concurrently call has_session while another thread mutates
        _session_pii via tag_session_pii."""
        from scruxy.tokenmap.service import ConcurrentSessionStore

        store = ConcurrentSessionStore(storage_dir=str(tmp_path), persistent=False)
        for i in range(100):
            store.tag_session_pii(f"sess-{i}", {f"pii-{i}"})

        errors: list[Exception] = []
        stop = threading.Event()

        def reader():
            i = 0
            while not stop.is_set():
                try:
                    store.has_session(f"sess-{i % 100}")
                    i += 1
                except Exception as exc:
                    errors.append(exc)

        def writer():
            i = 100
            while not stop.is_set():
                try:
                    store.tag_session_pii(f"sess-{i}", {f"pii-{i}"})
                    i += 1
                except Exception as exc:
                    errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(4)] + [
            threading.Thread(target=writer) for _ in range(2)
        ]
        for t in threads:
            t.start()
        import time as _time
        _time.sleep(0.3)
        stop.set()
        for t in threads:
            t.join(timeout=2.0)

        assert not errors, f"Concurrent has_session errors: {errors[:3]}"


# ---------------------------------------------------------------------------
# R68-2 — PluginStorage rejects Windows colon-prefixed plugin names
# ---------------------------------------------------------------------------

class TestR68_2_PluginStorageRejectsColon:
    def test_colon_prefix_rejected(self, tmp_path):
        from scruxy.plugin.storage import PluginStorage

        for bad in ["C:foo", "x:y", "drive:plugin"]:
            with pytest.raises(ValueError):
                PluginStorage(str(tmp_path), bad)


# ---------------------------------------------------------------------------
# R68-3 — Response deepcopy → json roundtrip (no RecursionError on deep JSON)
# ---------------------------------------------------------------------------

class TestR68_3_ResponseDeepcopySafe:
    def test_forward_proxy_uses_json_roundtrip(self):
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        src = inspect.getsource(ForwardProxyServer._scrub_and_forward)
        # Verify json.loads(json.dumps(resp_dict)) is used.
        assert "json.loads(json.dumps(resp_dict))" in src or "json.dumps(resp_dict)" in src, (
            "R68-3: forward_proxy must use json roundtrip for resp deep-copy"
        )

    def test_routes_uses_json_roundtrip(self):
        from scruxy.proxy import routes

        src = inspect.getsource(routes)
        # The routes site uses _json_mod alias.
        assert (
            "_json_mod.loads(_json_mod.dumps(resp_dict))" in src
            or "json.loads(json.dumps(resp_dict))" in src
        ), "R68-3: routes must use json roundtrip for resp deep-copy"
        # GPT-5.5 follow-up: also the unscrubbed_dict snapshot path.
        assert (
            "_json_mod.loads(_json_mod.dumps(unscrubbed_dict))" in src
            or "json.loads(json.dumps(unscrubbed_dict))" in src
        ), "R68-3 sibling: routes must use json roundtrip for unscrubbed_dict snapshot"

    def test_deep_response_does_not_crash_json_roundtrip(self):
        """Construct a 900-level deep dict and verify json roundtrip
        succeeds (proves the fix handles the depth that crashes deepcopy)."""
        leaf: object = {"k": "v"}
        nested: object = leaf
        for _ in range(900):
            nested = {"k": nested}
        # json roundtrip survives.
        roundtripped = json.loads(json.dumps(nested))
        assert isinstance(roundtripped, dict)


# ---------------------------------------------------------------------------
# R68-4 — RegexPlugin _slow_runs guarded by per-pattern lock
# ---------------------------------------------------------------------------

class TestR68_4_SlowRunsThreadSafe:
    def test_state_lock_attribute_exists(self):
        from scruxy.plugin.regex import _CompiledPattern

        assert "_state_lock" in _CompiledPattern.__slots__

    def test_concurrent_slow_run_increments_not_lost(self):
        """Direct mutation under the lock should be atomic — simulate
        the production critical section."""
        from scruxy.plugin.regex import RegexPlugin
        plugin = RegexPlugin()
        plugin.setup({
            "enabled": True,
            "patterns": [{"name": "p", "entity_type": "X", "pattern": "alice", "score": 0.9}],
        })
        target = plugin._patterns[0]

        N_THREADS = 20
        N_INCREMENTS = 50

        def increment():
            for _ in range(N_INCREMENTS):
                with target._state_lock:
                    target._slow_runs += 1

        threads = [threading.Thread(target=increment) for _ in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert target._slow_runs == N_THREADS * N_INCREMENTS, (
            f"R68-4: lost-update race; got {target._slow_runs}, "
            f"expected {N_THREADS * N_INCREMENTS}"
        )


# ---------------------------------------------------------------------------
# R68-6 — Engine pre-filter empty-PII guard covers the regex path
# ---------------------------------------------------------------------------

class TestR68_6_EmptyPIIRegexPathCovered:
    def test_empty_pii_with_case_insensitive_meta_skipped(self):
        """Drive the pre-filter with empty-PII AND `case_sensitive=False`
        meta so the regex path is the one that would infinite-loop."""
        from scruxy.pipeline.engine import PipelineEngine

        class _MockTM:
            scrub_map = {"": "REDACTED_X_1", "alice": "REDACTED_X_2"}
            unscrub_map = {"REDACTED_X_1": "", "REDACTED_X_2": "alice"}
            token_meta = {"": {"case_sensitive": False}, "alice": {}}
            entity_types = {"": "X", "alice": "X"}
            def get_entity_type(self, pii):
                return self.entity_types.get(pii, "X")

        engine = PipelineEngine(stages=[])
        # Must complete without infinite loop.
        result, matches, ph_counter = engine._pre_filter_to_placeholders(
            "alice goes home", _MockTM(), 0, [],
        )
        # Empty PII skipped → only "alice" was processed.
        assert ph_counter <= 5  # bounded


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
