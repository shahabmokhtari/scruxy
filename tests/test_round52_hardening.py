"""Regression tests for Round 52 hardening fixes (F1-F6)."""
from __future__ import annotations

import asyncio
import json
import threading
from collections import OrderedDict, deque
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# F1 — Query KEYS scrubbed (not just values)
# ---------------------------------------------------------------------------

class TestF1_QueryKeysScrubbed:
    @pytest.mark.asyncio
    async def test_pii_in_key_is_scrubbed(self):
        """A request like `?alice@example.com=1` must NOT forward the
        raw email upstream — the KEY must be scrubbed too."""
        from scruxy.proxy.routes import _scrub_url_query
        from scruxy.tokenmap.token_map import TokenMap

        tm = TokenMap()

        class _FakeResult:
            def __init__(self, text, entities=None):
                self.scrubbed_text = text
                self.entities = entities or []

        class _FakeEntity:
            def __init__(self, matched):
                self._matched_text = matched

        class _FakePipeline:
            async def scrub_text(self, text, token_map, context=None, request_id=""):
                if "@" in text:
                    tok = token_map.get_or_create_token(text, "EMAIL_ADDRESS")
                    return _FakeResult(tok, entities=[_FakeEntity(text)])
                return _FakeResult(text)

        url = "https://api.example.com/v1/messages?alice@example.com=1"
        out, detected = await _scrub_url_query(url, _FakePipeline(), tm, "r1")
        # The raw email MUST NOT be in the URL (URL-encoded or not).
        assert "alice@example.com" not in out
        assert "alice%40example.com" not in out, out
        # The token must replace it.
        assert "REDACTED_EMAIL_ADDRESS" in out
        # And the detected PII set must include the email so the
        # caller can tag/absorb it.
        assert "alice@example.com" in detected


# ---------------------------------------------------------------------------
# F2 — Query-detected PII tagged + absorbed for response unscrub
# ---------------------------------------------------------------------------

class TestF2_QueryPiiTaggedAndAbsorbed:
    @pytest.mark.asyncio
    async def test_query_pii_tagged_to_session(self, tmp_path):
        """Drive `_scrub_url_query` end-to-end: detected PII must be
        returned so the caller can tag it.  Then verify the response
        view can deanonymize the resulting token."""
        from scruxy.proxy.routes import _scrub_url_query
        from scruxy.tokenmap.service import ConcurrentSessionStore
        from scruxy.scrubber.response_unscrubber import deanonymize_text

        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            persistent=False,
        )
        await store.start()
        try:
            tm = await store.get_or_create_session("s1")

            class _FakeResult:
                def __init__(self, text, entities=None):
                    self.scrubbed_text = text
                    self.entities = entities or []

            class _FakeEntity:
                def __init__(self, matched):
                    self._matched_text = matched

            class _FakePipeline:
                async def scrub_text(self, text, token_map, context=None, request_id=""):
                    if "@" in text:
                        tok = token_map.get_or_create_token(text, "EMAIL_ADDRESS")
                        return _FakeResult(tok, entities=[_FakeEntity(text)])
                    return _FakeResult(text)

            url = "https://api.example.com/v1/messages?email=alice@example.com"
            view = store.get_session_token_map("s1")

            scrubbed_url, detected = await _scrub_url_query(
                url, _FakePipeline(), tm, "r1",
            )
            # Caller responsibility (production proxy code does this):
            assert detected == {"alice@example.com"}
            store.tag_session_pii("s1", detected)
            view.absorb_pii(detected)

            # Now the response unscrubber should reverse the token.
            out = deanonymize_text(
                "echo REDACTED_EMAIL_ADDRESS_1", view,
            )
            assert "alice@example.com" in out, (
                "Query-derived PII must be tagged + absorbed so response "
                "deanonymization works (F2 fix); got " + repr(out)
            )
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_query_pii_collected_from_pipeline_result_fields(self, tmp_path):
        """F2 r52 residual: production `PipelineResult` exposes PII
        via `detected_pii` (list[(pii, token)]) and
        `pre_filter_matches` (list with `.pii_text`), NOT
        `entity._matched_text`.  The helper MUST collect from those
        fields too — otherwise the round-52 fake-entity tests pass
        but production traffic leaks query tokens."""
        from scruxy.proxy.routes import _scrub_url_query
        from scruxy.tokenmap.token_map import TokenMap

        tm = TokenMap()

        class _ProdResult:
            """Mimics the actual PipelineEngine result shape."""
            def __init__(self, text, detected=None, pre_matches=None):
                self.scrubbed_text = text
                self.entities = []  # production may have these but
                                    # without _matched_text
                self.detected_pii = detected or []
                self.pre_filter_matches = pre_matches or []

        class _PreMatch:
            def __init__(self, pii):
                self.pii_text = pii

        class _ProdPipeline:
            async def scrub_text(self, text, token_map, context=None, request_id=""):
                if "@" in text:
                    tok = token_map.get_or_create_token(text, "EMAIL_ADDRESS")
                    # Production-style: detected_pii populated, no
                    # _matched_text on entities.
                    return _ProdResult(tok, detected=[(text, tok)])
                return _ProdResult(text)

        url = "https://api.example.com/x?email=alice@example.com"
        scrubbed, detected = await _scrub_url_query(
            url, _ProdPipeline(), tm, "r1",
        )
        assert "alice@example.com" not in scrubbed
        assert detected == {"alice@example.com"}, (
            f"_scrub_url_query must collect PII from result.detected_pii "
            f"(F2 r52 residual); got {detected!r}"
        )

        # Same with pre_filter_matches.
        class _PreMatchPipeline:
            async def scrub_text(self, text, token_map, context=None, request_id=""):
                tok = token_map.get_or_create_token(text, "EMAIL_ADDRESS") if "@" in text else text
                pre = [_PreMatch(text)] if "@" in text else []
                return _ProdResult(tok, pre_matches=pre)

        scrubbed2, detected2 = await _scrub_url_query(
            "https://x/?e=bob@example.com", _PreMatchPipeline(), tm, "r2",
        )
        assert "bob@example.com" in detected2


# ---------------------------------------------------------------------------
# F3 — load_from_disk handles non-dict / null-field JSON
# ---------------------------------------------------------------------------

class TestF3_LoadFromDiskRobust:
    @pytest.mark.asyncio
    async def test_null_root_does_not_crash(self, tmp_path):
        from scruxy.stats.collector import StatsCollector
        path = tmp_path / "stats.json"
        path.write_text("null")
        sc = StatsCollector(storage_file=str(path))
        await sc.load_from_disk()
        assert sc.total_requests == 0

    @pytest.mark.asyncio
    async def test_array_root_does_not_crash(self, tmp_path):
        from scruxy.stats.collector import StatsCollector
        path = tmp_path / "stats.json"
        path.write_text("[]")
        sc = StatsCollector(storage_file=str(path))
        await sc.load_from_disk()
        assert sc.total_requests == 0

    @pytest.mark.asyncio
    async def test_scalar_root_does_not_crash(self, tmp_path):
        from scruxy.stats.collector import StatsCollector
        for raw in ["42", '"hello"', "true"]:
            path = tmp_path / "stats.json"
            path.write_text(raw)
            sc = StatsCollector(storage_file=str(path))
            await sc.load_from_disk()
            assert sc.total_requests == 0

    @pytest.mark.asyncio
    async def test_null_field_value_does_not_crash(self, tmp_path):
        """A dict with null fields must NOT crash startup.

        R53-3 supersedes the original F3 rollback semantic: null
        scalars/lists/dicts are now coerced to their empty defaults,
        so valid sibling fields (like total_requests=5) are preserved
        instead of being wiped by a wholesale rollback."""
        from scruxy.stats.collector import StatsCollector
        path = tmp_path / "stats.json"
        path.write_text(json.dumps({
            "total_requests": 5,
            "ts_scrub_samples": None,
        }))
        sc = StatsCollector(storage_file=str(path))
        await sc.load_from_disk()
        # R53-3: total_requests=5 is preserved; null sample list → empty deque.
        assert sc.total_requests == 5
        assert isinstance(sc.ts_scrub_samples, deque)
        assert len(sc.ts_scrub_samples) == 0

    @pytest.mark.asyncio
    async def test_provider_samples_wrong_type_does_not_crash(self, tmp_path):
        """A wrong-typed (non-dict) provider_total_samples still
        triggers the F3 rollback because the construction code
        unpacks `.items()`."""
        from scruxy.stats.collector import StatsCollector
        path = tmp_path / "stats.json"
        path.write_text(json.dumps({
            "total_requests": 7,
            "provider_total_samples": "not-a-dict",
        }))
        sc = StatsCollector(storage_file=str(path))
        await sc.load_from_disk()
        assert sc.total_requests == 0


# ---------------------------------------------------------------------------
# F4 — All forward_proxy logger calls use redacted URL
# ---------------------------------------------------------------------------

class TestF4_AllLoggerCallsRedacted:
    def test_no_raw_url_logger_calls_in_forward_proxy(self):
        """Stronger version of E6: scan forward_proxy.py for any
        `logger.X(...)` call (across multiple lines) that passes
        bare `url` or `target` without `_redact_url_for_log`."""
        path = Path(__file__).parent.parent / "src" / "scruxy" / "proxy" / "forward_proxy.py"
        src = path.read_text(encoding="utf-8")
        import re
        # Find every full logger.X(...) call (possibly multi-line),
        # then check whether the call body contains a bare `url` /
        # `target` argument NOT wrapped in `_redact_url_for_log`.
        violations = []
        # Simple paren-balance walker.
        i = 0
        n = len(src)
        pat = re.compile(r"\blogger\.\w+\(")
        for m in pat.finditer(src):
            start = m.end()
            depth = 1
            j = start
            while j < n and depth > 0:
                ch = src[j]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                j += 1
            body = src[start:j - 1]
            # Skip if the call already uses the redaction helper anywhere.
            if "_redact_url_for_log" in body:
                continue
            # Otherwise look for a bare `url` or `target` argument.
            # Simple test: any `url` or `target` standing as its own
            # token (preceded by `,` or whitespace, followed by `,`,
            # `)`, or end of body).
            if re.search(r"(?:^|[,\s\(])(url|target)(?:[,\s\)]|$)", body):
                line_no = src[:m.start()].count("\n") + 1
                violations.append((line_no, body[:120].replace("\n", " ")))
        assert not violations, (
            "F4 r52 residual: forward_proxy.py logger calls must wrap "
            "url/target in _redact_url_for_log() — including multi-line "
            f"calls; violations:\n" +
            "\n".join(f"  L{n}: logger.X({b}...)" for n, b in violations)
        )

    @pytest.mark.asyncio
    async def test_matched_provider_log_uses_redacted_url(self, caplog):
        """R53-4 / Round 52 F4 strengthened: drive `_scrub_and_forward`
        with a VALID JSON body so the function runs past the 415
        short-circuit and exercises every matched-provider log site
        (matched-provider info, resolved-upstream info, plus any
        warnings on the upstream-forward path).  Assert no captured
        log record contains the raw query-string PII."""
        import logging
        from unittest.mock import AsyncMock
        from scruxy.proxy.forward_proxy import ForwardProxyServer

        provider = MagicMock()
        provider.name = "anthropic"
        provider.upstream_url = "https://api.example.com"
        provider.extract_session_id = MagicMock(return_value="s1")

        registry = MagicMock()
        registry.match = MagicMock(return_value=provider)
        registry.match_disabled = MagicMock(return_value=None)

        token_map = MagicMock()
        session_store = MagicMock()
        session_store.get_or_create_session = AsyncMock(return_value=token_map)
        session_store.tag_session_pii = MagicMock()
        session_store.mark_dirty = MagicMock(return_value=None)

        # Pipeline must return a result-shaped object for `_scrub_url_query`.
        pipeline = MagicMock()
        scrub_result = MagicMock()
        scrub_result.scrubbed_text = "REDACTED"
        scrub_result.detected_pii = set()
        scrub_result.pre_filter_matches = set()
        scrub_result.entities = []
        pipeline.scrub_text = AsyncMock(return_value=scrub_result)

        # request_scrubber.scrub_request is awaited and unpacked into 4-tuple.
        request_scrubber = MagicMock()
        request_scrubber.scrub_request = AsyncMock(
            return_value=({"model": "x"}, [], None, set())
        )

        server = ForwardProxyServer(
            host="127.0.0.1", port=0, ca=MagicMock(),
            registry=registry, pipeline=pipeline,
            session_store=session_store,
            request_scrubber=request_scrubber,
            response_unscrubber=MagicMock(),
        )

        with caplog.at_level(logging.DEBUG, logger="scruxy.proxy.forward_proxy"):
            try:
                # body is VALID JSON now so we skip past the 415
                # fail-closed and reach the deeper log sites that the
                # original (round-52) test never exercised.
                await server._scrub_and_forward(
                    method="POST",
                    url="https://api.example.com/v1/messages?api_key=secret-token-xyz&email=alice@example.com",
                    headers={"content-type": "application/json"},
                    body=b'{"model":"claude-3-opus"}',
                )
            except Exception:
                # Upstream call to api.example.com will fail in this
                # unit-test environment; we only care about log content.
                pass

        # Sanity check: at minimum the matched-provider info log must
        # have been emitted, otherwise the assertion below is vacuous.
        assert any(
            "matched provider" in r.getMessage().lower()
            for r in caplog.records
        ), "test_matched_provider_log_uses_redacted_url did not exercise the matched-provider log path"

        # No log record may contain the raw secret/email.
        for record in caplog.records:
            msg = record.getMessage()
            assert "secret-token-xyz" not in msg, (
                f"Raw secret leaked to log: {msg!r}"
            )
            assert "alice@example.com" not in msg, (
                f"Raw email leaked to log: {msg!r}"
            )

    @pytest.mark.asyncio
    async def test_query_scrub_failure_does_not_log_raw_key(self, caplog):
        """F4 r52 residual: when `_scrub_url_query` catches a per-pair
        scrub exception, the logged message MUST NOT include the raw
        key — the key may itself be PII (the entire reason F1 was
        added).  Log a length+position marker instead."""
        import logging
        from scruxy.proxy.routes import _scrub_url_query

        class _BoomPipeline:
            async def scrub_text(self, *a, **kw):
                raise RuntimeError("boom")

        url = "https://example.com/x?alice@example.com=1&token=secret-xyz"
        with caplog.at_level(logging.WARNING, logger="scruxy.proxy.routes"):
            scrubbed, detected = await _scrub_url_query(
                url, _BoomPipeline(), MagicMock(), "r1",
            )

        # The output must NOT contain the raw email or token.
        assert "alice@example.com" not in scrubbed
        assert "secret-xyz" not in scrubbed
        # And critically, no log record may contain them either.
        for record in caplog.records:
            msg = record.getMessage()
            assert "alice@example.com" not in msg, (
                f"F4 r52 residual: raw key leaked to log on scrub failure: {msg!r}"
            )
            assert "secret-xyz" not in msg, (
                f"F4 r52 residual: raw value leaked to log on scrub failure: {msg!r}"
            )


# ---------------------------------------------------------------------------
# F5 — sessions property iterates under lock
# ---------------------------------------------------------------------------

class TestF5_SessionsIteratesUnderLock:
    @pytest.mark.asyncio
    async def test_sessions_property_does_not_raise_during_concurrent_mutation(self, tmp_path):
        """The `sessions` property must NOT raise `RuntimeError:
        OrderedDict mutated during iteration` when `tag_session_pii`
        runs concurrently from a worker thread."""
        from scruxy.tokenmap.service import ConcurrentSessionStore

        store = ConcurrentSessionStore(
            storage_dir=str(tmp_path / "sessions"),
            persistent=False,
        )
        await store.start()
        try:
            for i in range(50):
                await store.get_or_create_session(f"sess-{i}")

            errors: list[BaseException] = []
            stop = threading.Event()

            def _mutator():
                try:
                    i = 0
                    while not stop.is_set():
                        store.tag_session_pii(f"newsess-{i}", {f"pii-{i}"})
                        i += 1
                except BaseException as exc:
                    errors.append(exc)

            def _iterator():
                try:
                    while not stop.is_set():
                        _ = store.sessions
                except BaseException as exc:
                    errors.append(exc)

            t1 = threading.Thread(target=_mutator)
            t2 = threading.Thread(target=_iterator)
            t1.start(); t2.start()
            await asyncio.sleep(0.2)
            stop.set()
            t1.join(timeout=5); t2.join(timeout=5)

            assert errors == [], (
                f"`sessions` property raced with `tag_session_pii`: {errors!r}"
            )
        finally:
            await store.stop()


# ---------------------------------------------------------------------------
# F6 — _owned_fallback_index_locks removed (no leak)
# ---------------------------------------------------------------------------

class TestF6_FallbackLockNoLeak:
    def test_owned_fallback_dict_removed(self):
        """The strong-ref `_owned_fallback_index_locks` was leaking
        across event-loop lifetimes; F6 removed it.  Verify the
        attribute no longer exists at class level."""
        from scruxy.recording.recorder import SessionRecorder
        assert not hasattr(SessionRecorder, "_owned_fallback_index_locks"), (
            "F6 fix: `_owned_fallback_index_locks` strong-ref dict must "
            "be removed (it leaked one entry per event-loop lifetime)"
        )

    @pytest.mark.asyncio
    async def test_overflow_recorders_still_share_lock_via_owned_pin(
        self, tmp_path, monkeypatch,
    ):
        """E7's behavioral promise must survive F6: as long as both
        recorders are still alive, they share the same fallback lock
        via their `_owned_index_lock` strong ref."""
        from scruxy.recording.recorder import SessionRecorder

        monkeypatch.setattr(SessionRecorder, "_MAX_SHARED_LOCKS", 0)

        rec1 = SessionRecorder(str(tmp_path / "a"))
        rec2 = SessionRecorder(str(tmp_path / "b"))
        # Both recorders pin the same fallback lock via _owned_index_lock,
        # which keeps the WeakValueDictionary entry alive.
        assert rec1._index_lock is rec2._index_lock, (
            "Over-cap recorders on the same loop must still share a lock "
            "(rec1 and rec2 each pin via _owned_index_lock)"
        )
