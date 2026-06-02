"""Tests for the StatsCollector statistics tracking module."""
from __future__ import annotations

import json
from pathlib import Path

from scruxy.stats.collector import PiiEntity, StatsCollector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entity(
    entity_type: str = "EMAIL",
    start: int = 0,
    end: int = 10,
    score: float = 0.95,
    source: str = "presidio",
) -> PiiEntity:
    return PiiEntity(
        entity_type=entity_type,
        start=start,
        end=end,
        score=score,
        source=source,
    )


# ---------------------------------------------------------------------------
# Empty / default state
# ---------------------------------------------------------------------------

class TestEmptyStats:
    """Verify that a fresh collector returns zeros everywhere."""

    async def test_empty_global_stats(self) -> None:
        collector = StatsCollector()
        stats = await collector.get_global_stats()
        assert stats["total_requests"] == 0
        assert stats["total_entities"] == 0
        assert stats["total_unscrub_events"] == 0
        assert stats["total_tokens_unscrubbed"] == 0
        assert stats["entities_by_type"] == {}
        assert stats["entities_by_provider"] == {}
        assert stats["entities_by_source"] == {}
        assert stats["latency_percentiles"] == {"p50": 0.0, "p95": 0.0, "p99": 0.0}

    async def test_empty_session_stats_returns_none(self) -> None:
        collector = StatsCollector()
        result = await collector.get_session_stats("nonexistent")
        assert result is None


# ---------------------------------------------------------------------------
# record_scrub_event
# ---------------------------------------------------------------------------

class TestRecordScrubEvent:
    """Test that record_scrub_event updates all counters correctly."""

    async def test_single_event_updates_totals(self) -> None:
        collector = StatsCollector()
        entities = [_make_entity("EMAIL"), _make_entity("PHONE_NUMBER", source="regex")]
        await collector.record_scrub_event("s1", "anthropic", entities, 12.5)

        assert collector.total_requests == 1
        assert collector.total_entities == 2

    async def test_entities_by_type(self) -> None:
        collector = StatsCollector()
        entities = [
            _make_entity("EMAIL"),
            _make_entity("EMAIL"),
            _make_entity("PHONE_NUMBER"),
        ]
        await collector.record_scrub_event("s1", "openai", entities, 10.0)

        assert collector.entities_by_type == {"EMAIL": 2, "PHONE_NUMBER": 1}

    async def test_entities_by_provider(self) -> None:
        collector = StatsCollector()
        await collector.record_scrub_event(
            "s1", "anthropic", [_make_entity()], 5.0
        )
        await collector.record_scrub_event(
            "s2", "openai", [_make_entity(), _make_entity()], 8.0
        )

        assert collector.entities_by_provider == {"anthropic": 1, "openai": 2}

    async def test_entities_by_source(self) -> None:
        collector = StatsCollector()
        entities = [
            _make_entity(source="presidio"),
            _make_entity(source="regex"),
            _make_entity(source="presidio"),
        ]
        await collector.record_scrub_event("s1", "anthropic", entities, 7.0)

        assert collector.entities_by_source == {"presidio": 2, "regex": 1}

    async def test_latency_recorded(self) -> None:
        collector = StatsCollector()
        await collector.record_scrub_event("s1", "anthropic", [], 42.0)

        assert list(collector.latency_samples) == [42.0]

    async def test_multiple_events_accumulate(self) -> None:
        collector = StatsCollector()
        await collector.record_scrub_event(
            "s1", "anthropic", [_make_entity()], 10.0
        )
        await collector.record_scrub_event(
            "s1", "anthropic", [_make_entity(), _make_entity()], 20.0
        )

        assert collector.total_requests == 2
        assert collector.total_entities == 3

    async def test_event_with_no_entities(self) -> None:
        collector = StatsCollector()
        await collector.record_scrub_event("s1", "anthropic", [], 5.0)

        assert collector.total_requests == 1
        assert collector.total_entities == 0
        assert collector.entities_by_provider == {"anthropic": 0}


# ---------------------------------------------------------------------------
# record_unscrub_event
# ---------------------------------------------------------------------------

class TestRecordUnscrubEvent:
    """Test that record_unscrub_event updates counters."""

    async def test_single_unscrub(self) -> None:
        collector = StatsCollector()
        await collector.record_unscrub_event("s1", 5)

        assert collector.total_unscrub_events == 1
        assert collector.total_tokens_unscrubbed == 5

    async def test_multiple_unscrubs_accumulate(self) -> None:
        collector = StatsCollector()
        await collector.record_unscrub_event("s1", 3)
        await collector.record_unscrub_event("s1", 7)

        assert collector.total_unscrub_events == 2
        assert collector.total_tokens_unscrubbed == 10

    async def test_unscrub_creates_session_entry(self) -> None:
        collector = StatsCollector()
        await collector.record_unscrub_event("s1", 2)

        session = await collector.get_session_stats("s1")
        assert session is not None
        assert session["unscrub_events"] == 1
        assert session["tokens_unscrubbed"] == 2
        # Scrub counters should be zero-initialised
        assert session["requests"] == 0
        assert session["entities"] == 0

    async def test_unscrub_zero_tokens(self) -> None:
        collector = StatsCollector()
        await collector.record_unscrub_event("s1", 0)

        assert collector.total_unscrub_events == 1
        assert collector.total_tokens_unscrubbed == 0


# ---------------------------------------------------------------------------
# get_global_stats
# ---------------------------------------------------------------------------

class TestGetGlobalStats:
    """Test the global stats snapshot."""

    async def test_snapshot_reflects_recorded_events(self) -> None:
        collector = StatsCollector()
        entities = [_make_entity("EMAIL", source="presidio")]
        await collector.record_scrub_event("s1", "anthropic", entities, 15.0)
        await collector.record_unscrub_event("s1", 1)

        stats = await collector.get_global_stats()

        assert stats["total_requests"] == 1
        assert stats["total_entities"] == 1
        assert stats["total_unscrub_events"] == 1
        assert stats["total_tokens_unscrubbed"] == 1
        assert stats["entities_by_type"] == {"EMAIL": 1}
        assert stats["entities_by_provider"] == {"anthropic": 1}
        assert stats["entities_by_source"] == {"presidio": 1}
        assert stats["latency_percentiles"]["p50"] == 15.0

    async def test_snapshot_is_a_copy(self) -> None:
        """Mutating the returned dict should not affect internal state."""
        collector = StatsCollector()
        await collector.record_scrub_event(
            "s1", "anthropic", [_make_entity()], 10.0
        )
        stats = await collector.get_global_stats()
        stats["entities_by_type"]["EMAIL"] = 999

        # Internal state unaffected
        fresh = await collector.get_global_stats()
        assert fresh["entities_by_type"]["EMAIL"] == 1


# ---------------------------------------------------------------------------
# get_latency_percentiles
# ---------------------------------------------------------------------------

class TestLatencyPercentiles:
    """Test latency percentile calculation with known data."""

    async def test_empty_returns_zeros(self) -> None:
        collector = StatsCollector()
        p = collector.get_latency_percentiles()
        assert p == {"p50": 0.0, "p95": 0.0, "p99": 0.0}

    async def test_single_sample(self) -> None:
        collector = StatsCollector()
        await collector.record_scrub_event("s1", "p", [], 42.0)
        p = collector.get_latency_percentiles()
        assert p["p50"] == 42.0
        assert p["p95"] == 42.0
        assert p["p99"] == 42.0

    async def test_known_distribution(self) -> None:
        """100 evenly spaced samples 1..100 -> predictable percentiles."""
        collector = StatsCollector()
        for i in range(1, 101):
            await collector.record_scrub_event("s1", "p", [], float(i))

        p = collector.get_latency_percentiles()
        assert p["p50"] == 51.0   # index 50 of [1..100]
        assert p["p95"] == 96.0   # index 95
        assert p["p99"] == 100.0  # index 99 (min(99, 99))

    async def test_two_samples(self) -> None:
        collector = StatsCollector()
        await collector.record_scrub_event("s1", "p", [], 10.0)
        await collector.record_scrub_event("s1", "p", [], 20.0)

        p = collector.get_latency_percentiles()
        # n=2: p50 -> index 1 -> 20.0, p95 -> min(1,1) -> 20.0, p99 -> min(1,1) -> 20.0
        assert p["p50"] == 20.0
        assert p["p95"] == 20.0
        assert p["p99"] == 20.0

    async def test_unsorted_samples(self) -> None:
        """Samples recorded out of order are still sorted before percentile calc."""
        collector = StatsCollector()
        for v in [50.0, 10.0, 90.0, 30.0, 70.0]:
            await collector.record_scrub_event("s1", "p", [], v)

        p = collector.get_latency_percentiles()
        # sorted: [10, 30, 50, 70, 90], n=5
        assert p["p50"] == 50.0   # index 2
        assert p["p95"] == 90.0   # index min(4, 4)
        assert p["p99"] == 90.0   # index min(4, 4)


# ---------------------------------------------------------------------------
# Latency deque maxlen
# ---------------------------------------------------------------------------

class TestLatencyDequeMaxlen:
    """Test that latency_samples deque honours maxlen=100."""

    async def test_maxlen_is_100(self) -> None:
        collector = StatsCollector()
        assert collector.latency_samples.maxlen == 100

    async def test_overflow_evicts_oldest(self) -> None:
        collector = StatsCollector()
        for i in range(150):
            await collector.record_scrub_event("s1", "p", [], float(i))

        assert len(collector.latency_samples) == 100
        # Oldest 50 samples (0..49) should have been evicted
        assert list(collector.latency_samples)[0] == 50.0
        assert list(collector.latency_samples)[-1] == 149.0


# ---------------------------------------------------------------------------
# Per-session stats isolation
# ---------------------------------------------------------------------------

class TestPerSessionIsolation:
    """Test that per-session stats are isolated from one another."""

    async def test_separate_sessions(self) -> None:
        collector = StatsCollector()
        await collector.record_scrub_event(
            "session-a", "anthropic", [_make_entity("EMAIL")], 10.0
        )
        await collector.record_scrub_event(
            "session-b", "openai", [_make_entity("PHONE_NUMBER")], 20.0
        )

        sa = await collector.get_session_stats("session-a")
        sb = await collector.get_session_stats("session-b")

        assert sa is not None
        assert sb is not None
        assert sa["requests"] == 1
        assert sa["entities"] == 1
        assert sa["by_type"] == {"EMAIL": 1}

        assert sb["requests"] == 1
        assert sb["entities"] == 1
        assert sb["by_type"] == {"PHONE_NUMBER": 1}

    async def test_session_accumulates(self) -> None:
        collector = StatsCollector()
        await collector.record_scrub_event(
            "s1", "anthropic", [_make_entity("EMAIL")], 5.0
        )
        await collector.record_scrub_event(
            "s1", "anthropic", [_make_entity("EMAIL"), _make_entity("PHONE_NUMBER")], 8.0
        )

        s1 = await collector.get_session_stats("s1")
        assert s1 is not None
        assert s1["requests"] == 2
        assert s1["entities"] == 3
        assert s1["by_type"] == {"EMAIL": 2, "PHONE_NUMBER": 1}

    async def test_mixed_scrub_and_unscrub(self) -> None:
        collector = StatsCollector()
        await collector.record_scrub_event(
            "s1", "anthropic", [_make_entity()], 10.0
        )
        await collector.record_unscrub_event("s1", 3)

        s1 = await collector.get_session_stats("s1")
        assert s1 is not None
        assert s1["requests"] == 1
        assert s1["entities"] == 1
        assert s1["unscrub_events"] == 1
        assert s1["tokens_unscrubbed"] == 3

    async def test_get_session_stats_returns_copy(self) -> None:
        """Mutating the returned dict should not affect internal state."""
        collector = StatsCollector()
        await collector.record_scrub_event("s1", "p", [_make_entity()], 5.0)

        result = await collector.get_session_stats("s1")
        assert result is not None
        result["requests"] = 999

        fresh = await collector.get_session_stats("s1")
        assert fresh is not None
        assert fresh["requests"] == 1


# ---------------------------------------------------------------------------
# save_to_disk / load_from_disk roundtrip
# ---------------------------------------------------------------------------

class TestDiskPersistence:
    """Test save/load roundtrip using tmp_path."""

    async def test_save_creates_file(self, tmp_path: Path) -> None:
        storage = str(tmp_path / "stats.json")
        collector = StatsCollector(storage_file=storage)
        await collector.record_scrub_event(
            "s1", "anthropic", [_make_entity()], 10.0
        )
        await collector.save_to_disk()

        assert Path(storage).exists()
        data = json.loads(Path(storage).read_text(encoding="utf-8"))
        assert data["total_requests"] == 1
        assert data["total_entities"] == 1

    async def test_roundtrip_preserves_all_fields(self, tmp_path: Path) -> None:
        storage = str(tmp_path / "stats.json")
        original = StatsCollector(storage_file=storage)

        entities = [
            _make_entity("EMAIL", source="presidio"),
            _make_entity("PHONE_NUMBER", source="regex"),
        ]
        await original.record_scrub_event("s1", "anthropic", entities, 12.0)
        await original.record_scrub_event("s2", "openai", [_make_entity("IP_ADDRESS")], 8.0)
        await original.record_unscrub_event("s1", 5)
        await original.save_to_disk()

        restored = StatsCollector(storage_file=storage)
        await restored.load_from_disk()

        assert restored.total_requests == original.total_requests
        assert restored.total_entities == original.total_entities
        assert restored.total_unscrub_events == original.total_unscrub_events
        assert restored.total_tokens_unscrubbed == original.total_tokens_unscrubbed
        assert restored.entities_by_type == original.entities_by_type
        assert restored.entities_by_provider == original.entities_by_provider
        assert restored.entities_by_source == original.entities_by_source
        assert list(restored.latency_samples) == list(original.latency_samples)
        assert restored.per_session == original.per_session

    async def test_load_nonexistent_file_is_noop(self, tmp_path: Path) -> None:
        storage = str(tmp_path / "missing.json")
        collector = StatsCollector(storage_file=storage)
        await collector.load_from_disk()  # Should not raise

        assert collector.total_requests == 0

    async def test_save_noop_when_no_storage_file(self) -> None:
        collector = StatsCollector(storage_file=None)
        await collector.record_scrub_event("s1", "p", [_make_entity()], 5.0)
        await collector.save_to_disk()  # Should not raise

    async def test_load_noop_when_no_storage_file(self) -> None:
        collector = StatsCollector(storage_file=None)
        await collector.load_from_disk()  # Should not raise

    async def test_save_creates_parent_directories(self, tmp_path: Path) -> None:
        storage = str(tmp_path / "nested" / "dir" / "stats.json")
        collector = StatsCollector(storage_file=storage)
        await collector.record_scrub_event("s1", "p", [], 1.0)
        await collector.save_to_disk()

        assert Path(storage).exists()

    async def test_latency_deque_maxlen_preserved_after_load(self, tmp_path: Path) -> None:
        """After loading, the deque maxlen must still be 100."""
        storage = str(tmp_path / "stats.json")
        collector = StatsCollector(storage_file=storage)
        for i in range(50):
            await collector.record_scrub_event("s1", "p", [], float(i))
        await collector.save_to_disk()

        restored = StatsCollector(storage_file=storage)
        await restored.load_from_disk()

        assert restored.latency_samples.maxlen == 100
        assert len(restored.latency_samples) == 50

    async def test_save_overwrites_previous(self, tmp_path: Path) -> None:
        """A second save overwrites the first."""
        storage = str(tmp_path / "stats.json")
        collector = StatsCollector(storage_file=storage)

        await collector.record_scrub_event("s1", "p", [_make_entity()], 5.0)
        await collector.save_to_disk()

        await collector.record_scrub_event("s1", "p", [_make_entity()], 10.0)
        await collector.save_to_disk()

        data = json.loads(Path(storage).read_text(encoding="utf-8"))
        assert data["total_requests"] == 2
        assert data["total_entities"] == 2


# ---------------------------------------------------------------------------
# New fields: uptime_seconds, requests_by_provider, latency_history, provider
# ---------------------------------------------------------------------------


class TestUptimeSeconds:

    async def test_uptime_is_positive(self):
        collector = StatsCollector()
        assert collector.uptime_seconds >= 0

    async def test_uptime_increases(self):
        import asyncio
        collector = StatsCollector()
        t1 = collector.uptime_seconds
        await asyncio.sleep(0.05)
        t2 = collector.uptime_seconds
        assert t2 > t1


class TestRequestsByProvider:

    async def test_increments_per_request_not_per_entity(self):
        collector = StatsCollector()
        entities = [_make_entity(), _make_entity("PHONE_NUMBER", 20, 30)]
        await collector.record_scrub_event("s1", "anthropic", entities, 5.0)
        assert collector.requests_by_provider["anthropic"] == 1

    async def test_multiple_providers(self):
        collector = StatsCollector()
        await collector.record_scrub_event("s1", "anthropic", [_make_entity()], 5.0)
        await collector.record_scrub_event("s2", "openai", [_make_entity()], 3.0)
        assert collector.requests_by_provider["anthropic"] == 1
        assert collector.requests_by_provider["openai"] == 1

    async def test_persists_to_disk(self, tmp_path):
        storage = str(tmp_path / "stats.json")
        collector = StatsCollector(storage_file=storage)
        await collector.record_scrub_event("s1", "anthropic", [_make_entity()], 5.0)
        await collector.save_to_disk()

        loaded = StatsCollector(storage_file=storage)
        await loaded.load_from_disk()
        assert loaded.requests_by_provider["anthropic"] == 1


class TestLatencyHistory:

    async def test_returns_list(self):
        collector = StatsCollector()
        assert isinstance(collector.latency_history, list)

    async def test_empty_when_no_samples(self):
        collector = StatsCollector()
        assert collector.latency_history == []

    async def test_contains_samples(self):
        collector = StatsCollector()
        await collector.record_scrub_event("s1", "p", [_make_entity()], 5.0)
        await collector.record_scrub_event("s2", "p", [_make_entity()], 10.0)
        assert collector.latency_history == [5.0, 10.0]


class TestPerSessionProvider:

    async def test_provider_stored_in_per_session(self):
        collector = StatsCollector()
        await collector.record_scrub_event("s1", "anthropic", [_make_entity()], 5.0)
        assert collector.per_session["s1"]["provider"] == "anthropic"

    async def test_provider_updated_on_subsequent_events(self):
        collector = StatsCollector()
        await collector.record_unscrub_event("s1", 1)
        await collector.record_scrub_event("s1", "anthropic", [], 5.0)
        assert collector.per_session["s1"]["provider"] == "anthropic"


# ---------------------------------------------------------------------------
# EventBus
# ---------------------------------------------------------------------------

import asyncio
from scruxy.stats import EventBus


class TestEventBus:

    async def test_publish_delivers_to_subscriber(self):
        bus = EventBus()
        queue: asyncio.Queue = asyncio.Queue(maxsize=16)
        bus.subscribers.append(queue)
        await bus.publish({"type": "test", "value": 42})
        event = queue.get_nowait()
        assert event["type"] == "test"
        assert event["value"] == 42

    async def test_publish_no_subscribers_does_not_raise(self):
        bus = EventBus()
        await bus.publish({"type": "test"})

    async def test_publish_multiple_subscribers(self):
        bus = EventBus()
        q1: asyncio.Queue = asyncio.Queue(maxsize=16)
        q2: asyncio.Queue = asyncio.Queue(maxsize=16)
        bus.subscribers.extend([q1, q2])
        await bus.publish({"type": "test"})
        assert not q1.empty()
        assert not q2.empty()

    async def test_publish_drops_on_full_queue(self):
        bus = EventBus()
        queue: asyncio.Queue = asyncio.Queue(maxsize=1)
        bus.subscribers.append(queue)
        await bus.publish({"type": "first"})
        await bus.publish({"type": "second"})  # should be dropped
        assert queue.qsize() == 1
        assert queue.get_nowait()["type"] == "first"

    async def test_subscriber_removal_safe_during_publish(self):
        bus = EventBus()
        q1: asyncio.Queue = asyncio.Queue(maxsize=16)
        bus.subscribers.append(q1)
        await bus.publish({"type": "test"})
        bus.subscribers.remove(q1)
        await bus.publish({"type": "test2"})
        assert q1.qsize() == 1
