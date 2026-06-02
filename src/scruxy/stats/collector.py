"""Global and per-session statistics tracking with latency percentiles and disk persistence."""
from __future__ import annotations

import asyncio
import json
import logging
import time as _time
from collections import deque
from pathlib import Path
from typing import Any

from scruxy.plugin.base import PiiEntity


logger = logging.getLogger(__name__)


class StatsCollector:
    """Global and per-session statistics collector.

    Tracks request counts, entity counts (by type, provider, source),
    latency percentiles, and per-session breakdowns. Supports JSON
    persistence to disk.
    """

    def __init__(self, storage_file: str | None = None) -> None:
        import threading as _threading
        self._lock = asyncio.Lock()
        # D4 fix: a separate threading.Lock for the synchronous
        # snapshot methods (`get_windowed_stats`, `get_provider_latency_history`)
        # called from sync FastAPI handlers.  ``asyncio.Lock`` only
        # supports ``async with``; using it as a regular context manager
        # raises ``TypeError: 'Lock' object does not support the context
        # manager protocol`` — which crashed `/ui/api/dashboard` in
        # production.
        #
        # E5 clarification: the snapshot methods rely on CPython's GIL
        # for atomicity of individual `list(deque)` and `dict.get()`
        # calls — async writers do NOT acquire ``_sync_lock``.  The
        # snapshot is therefore intra-call consistent (no torn list)
        # but inter-call snapshots may differ by one writer step.
        # That's acceptable for dashboard metrics.  If you ever invoke
        # these methods from a worker thread (e.g. via
        # ``asyncio.to_thread``), ALSO add ``with self._sync_lock:``
        # around every async writer's deque/dict mutation, otherwise
        # `RuntimeError: deque mutated during iteration` is possible.
        self._sync_lock = _threading.Lock()
        self._start_time: float = _time.time()
        self.total_requests: int = 0
        self.total_entities: int = 0
        self.total_unscrub_events: int = 0
        self.total_tokens_unscrubbed: int = 0
        self.entities_by_type: dict[str, int] = {}
        self.entities_by_provider: dict[str, int] = {}
        self.entities_by_source: dict[str, int] = {}
        self._requests_by_provider: dict[str, int] = {}
        # Granular latency tracking (last 100 samples each)
        self.latency_samples: deque[float] = deque(maxlen=100)  # scrub (backward compat)
        self.unscrub_latency_samples: deque[float] = deque(maxlen=100)
        self.network_latency_samples: deque[float] = deque(maxlen=100)
        self.total_latency_samples: deque[float] = deque(maxlen=100)
        # Timestamped latency samples: deque of (timestamp, value) for windowed stats
        self.ts_scrub_samples: deque[tuple[float, float]] = deque(maxlen=1000)
        self.ts_unscrub_samples: deque[tuple[float, float]] = deque(maxlen=1000)
        self.ts_network_samples: deque[tuple[float, float]] = deque(maxlen=1000)
        self.ts_total_samples: deque[tuple[float, float]] = deque(maxlen=1000)
        # Per-provider latency: provider -> deque of (timestamp, value)
        self.provider_total_samples: dict[str, deque[tuple[float, float]]] = {}
        self.provider_network_samples: dict[str, deque[tuple[float, float]]] = {}
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=500)
        # D5 fix: bound per-session stats with LRU eviction so a flood
        # of unique session IDs cannot cause unbounded memory growth
        # or unbounded persisted-stats JSON.
        from collections import OrderedDict as _OrderedDict
        self.per_session: "_OrderedDict[str, dict[str, Any]]" = _OrderedDict()
        self._per_session_max = 1024
        self.storage_file = storage_file

    @property
    def uptime_seconds(self) -> float:
        """Seconds since this collector was created."""
        return _time.time() - self._start_time

    @property
    def latency_history(self) -> list[float]:
        """Scrub latency samples as a plain list (backward compat)."""
        return list(self.latency_samples)

    @property
    def unscrub_latency_history(self) -> list[float]:
        """Unscrub latency samples as a plain list."""
        return list(self.unscrub_latency_samples)

    @property
    def network_latency_history(self) -> list[float]:
        """Network latency samples as a plain list."""
        return list(self.network_latency_samples)

    @property
    def total_latency_history(self) -> list[float]:
        """Total pipeline latency samples as a plain list."""
        return list(self.total_latency_samples)

    @property
    def requests_by_provider(self) -> dict[str, int]:
        """Number of requests per provider (counted once per request)."""
        return dict(self._requests_by_provider)

    async def record_scrub_event(
        self,
        session_id: str,
        provider: str,
        entities: list[PiiEntity],
        latency_ms: float,
    ) -> None:
        """Record a scrub event with entities and latency."""
        async with self._lock:
            self.total_requests += 1
            self.total_entities += len(entities)
            self.latency_samples.append(latency_ms)
            self.ts_scrub_samples.append((_time.time(), latency_ms))

            for entity in entities:
                self.entities_by_type[entity.entity_type] = (
                    self.entities_by_type.get(entity.entity_type, 0) + 1
                )
                self.entities_by_source[entity.source] = (
                    self.entities_by_source.get(entity.source, 0) + 1
                )

            self.entities_by_provider[provider] = (
                self.entities_by_provider.get(provider, 0) + len(entities)
            )
            self._requests_by_provider[provider] = (
                self._requests_by_provider.get(provider, 0) + 1
            )

            # Append per-entity events for the event log
            now = _time.time()
            for entity in entities:
                self.recent_events.append({
                    "entity_type": entity.entity_type,
                    "confidence": entity.score,
                    "direction": "request",
                    "session_id": session_id,
                    "provider": provider,
                    "timestamp": now,
                })

            # Update per-session stats (D5: bounded LRU; promote on access,
            # evict the LRU entry when over cap).
            if session_id not in self.per_session:
                self.per_session[session_id] = {
                    "requests": 0,
                    "entities": 0,
                    "unscrub_events": 0,
                    "tokens_unscrubbed": 0,
                    "by_type": {},
                    "provider": provider,
                }
                while len(self.per_session) > self._per_session_max:
                    self.per_session.popitem(last=False)
            else:
                self.per_session.move_to_end(session_id)
            session = self.per_session[session_id]
            session["requests"] += 1
            session["entities"] += len(entities)
            session["provider"] = provider
            for entity in entities:
                session["by_type"][entity.entity_type] = (
                    session["by_type"].get(entity.entity_type, 0) + 1
                )

    async def record_unscrub_event(
        self, session_id: str, tokens_unscrubbed: int
    ) -> None:
        """Record an unscrub event (response deanonymization)."""
        async with self._lock:
            self.total_unscrub_events += 1
            self.total_tokens_unscrubbed += tokens_unscrubbed

            if session_id not in self.per_session:
                self.per_session[session_id] = {
                    "requests": 0,
                    "entities": 0,
                    "unscrub_events": 0,
                    "tokens_unscrubbed": 0,
                    "by_type": {},
                }
                while len(self.per_session) > self._per_session_max:
                    self.per_session.popitem(last=False)
            else:
                self.per_session.move_to_end(session_id)
            session = self.per_session[session_id]
            session["unscrub_events"] += 1
            session["tokens_unscrubbed"] += tokens_unscrubbed

    async def record_latencies(
        self,
        *,
        scrub_ms: float = 0.0,
        unscrub_ms: float = 0.0,
        network_ms: float = 0.0,
        total_ms: float = 0.0,
        provider: str = "",
    ) -> None:
        """Record granular latency breakdown for a request cycle.

        Note: scrub latency is already recorded by ``record_scrub_event``,
        so ``scrub_ms`` is accepted but not stored again to avoid duplication.
        """
        async with self._lock:
            now = _time.time()
            if unscrub_ms > 0:
                self.unscrub_latency_samples.append(unscrub_ms)
                self.ts_unscrub_samples.append((now, unscrub_ms))
            if network_ms > 0:
                self.network_latency_samples.append(network_ms)
                self.ts_network_samples.append((now, network_ms))
            if total_ms > 0:
                self.total_latency_samples.append(total_ms)
                self.ts_total_samples.append((now, total_ms))
            # Per-provider latency tracking
            if provider:
                if provider not in self.provider_total_samples:
                    self.provider_total_samples[provider] = deque(maxlen=1000)
                if provider not in self.provider_network_samples:
                    self.provider_network_samples[provider] = deque(maxlen=1000)
                if total_ms > 0:
                    self.provider_total_samples[provider].append((now, total_ms))
                if network_ms > 0:
                    self.provider_network_samples[provider].append((now, network_ms))

    async def get_global_stats(self) -> dict[str, Any]:
        """Return global statistics snapshot."""
        async with self._lock:
            return {
                "total_requests": self.total_requests,
                "total_entities": self.total_entities,
                "total_unscrub_events": self.total_unscrub_events,
                "total_tokens_unscrubbed": self.total_tokens_unscrubbed,
                "entities_by_type": dict(self.entities_by_type),
                "entities_by_provider": dict(self.entities_by_provider),
                "entities_by_source": dict(self.entities_by_source),
                "latency_percentiles": self._get_latency_percentiles(),
                "unscrub_latency_percentiles": self._get_percentiles(self.unscrub_latency_samples),
                "network_latency_percentiles": self._get_percentiles(self.network_latency_samples),
                "total_latency_percentiles": self._get_percentiles(self.total_latency_samples),
            }

    async def get_session_stats(self, session_id: str) -> dict[str, Any] | None:
        """Return stats for a specific session, or None if not found."""
        async with self._lock:
            session = self.per_session.get(session_id)
            if session is None:
                return None
            return dict(session)

    def _get_latency_percentiles(self) -> dict[str, float]:
        """Calculate p50, p95, p99 from scrub latency samples.

        Must be called while holding ``self._lock``.
        """
        return self._get_percentiles(self.latency_samples)

    @staticmethod
    def _get_percentiles(samples: deque[float]) -> dict[str, float]:
        """Calculate p50, p95, p99 from a deque of samples."""
        if not samples:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0}
        sorted_samples = sorted(samples)
        n = len(sorted_samples)
        return {
            "p50": sorted_samples[int(n * 0.5)],
            "p95": sorted_samples[min(int(n * 0.95), n - 1)],
            "p99": sorted_samples[min(int(n * 0.99), n - 1)],
        }

    # Keep the public name from the spec as a convenience wrapper.
    def get_latency_percentiles(self) -> dict[str, float]:
        """Public (non-locked) convenience for latency percentiles.

        Callers that already hold the lock (or accept a racy read for
        display purposes) may call this directly.
        """
        return self._get_latency_percentiles()

    @staticmethod
    def _compute_windowed_percentiles(
        samples: deque[tuple[float, float]], cutoff: float
    ) -> dict[str, float]:
        """Compute avg/min/max/p95/p99 from timestamped samples after *cutoff*."""
        vals = [v for ts, v in samples if ts >= cutoff]
        if not vals:
            return {"avg": 0.0, "min": 0.0, "max": 0.0, "p95": 0.0, "p99": 0.0}
        vals.sort()
        n = len(vals)
        return {
            "avg": round(sum(vals) / n, 2),
            "min": round(vals[0], 2),
            "max": round(vals[-1], 2),
            "p95": round(vals[min(int(n * 0.95), n - 1)], 2),
            "p99": round(vals[min(int(n * 0.99), n - 1)], 2),
        }

    def get_windowed_stats(self, window_minutes: int) -> dict[str, Any]:
        """Compute avg/min/max/p95/p99 from timestamped samples within *window_minutes*.

        Returns a dict with keys: scrub, unscrub, network, total.
        Each value is a dict with avg, min, max, p95, p99.
        """
        cutoff = _time.time() - window_minutes * 60
        # D4 fix: use the sync threading.Lock instead of the asyncio.Lock.
        with self._sync_lock:
            scrub = list(self.ts_scrub_samples)
            unscrub = list(self.ts_unscrub_samples)
            network = list(self.ts_network_samples)
            total = list(self.ts_total_samples)
        return {
            "scrub": self._compute_windowed_percentiles(scrub, cutoff),
            "unscrub": self._compute_windowed_percentiles(unscrub, cutoff),
            "network": self._compute_windowed_percentiles(network, cutoff),
            "total": self._compute_windowed_percentiles(total, cutoff),
        }

    def get_provider_latency_history(self, provider: str) -> dict[str, list[float]]:
        """Return total and network latency value lists for a provider."""
        # D4 fix: use the sync threading.Lock instead of the asyncio.Lock.
        with self._sync_lock:
            total_dq = list(self.provider_total_samples.get(provider) or [])
            network_dq = list(self.provider_network_samples.get(provider) or [])
        return {
            "total_history": [v for _, v in total_dq],
            "network_history": [v for _, v in network_dq],
        }

    async def save_to_disk(self) -> None:
        """Persist stats to *storage_file* as JSON.

        Does nothing when *storage_file* is ``None``.
        """
        if self.storage_file is None:
            return

        async with self._lock:
            data = {
                "total_requests": self.total_requests,
                "total_entities": self.total_entities,
                "total_unscrub_events": self.total_unscrub_events,
                "total_tokens_unscrubbed": self.total_tokens_unscrubbed,
                "entities_by_type": dict(self.entities_by_type),
                "entities_by_provider": dict(self.entities_by_provider),
                "requests_by_provider": dict(self._requests_by_provider),
                "entities_by_source": dict(self.entities_by_source),
                "latency_samples": list(self.latency_samples),
                "unscrub_latency_samples": list(self.unscrub_latency_samples),
                "network_latency_samples": list(self.network_latency_samples),
                "total_latency_samples": list(self.total_latency_samples),
                "ts_scrub_samples": list(self.ts_scrub_samples),
                "ts_unscrub_samples": list(self.ts_unscrub_samples),
                "ts_network_samples": list(self.ts_network_samples),
                "ts_total_samples": list(self.ts_total_samples),
                "provider_total_samples": {
                    p: list(dq) for p, dq in self.provider_total_samples.items()
                },
                "provider_network_samples": {
                    p: list(dq) for p, dq in self.provider_network_samples.items()
                },
                "recent_events": list(self.recent_events),
                "per_session": {
                    sid: dict(sdata) for sid, sdata in self.per_session.items()
                },
            }

            path = Path(self.storage_file).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)

            # Write atomically via a temp file to avoid partial reads.
            # R64-3 fix: keep the file I/O INSIDE the lock so concurrent
            # ``save_to_disk()`` calls can't race on the same ``.tmp``
            # path.  Asyncio.Lock allows yielding during the await; the
            # critical section is small (a single write+rename).
            tmp_path = path.with_suffix(".tmp")
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8"),
            )
            await loop.run_in_executor(None, lambda: tmp_path.replace(path))

    async def load_from_disk(self) -> None:
        """Load stats from *storage_file*.

        Does nothing when *storage_file* is ``None`` or the file does not exist.

        E8 fix: stats are non-critical telemetry — a corrupt /
        truncated / manually-edited JSON file must NOT prevent
        Scruxy from starting.  Catch decode errors and read errors,
        log a warning, and continue with an empty stats state.
        """
        if self.storage_file is None:
            return

        path = Path(self.storage_file).expanduser()
        if not path.exists():
            return

        loop = asyncio.get_running_loop()
        try:
            raw = await loop.run_in_executor(
                None, lambda: path.read_text(encoding="utf-8")
            )
            data: dict[str, Any] = json.loads(raw)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            logger.warning(
                "Stats file %s is unreadable or corrupt (%s); starting with empty stats. "
                "The bad file is left in place for inspection.",
                path, exc,
            )
            return
        # F3 fix: a syntactically-valid JSON file containing `null`,
        # `[]`, `42`, or any non-dict value would otherwise crash the
        # subsequent `data.get(...)` calls with AttributeError and
        # block startup.  Reject non-dict roots up front.
        if not isinstance(data, dict):
            logger.warning(
                "Stats file %s does not contain a JSON object (got %s); "
                "starting with empty stats.",
                path, type(data).__name__,
            )
            return

        async with self._lock:
            try:
                self._load_data_unlocked(data)
            except Exception as exc:
                # F3 fix: a JSON object with the right top-level shape
                # but wrong field types (e.g. `"ts_scrub_samples": null`
                # → TypeError inside deque/dict construction) must NOT
                # block startup either.  Roll back to empty state.
                logger.warning(
                    "Stats file %s contained malformed fields (%s); "
                    "starting with empty stats.",
                    path, exc,
                )
                self._reset_to_empty()
                return

    def _reset_to_empty(self) -> None:
        """Reset all in-memory counters/deques to fresh defaults.

        Used by ``load_from_disk`` when a malformed field is detected
        partway through hydration so the collector is left in a
        consistent empty state.  Caller MUST hold ``self._lock``.
        """
        self.total_requests = 0
        self.total_entities = 0
        self.total_unscrub_events = 0
        self.total_tokens_unscrubbed = 0
        self.entities_by_type = {}
        self.entities_by_provider = {}
        self._requests_by_provider = {}
        self.entities_by_source = {}
        self.latency_samples = deque(maxlen=100)
        self.unscrub_latency_samples = deque(maxlen=100)
        self.network_latency_samples = deque(maxlen=100)
        self.total_latency_samples = deque(maxlen=100)
        self.ts_scrub_samples = deque(maxlen=1000)
        self.ts_unscrub_samples = deque(maxlen=1000)
        self.ts_network_samples = deque(maxlen=1000)
        self.ts_total_samples = deque(maxlen=1000)
        self.provider_total_samples = {}
        self.provider_network_samples = {}
        self.recent_events = deque(maxlen=500)
        from collections import OrderedDict as _OrderedDict
        self.per_session = _OrderedDict()

    def _load_data_unlocked(self, data: dict) -> None:
        """Apply a parsed dict snapshot to in-memory state.

        Caller MUST hold ``self._lock``.  Extracted from
        ``load_from_disk`` so a single try/except can roll back on any
        per-field hydration failure (F3 fix).
        """
        # R53-3 fix: `data.get(k, default)` returns the value as-is
        # when the key exists with value `null` (not the default), so
        # an explicit `null` in the JSON file would assign `None` to
        # scalar/dict fields and silently break stats recording later
        # (TypeError on `+=`, AttributeError on `.get`).  Use ``or``
        # to coerce ``None`` to the appropriate empty default.  This
        # is safe because the empty defaults (0, {}, []) are also
        # falsy, so a real empty value is unchanged.
        self.total_requests = data.get("total_requests") or 0
        self.total_entities = data.get("total_entities") or 0
        self.total_unscrub_events = data.get("total_unscrub_events") or 0
        self.total_tokens_unscrubbed = data.get("total_tokens_unscrubbed") or 0
        self.entities_by_type = data.get("entities_by_type") or {}
        self.entities_by_provider = data.get("entities_by_provider") or {}
        self._requests_by_provider = data.get("requests_by_provider") or {}
        self.entities_by_source = data.get("entities_by_source") or {}
        samples = data.get("latency_samples") or []
        self.latency_samples = deque(samples, maxlen=100)
        self.unscrub_latency_samples = deque(
            data.get("unscrub_latency_samples") or [], maxlen=100
        )
        self.network_latency_samples = deque(
            data.get("network_latency_samples") or [], maxlen=100
        )
        self.total_latency_samples = deque(
            data.get("total_latency_samples") or [], maxlen=100
        )
        # Timestamped samples (list of [ts, value] pairs)
        self.ts_scrub_samples = deque(
            (tuple(p) for p in (data.get("ts_scrub_samples") or [])), maxlen=1000
        )
        self.ts_unscrub_samples = deque(
            (tuple(p) for p in (data.get("ts_unscrub_samples") or [])), maxlen=1000
        )
        self.ts_network_samples = deque(
            (tuple(p) for p in (data.get("ts_network_samples") or [])), maxlen=1000
        )
        self.ts_total_samples = deque(
            (tuple(p) for p in (data.get("ts_total_samples") or [])), maxlen=1000
        )
        # Per-provider latency
        self.provider_total_samples = {
            p: deque((tuple(s) for s in samples), maxlen=1000)
            for p, samples in (data.get("provider_total_samples") or {}).items()
        }
        self.provider_network_samples = {
            p: deque((tuple(s) for s in samples), maxlen=1000)
            for p, samples in (data.get("provider_network_samples") or {}).items()
        }
        events = data.get("recent_events") or []
        self.recent_events = deque(events, maxlen=500)
        # D5 residual fix: rebuild per_session as the bounded
        # OrderedDict the rest of the code expects.  Loading the
        # raw dict from JSON would (a) lose the LRU ordering and
        # (b) cause the next eviction to crash with
        # `TypeError: dict.popitem() takes no keyword arguments`.
        from collections import OrderedDict as _OrderedDict
        persisted = data.get("per_session") or {}
        # Keep only the newest _per_session_max entries (file order
        # is insertion order from the prior process; no per-entry
        # timestamp is persisted, so we trim from the front).
        items = list(persisted.items())
        if len(items) > self._per_session_max:
            items = items[-self._per_session_max:]
        self.per_session = _OrderedDict(items)
