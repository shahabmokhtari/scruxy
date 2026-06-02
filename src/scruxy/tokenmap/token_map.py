"""Single-session TokenMap: bidirectional scrub/unscrub dicts with counters and stats."""
from __future__ import annotations

import logging
import threading
import time as _time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scruxy.tokenmap.db import TokenDB
    from scruxy.tokenmap.replacer import ReplacementStrategy

logger = logging.getLogger(__name__)


class TokenMap:
    """Bidirectional PII <-> token mapping for a single session.

    By default tokens use the format ``REDACTED_{TYPE}_{N}``.  Custom
    replacement strategies can be supplied per entity type to produce
    alternative tokens (UUIDs, fake data from scripts, etc.).  The
    mapping is deterministic: the same PII text always resolves to the
    same token within a session.

    If an optional *db* handle is provided, new tokens are queued for
    async write to SQLite (the queue is drained by the service layer).

    Thread-safety: all mutations are protected by a threading.Lock so the
    map can be shared between the main asyncio loop and the mitmproxy thread.
    """

    def __init__(
        self,
        replacements: dict[str, ReplacementStrategy] | None = None,
        db: TokenDB | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._scrub: dict[str, str] = {}
        self._unscrub: dict[str, str] = {}
        self._entity_types: dict[str, str] = {}  # PII → entity_type
        self._token_meta: dict[str, dict] = {}  # PII → {word_boundary, case_sensitive, ...}
        self._counters: dict[str, int] = {}
        self._entry_timestamps: dict[str, float] = {}  # PII → unix timestamp
        self._stats_total: int = 0
        self._stats_by_type: dict[str, int] = {}
        self._stats_by_source: dict[str, int] = {}
        self._created_at: datetime = datetime.now(timezone.utc)
        self._updated_at: datetime = self._created_at
        self._replacements: dict[str, ReplacementStrategy] = replacements or {}
        # Pending DB writes — drained asynchronously by the service layer
        # (pii, token, type, source, count, request_id, word_boundary, case_sensitive, exclude_from_prefilter)
        self._pending_writes: list[tuple[str, str, str, str, int, str, bool, bool, bool]] = []
        self._pending_touches: set[str] = set()
        self._pending_deletes: set[str] = set()
        self._pending_clear: bool = False
        self._db: TokenDB | None = db
        # Monotonic version bumped on every new token — lets consumers
        # (e.g. SSE unscrubber trie) detect when the map has changed.
        self._token_version: int = 0
        # M7 fix: track which canonical PII strings have already
        # emitted a metadata-conflict warning so the log buffer
        # isn't flooded when the same conflicting registration
        # happens on every request.
        self._meta_conflict_warned: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_or_create_token(
        self,
        pii: str,
        entity_type: str,
        source: str = "",
        *,
        use_word_boundary: bool = False,
        case_sensitive: bool = True,
        exclude_from_prefilter: bool = False,
        request_id: str = "",
    ) -> str | None:
        """Return existing token for *pii*, create one via the configured strategy, or ``None``.

        Thread-safe: acquires ``self._lock`` for the duration of the lookup/create.
        """
        # Reject placeholder markers — return the placeholder as-is (identity mapping)
        if "§§§SCRX" in pii:
            return pii

        # Reject empty PII — not meaningful for scrubbing
        if not pii:
            return None

        with self._lock:
            existing = self._scrub.get(pii)
            if existing is not None:
                # R71-12 fix: warn if a re-registration uses different
                # metadata than the first registration.  We keep the
                # first metadata (first-write-wins) because changing
                # it mid-flight would invalidate already-emitted
                # tokens, but log so the operator notices the conflict.
                prev_meta = self._token_meta.get(pii)
                if prev_meta is not None:
                    new_wb = bool(use_word_boundary)
                    new_cs = bool(case_sensitive)
                    new_efp = bool(exclude_from_prefilter)
                    if (
                        prev_meta.get("word_boundary") != new_wb
                        or prev_meta.get("case_sensitive") != new_cs
                        or prev_meta.get("exclude_from_prefilter") != new_efp
                    ):
                        # M7 fix: dedup — emit at most one warning per
                        # canonical PII for the lifetime of this map.
                        if pii not in self._meta_conflict_warned:
                            self._meta_conflict_warned.add(pii)
                            logger.warning(
                                "Token re-registered with different metadata "
                                "(first-write wins).  pii_len=%d type=%s "
                                "prev=%s new={word_boundary=%s, "
                                "case_sensitive=%s, exclude_from_prefilter=%s}",
                                len(pii), entity_type, prev_meta,
                                new_wb, new_cs, new_efp,
                            )
                if self._db is not None:
                    self._pending_touches.add(pii)
                self._record_stat(entity_type, source)
                return existing

            # Whitelisted terms use an identity mapping (token == original text)
            if entity_type == "WHITELIST":
                self._scrub[pii] = pii
                self._unscrub[pii] = pii
                self._entity_types[pii] = entity_type
                self._entry_timestamps[pii] = _time.time()
                self._pending_deletes.discard(pii)
                self._pending_touches.discard(pii)
                self._updated_at = datetime.now(timezone.utc)
                return pii

            # Provisional counter — only committed if a token is actually created.
            count = self._counters.get(entity_type, 0) + 1

            strategy = self._replacements.get(entity_type)
            if strategy is not None:
                token = strategy.generate(entity_type, pii, count)
            else:
                token = f"REDACTED_{entity_type}_{count}"

            if not token:
                # R58-3 fix: reject both ``None`` AND ``""``.  An
                # empty-string token from a custom ReplacementStrategy
                # would (a) infinite-loop ``_build_occupied_ranges``
                # via ``str.find("", pos)``, and (b) corrupt every
                # response in ``deanonymize_text`` because the regex
                # ``"|..."`` matches every character position.  The
                # original guard only checked ``is None``.
                return None

            # Collision guard: if a custom strategy produced a token already
            # mapped to different PII, fall back to the default format.
            # Check the fallback for secondary collisions too.
            existing_pii = self._unscrub.get(token)
            if existing_pii is not None and existing_pii != pii:
                logger.error(
                    "Token collision: %r already maps to different PII, "
                    "falling back to default format for entity type %s",
                    token,
                    entity_type,
                )
                token = f"REDACTED_{entity_type}_{count}"
                # If the fallback also collides, bump the counter until clear
                while self._unscrub.get(token) is not None and self._unscrub[token] != pii:
                    count += 1
                    token = f"REDACTED_{entity_type}_{count}"

            self._counters[entity_type] = count
            self._pending_deletes.discard(pii)
            self._pending_touches.discard(pii)
            self._scrub[pii] = token
            self._unscrub[token] = pii
            # B3: When a replacement strategy emits a multi-part token
            # (e.g. ``REDACTED_PERSON_1A REDACTED_PERSON_1B`` for the
            # PII ``Alice Smith``), the LLM upstream may refer to a
            # single sub-token in its reply (``Hi REDACTED_PERSON_1A``).
            # Without per-sub-token reverse mappings the deanonymizer
            # would leak the raw token to the user.  Map each
            # whitespace-separated sub-token back to the corresponding
            # whitespace-separated original word, so partial references
            # restore correctly.  We only do this when the part counts
            # match — otherwise we fall back to the joint mapping
            # (longest-first deanonymization still handles the full
            # phrase).
            sub_tokens = token.split()
            sub_piis = pii.split()
            if (
                len(sub_tokens) > 1
                and len(sub_tokens) == len(sub_piis)
                and all(st != sp for st, sp in zip(sub_tokens, sub_piis))
            ):
                for sub_t, sub_p in zip(sub_tokens, sub_piis):
                    # Don't overwrite a pre-existing reverse mapping
                    # that points to different PII (collision guard).
                    existing = self._unscrub.get(sub_t)
                    if existing is None or existing == sub_p:
                        self._unscrub[sub_t] = sub_p
            self._entity_types[pii] = entity_type
            self._token_meta[pii] = {
                "word_boundary": use_word_boundary,
                "case_sensitive": case_sensitive,
                "exclude_from_prefilter": exclude_from_prefilter,
                "first_seen_request_id": request_id,
            }
            self._entry_timestamps[pii] = _time.time()
            self._updated_at = datetime.now(timezone.utc)
            self._token_version += 1

            # Queue DB write (drained asynchronously by the service layer)
            self._pending_writes.append((
                pii, token, entity_type, source, count, request_id,
                use_word_boundary, case_sensitive, exclude_from_prefilter,
            ))

            self._record_stat(entity_type, source)
            return token

    def get_pii(self, token: str) -> str | None:
        """Reverse-lookup: return the original PII for *token*, or ``None``."""
        with self._lock:
            return self._unscrub.get(token)

    def get_token(self, pii: str) -> str | None:
        """Forward-lookup: return the token for *pii*, or ``None``."""
        with self._lock:
            return self._scrub.get(pii)

    @property
    def scrub_map(self) -> dict[str, str]:
        """Read-only snapshot of the PII -> token mapping."""
        with self._lock:
            return dict(self._scrub)

    @property
    def unscrub_map(self) -> dict[str, str]:
        """Read-only snapshot of the token -> PII mapping."""
        with self._lock:
            return dict(self._unscrub)

    @property
    def counters(self) -> dict[str, int]:
        """Read-only snapshot of per-type counters."""
        with self._lock:
            return dict(self._counters)

    @property
    def size(self) -> int:
        """Number of unique PII entries in the map."""
        with self._lock:
            return len(self._scrub)

    @property
    def token_meta(self) -> dict[str, dict]:
        """Read-only snapshot of the PII → metadata mapping."""
        with self._lock:
            return dict(self._token_meta)

    @property
    def entity_types(self) -> dict[str, str]:
        """Read-only snapshot of the PII → entity type mapping."""
        with self._lock:
            return dict(self._entity_types)

    def get_entity_type(self, pii: str) -> str:
        """Return the entity type for *pii*, or 'UNKNOWN'."""
        with self._lock:
            return self._entity_types.get(pii, "UNKNOWN")

    def clear(self) -> None:
        """Remove all entries, reset counters, stats, and pending writes."""
        with self._lock:
            self._scrub.clear()
            self._unscrub.clear()
            self._entity_types.clear()
            self._token_meta.clear()
            self._counters.clear()
            self._entry_timestamps.clear()
            self._pending_writes = []
            self._pending_touches.clear()
            self._pending_deletes.clear()
            self._pending_clear = self._db is not None
            self._stats_total = 0
            self._stats_by_type.clear()
            self._stats_by_source.clear()
            self._updated_at = datetime.now(timezone.utc)
            self._token_version += 1

    def _purge_subtoken_aliases(self, pii: str, token: str) -> None:
        """Remove per-sub-token reverse mappings created by
        :meth:`get_or_create_token` for multi-word PII.

        Matches the alias-creation logic exactly so a remove/invalidate
        operation cannot leave stale aliases pointing at deleted PII
        AND cannot delete unrelated mappings (e.g. a whitelist identity
        entry for a common word like "Dr").  D2 fix: replicate the
        ``all(st != sp)`` creation-path guard, otherwise a custom
        replacement strategy that emits a sub-token equal to its PII
        word could trick this helper into popping a whitelist mapping.

        Caller MUST hold ``self._lock``.
        """
        if not token or not pii:
            return
        sub_tokens = token.split()
        sub_piis = pii.split()
        if len(sub_tokens) <= 1 or len(sub_tokens) != len(sub_piis):
            return
        # Replicate the creation guard: aliases were only inserted when
        # EVERY sub-token differed from its sub-PII.  Without this we
        # might pop an unrelated `_unscrub[word] = word` mapping.
        if not all(st != sp for st, sp in zip(sub_tokens, sub_piis)):
            return
        for sub_t, sub_p in zip(sub_tokens, sub_piis):
            # Only remove if it still aliases to the same sub-PII; a
            # later mapping may have re-bound this sub-token.
            if self._unscrub.get(sub_t) == sub_p:
                self._unscrub.pop(sub_t, None)

    def remove_entry(self, pii: str) -> bool:
        """Remove a single PII entry from the map. Returns True if found and removed."""
        with self._lock:
            token = self._scrub.get(pii)
            if token is None:
                return False
            self._scrub.pop(pii, None)
            self._unscrub.pop(token, None)
            # B3 cleanup: purge per-sub-token aliases too.
            self._purge_subtoken_aliases(pii, token)
            self._entity_types.pop(pii, None)
            self._entry_timestamps.pop(pii, None)
            self._token_meta.pop(pii, None)
            # Remove matching pending writes to prevent resurrection on drain
            self._pending_writes = [
                pw for pw in self._pending_writes if pw[0] != pii
            ]
            self._pending_touches.discard(pii)
            if self._db is not None:
                self._pending_deletes.add(pii)
            self._updated_at = datetime.now(timezone.utc)
            self._token_version += 1
            return True

    def invalidate_entity_types(self, entity_types: set[str]) -> None:
        """Remove cached forward mappings for the given entity types."""
        if not entity_types:
            return
        with self._lock:
            pii_to_remove = [
                pii for pii, etype in self._entity_types.items()
                if etype in entity_types
            ]
            for pii in pii_to_remove:
                etype = self._entity_types.get(pii, "?")
                token = self._scrub.pop(pii, None)
                self._entity_types.pop(pii, None)
                self._entry_timestamps.pop(pii, None)
                self._token_meta.pop(pii, None)
                if token is not None:
                    self._unscrub.pop(token, None)
                    # B3 cleanup: purge per-sub-token aliases too.
                    self._purge_subtoken_aliases(pii, token)
                    logger.debug(
                        "Invalidated cached mapping for %s entity (token %s)",
                        etype,
                        token,
                    )
            if pii_to_remove:
                # Purge matching pending writes
                removed_set = set(pii_to_remove)
                self._pending_writes = [
                    pw for pw in self._pending_writes if pw[0] not in removed_set
                ]
                self._pending_touches.difference_update(removed_set)
                if self._db is not None:
                    self._pending_deletes.update(removed_set)
                self._token_version += 1

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize to the canonical ``token_map.json`` format."""
        with self._lock:
            return {
                "version": 1,
                "created_at": self._created_at.isoformat().replace("+00:00", "Z"),
                "updated_at": self._updated_at.isoformat().replace("+00:00", "Z"),
                "scrub": dict(self._scrub),
                "unscrub": dict(self._unscrub),
                "entity_types": dict(self._entity_types),
                "token_meta": dict(self._token_meta),
                "counters": dict(self._counters),
                "entry_timestamps": dict(self._entry_timestamps),
                "stats": {
                    "total_scrubbed": self._stats_total,
                    "by_type": dict(self._stats_by_type),
                    "by_source": dict(self._stats_by_source),
                },
            }

    @classmethod
    def from_dict(
        cls,
        data: dict,
        replacements: dict[str, ReplacementStrategy] | None = None,
        db: TokenDB | None = None,
    ) -> TokenMap:
        """Deserialize from the canonical ``token_map.json`` format."""
        tm = cls.__new__(cls)
        tm._lock = threading.RLock()
        tm._scrub = dict(data.get("scrub", {}))
        tm._unscrub = dict(data.get("unscrub", {}))
        tm._entity_types = dict(data.get("entity_types", {}))
        tm._token_meta = dict(data.get("token_meta", {}))
        tm._counters = dict(data.get("counters", {}))
        tm._entry_timestamps = {k: float(v) for k, v in data.get("entry_timestamps", {}).items()}
        tm._replacements = replacements or {}
        tm._db = db
        tm._pending_writes = []
        tm._pending_touches = set()
        tm._pending_deletes = set()
        tm._pending_clear = False

        created_raw = data.get("created_at", "")
        updated_raw = data.get("updated_at", "")
        tm._created_at = _parse_iso(created_raw) if created_raw else datetime.now(timezone.utc)
        tm._updated_at = _parse_iso(updated_raw) if updated_raw else datetime.now(timezone.utc)

        stats = data.get("stats", {})
        tm._stats_total = stats.get("total_scrubbed", 0)
        tm._stats_by_type = dict(stats.get("by_type", {}))
        tm._stats_by_source = dict(stats.get("by_source", {}))
        tm._token_version = 0
        return tm

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _record_stat(self, entity_type: str, source: str) -> None:
        """Update aggregate statistics counters."""
        self._stats_total += 1
        self._stats_by_type[entity_type] = self._stats_by_type.get(entity_type, 0) + 1
        if source:
            self._stats_by_source[source] = self._stats_by_source.get(source, 0) + 1


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 datetime string, handling trailing ``Z``."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)
