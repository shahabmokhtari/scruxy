"""Tests for TokenMap creation, deterministic tokens, serialization, and anonymizer/deanonymizer."""
from __future__ import annotations

import pytest

from scruxy.tokenmap.token_map import TokenMap
from scruxy.tokenmap.anonymizer import PiiEntity, anonymize_text
from scruxy.tokenmap.deanonymizer import Deanonymizer, SSEChunkBuffer


# ---------------------------------------------------------------------------
# TokenMap core behaviour
# ---------------------------------------------------------------------------


class TestTokenMapCreation:
    """Basic TokenMap instantiation and single-entry operations."""

    def test_empty_token_map(self) -> None:
        tm = TokenMap()
        assert tm.size == 0
        assert tm.scrub_map == {}
        assert tm.unscrub_map == {}
        assert tm.counters == {}

    def test_get_or_create_token_creates_new(self) -> None:
        tm = TokenMap()
        token = tm.get_or_create_token("john@example.com", "EMAIL")
        assert token == "REDACTED_EMAIL_1"
        assert tm.size == 1

    def test_get_or_create_token_deterministic(self) -> None:
        """Same PII always maps to the same token within a session."""
        tm = TokenMap()
        token1 = tm.get_or_create_token("john@example.com", "EMAIL")
        token2 = tm.get_or_create_token("john@example.com", "EMAIL")
        assert token1 == token2
        assert tm.size == 1  # no duplicate entry

    def test_different_pii_different_tokens(self) -> None:
        tm = TokenMap()
        t1 = tm.get_or_create_token("john@example.com", "EMAIL")
        t2 = tm.get_or_create_token("jane@example.com", "EMAIL")
        assert t1 == "REDACTED_EMAIL_1"
        assert t2 == "REDACTED_EMAIL_2"
        assert tm.size == 2

    def test_different_types_have_separate_counters(self) -> None:
        tm = TokenMap()
        t_email = tm.get_or_create_token("john@example.com", "EMAIL")
        t_person = tm.get_or_create_token("John Doe", "PERSON")
        assert t_email == "REDACTED_EMAIL_1"
        assert t_person == "REDACTED_PERSON_1"
        assert tm.counters == {"EMAIL": 1, "PERSON": 1}

    def test_get_pii_reverse_lookup(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("john@example.com", "EMAIL")
        assert tm.get_pii("REDACTED_EMAIL_1") == "john@example.com"
        assert tm.get_pii("REDACTED_EMAIL_999") is None

    def test_get_token_forward_lookup(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("john@example.com", "EMAIL")
        assert tm.get_token("john@example.com") == "REDACTED_EMAIL_1"
        assert tm.get_token("unknown@example.com") is None

    def test_stats_tracking(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("john@example.com", "EMAIL", source="presidio")
        tm.get_or_create_token("john@example.com", "EMAIL", source="presidio")
        tm.get_or_create_token("Jane Doe", "PERSON", source="regex")

        data = tm.to_dict()
        assert data["stats"]["total_scrubbed"] == 3
        assert data["stats"]["by_type"] == {"EMAIL": 2, "PERSON": 1}
        assert data["stats"]["by_source"] == {"presidio": 2, "regex": 1}


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------


class TestTokenMapSerialization:
    """to_dict / from_dict round-trip tests."""

    def test_roundtrip_empty(self) -> None:
        tm = TokenMap()
        data = tm.to_dict()
        restored = TokenMap.from_dict(data)
        assert restored.size == 0
        assert restored.to_dict()["version"] == 1

    def test_roundtrip_with_entries(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("john@example.com", "EMAIL", source="presidio")
        tm.get_or_create_token("Jane Smith", "PERSON", source="regex")
        tm.get_or_create_token("555-0123", "PHONE", source="presidio")

        data = tm.to_dict()
        restored = TokenMap.from_dict(data)

        assert restored.scrub_map == tm.scrub_map
        assert restored.unscrub_map == tm.unscrub_map
        assert restored.counters == tm.counters
        assert restored.get_pii("REDACTED_EMAIL_1") == "john@example.com"
        assert restored.get_token("Jane Smith") == "REDACTED_PERSON_1"

    def test_roundtrip_preserves_stats(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("a@b.com", "EMAIL", source="presidio")
        tm.get_or_create_token("a@b.com", "EMAIL", source="presidio")

        data = tm.to_dict()
        restored = TokenMap.from_dict(data)
        restored_data = restored.to_dict()

        assert restored_data["stats"]["total_scrubbed"] == data["stats"]["total_scrubbed"]
        assert restored_data["stats"]["by_type"] == data["stats"]["by_type"]
        assert restored_data["stats"]["by_source"] == data["stats"]["by_source"]

    def test_from_dict_with_canonical_format(self) -> None:
        """Load the exact format described in the design doc."""
        data = {
            "version": 1,
            "created_at": "2026-03-03T10:15:00Z",
            "updated_at": "2026-03-03T10:42:30Z",
            "scrub": {
                "john.doe@company.com": "REDACTED_EMAIL_1",
                "Jane Smith": "REDACTED_PERSON_1",
                "555-0123": "REDACTED_PHONE_1",
            },
            "unscrub": {
                "REDACTED_EMAIL_1": "john.doe@company.com",
                "REDACTED_PERSON_1": "Jane Smith",
                "REDACTED_PHONE_1": "555-0123",
            },
            "counters": {"EMAIL": 1, "PERSON": 1, "PHONE": 1},
            "stats": {
                "total_scrubbed": 47,
                "by_type": {"EMAIL": 12, "PERSON": 8, "PHONE": 5, "US_SSN": 2},
                "by_source": {"presidio": 20, "regex": 5, "plugin:codename_detector": 2},
            },
        }

        tm = TokenMap.from_dict(data)
        assert tm.size == 3
        assert tm.get_pii("REDACTED_EMAIL_1") == "john.doe@company.com"
        assert tm.get_token("Jane Smith") == "REDACTED_PERSON_1"
        assert tm.counters == {"EMAIL": 1, "PERSON": 1, "PHONE": 1}

    def test_to_dict_version_field(self) -> None:
        tm = TokenMap()
        assert tm.to_dict()["version"] == 1

    def test_to_dict_timestamps_are_strings(self) -> None:
        tm = TokenMap()
        data = tm.to_dict()
        assert isinstance(data["created_at"], str)
        assert isinstance(data["updated_at"], str)
        assert data["created_at"].endswith("Z")

    def test_continued_use_after_from_dict(self) -> None:
        """After restoring from dict, new tokens should use correct counters."""
        data = {
            "version": 1,
            "created_at": "2026-03-03T10:15:00Z",
            "updated_at": "2026-03-03T10:15:00Z",
            "scrub": {"a@b.com": "REDACTED_EMAIL_1"},
            "unscrub": {"REDACTED_EMAIL_1": "a@b.com"},
            "counters": {"EMAIL": 1},
            "stats": {"total_scrubbed": 1, "by_type": {"EMAIL": 1}, "by_source": {}},
        }
        tm = TokenMap.from_dict(data)
        new_token = tm.get_or_create_token("c@d.com", "EMAIL")
        assert new_token == "REDACTED_EMAIL_2"
        assert tm.size == 2


# ---------------------------------------------------------------------------
# Anonymizer
# ---------------------------------------------------------------------------


class TestAnonymizer:
    """anonymize_text replaces PII spans with tokens."""

    def test_single_entity(self) -> None:
        tm = TokenMap()
        text = "Contact john@example.com for info."
        entities = [PiiEntity("EMAIL", 8, 24, 0.9, "presidio")]
        result = anonymize_text(text, entities, tm)
        assert result == "Contact REDACTED_EMAIL_1 for info."

    def test_multiple_entities(self) -> None:
        tm = TokenMap()
        text = "John Doe (john@example.com) called 555-0123."
        entities = [
            PiiEntity("PERSON", 0, 8, 0.85, "presidio"),
            PiiEntity("EMAIL", 10, 26, 0.95, "presidio"),
            PiiEntity("PHONE", 35, 43, 0.9, "regex"),
        ]
        result = anonymize_text(text, entities, tm)
        assert "REDACTED_PERSON_1" in result
        assert "REDACTED_EMAIL_1" in result
        assert "REDACTED_PHONE_1" in result
        assert "John Doe" not in result
        assert "john@example.com" not in result
        assert "555-0123" not in result

    def test_empty_entities(self) -> None:
        tm = TokenMap()
        text = "No PII here."
        result = anonymize_text(text, [], tm)
        assert result == text

    def test_deterministic_across_calls(self) -> None:
        tm = TokenMap()
        text1 = "Email: john@example.com"
        text2 = "Also john@example.com"
        e1 = [PiiEntity("EMAIL", 7, 23, 0.9, "presidio")]
        e2 = [PiiEntity("EMAIL", 5, 21, 0.9, "presidio")]
        r1 = anonymize_text(text1, e1, tm)
        r2 = anonymize_text(text2, e2, tm)
        assert "REDACTED_EMAIL_1" in r1
        assert "REDACTED_EMAIL_1" in r2

    def test_right_to_left_processing_preserves_indices(self) -> None:
        """Adjacent entities with different token lengths shouldn't corrupt offsets."""
        tm = TokenMap()
        text = "AB"  # A at [0,1], B at [1,2]
        entities = [
            PiiEntity("X", 0, 1, 1.0, "test"),
            PiiEntity("Y", 1, 2, 1.0, "test"),
        ]
        result = anonymize_text(text, entities, tm)
        assert result == "REDACTED_X_1REDACTED_Y_1"


# ---------------------------------------------------------------------------
# Deanonymizer
# ---------------------------------------------------------------------------


class TestDeanonymizer:
    """Deanonymizer.deanonymize_text replaces tokens with PII."""

    def test_single_token(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("john@example.com", "EMAIL")
        text = "Contact REDACTED_EMAIL_1 for info."
        result = Deanonymizer.deanonymize_text(text, tm)
        assert result == "Contact john@example.com for info."

    def test_multiple_tokens(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("john@example.com", "EMAIL")
        tm.get_or_create_token("Jane Doe", "PERSON")
        text = "REDACTED_PERSON_1 emailed REDACTED_EMAIL_1"
        result = Deanonymizer.deanonymize_text(text, tm)
        assert result == "Jane Doe emailed john@example.com"

    def test_unknown_token_left_as_is(self) -> None:
        tm = TokenMap()
        text = "Token REDACTED_SSN_99 is unknown."
        result = Deanonymizer.deanonymize_text(text, tm)
        assert result == text

    def test_no_tokens(self) -> None:
        tm = TokenMap()
        text = "Plain text with no tokens."
        result = Deanonymizer.deanonymize_text(text, tm)
        assert result == text

    def test_roundtrip_anonymize_deanonymize(self) -> None:
        tm = TokenMap()
        original = "John Doe (john@example.com) lives at 123 Main St."
        entities = [
            PiiEntity("PERSON", 0, 8, 0.9, "presidio"),
            PiiEntity("EMAIL", 10, 26, 0.95, "presidio"),
            PiiEntity("ADDRESS", 37, 49, 0.8, "regex"),
        ]
        scrubbed = anonymize_text(original, entities, tm)
        restored = Deanonymizer.deanonymize_text(scrubbed, tm)
        assert restored == original


# ---------------------------------------------------------------------------
# SSEChunkBuffer
# ---------------------------------------------------------------------------


class TestSSEChunkBuffer:
    """SSEChunkBuffer handles tokens split across SSE chunk boundaries."""

    def test_complete_token_in_single_chunk(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("john@example.com", "EMAIL")
        buf = SSEChunkBuffer(tm)
        result = buf.feed("Hello REDACTED_EMAIL_1 world")
        result += buf.flush()
        assert result == "Hello john@example.com world"

    def test_token_split_across_chunks(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("john@example.com", "EMAIL")
        buf = SSEChunkBuffer(tm)
        part1 = buf.feed("I see REDACTED_EM")
        part2 = buf.feed("AIL_1 has a bug")
        part3 = buf.flush()
        combined = part1 + part2 + part3
        assert "john@example.com" in combined
        assert "REDACTED_EMAIL_1" not in combined

    def test_no_tokens(self) -> None:
        tm = TokenMap()
        buf = SSEChunkBuffer(tm)
        result = buf.feed("just plain text") + buf.flush()
        assert result == "just plain text"

    def test_flush_emits_buffered_non_token(self) -> None:
        """If buffer holds a partial that never completes, flush emits it."""
        tm = TokenMap()
        buf = SSEChunkBuffer(tm)
        result = buf.feed("prefix REDACT")
        # REDACT alone won't match anything in trie (trie is empty).
        result += buf.flush()
        assert "REDACT" in result

    def test_multiple_tokens_in_stream(self) -> None:
        tm = TokenMap()
        tm.get_or_create_token("john@example.com", "EMAIL")
        tm.get_or_create_token("Jane Doe", "PERSON")
        buf = SSEChunkBuffer(tm)
        out = buf.feed("REDACTED_EMAIL_1 said hi to REDACTED_PERSON_1")
        out += buf.flush()
        assert "john@example.com" in out
        assert "Jane Doe" in out

    def test_rebuild_trie_after_new_token(self) -> None:
        tm = TokenMap()
        buf = SSEChunkBuffer(tm)

        # Token added after buffer creation.
        tm.get_or_create_token("john@example.com", "EMAIL")
        buf.rebuild_trie()

        out = buf.feed("REDACTED_EMAIL_1") + buf.flush()
        assert out == "john@example.com"
