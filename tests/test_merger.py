"""Tests for PII entity merge and deduplication."""
from __future__ import annotations

from scruxy.pipeline.merger import PiiEntity, merge_and_deduplicate


def _entity(
    entity_type: str = "PERSON",
    start: int = 0,
    end: int = 5,
    score: float = 0.9,
    source: str = "presidio",
) -> PiiEntity:
    """Helper to create a PiiEntity with sensible defaults."""
    return PiiEntity(
        entity_type=entity_type,
        start=start,
        end=end,
        score=score,
        source=source,
    )


class TestMergeAndDeduplicateEmpty:
    """Edge cases with zero or one entity."""

    def test_no_entities_returns_empty_list(self):
        assert merge_and_deduplicate([]) == []

    def test_single_entity_returned_unchanged(self):
        e = _entity(start=0, end=5, score=0.9)
        result = merge_and_deduplicate([e])
        assert result == [e]


class TestNonOverlapping:
    """Entities that do not overlap should all be kept."""

    def test_non_overlapping_entities_all_kept_sorted(self):
        e1 = _entity(start=0, end=5, score=0.8)
        e2 = _entity(start=10, end=15, score=0.9)
        e3 = _entity(start=20, end=25, score=0.7)
        result = merge_and_deduplicate([e3, e1, e2])
        assert result == [e1, e2, e3]

    def test_adjacent_touching_entities_both_kept(self):
        """Adjacent means end of one == start of next. No actual overlap."""
        e1 = _entity(start=0, end=5, score=0.9)
        e2 = _entity(start=5, end=10, score=0.8)
        result = merge_and_deduplicate([e1, e2])
        assert result == [e1, e2]


class TestOverlappingDifferentScores:
    """When two entities overlap, the one with a higher score should win."""

    def test_higher_score_wins(self):
        low = _entity(entity_type="PERSON", start=0, end=10, score=0.6)
        high = _entity(entity_type="EMAIL", start=5, end=15, score=0.9)
        result = merge_and_deduplicate([low, high])
        # Winner (high) is extended to cover loser's prefix [0,5)
        assert len(result) == 1
        assert result[0].entity_type == "EMAIL"
        assert result[0].start == 0
        assert result[0].end == 15
        assert result[0].score == 0.9

    def test_higher_score_wins_reversed_input_order(self):
        low = _entity(entity_type="PERSON", start=0, end=10, score=0.6)
        high = _entity(entity_type="EMAIL", start=5, end=15, score=0.9)
        result = merge_and_deduplicate([high, low])
        # sorted by start: low first, high second; high wins and extends to [0,15)
        assert len(result) == 1
        assert result[0].entity_type == "EMAIL"
        assert result[0].start == 0
        assert result[0].end == 15


class TestOverlappingSameScore:
    """When two overlapping entities have the same score, longer span wins."""

    def test_same_score_longer_span_wins(self):
        short = _entity(entity_type="PERSON", start=0, end=5, score=0.8)
        long = _entity(entity_type="FULL_NAME", start=0, end=10, score=0.8)
        result = merge_and_deduplicate([short, long])
        assert result == [long]

    def test_same_score_longer_span_wins_reversed(self):
        short = _entity(entity_type="PERSON", start=3, end=8, score=0.8)
        long = _entity(entity_type="FULL_NAME", start=0, end=10, score=0.8)
        result = merge_and_deduplicate([short, long])
        assert result == [long]


class TestCascadingOverlaps:
    """Three or more entities with cascading overlaps."""

    def test_three_cascading_overlaps_highest_score_wins(self):
        """A overlaps B, B overlaps C. The one with the best score should survive."""
        e1 = _entity(entity_type="A", start=0, end=10, score=0.5)
        e2 = _entity(entity_type="B", start=5, end=15, score=0.9)
        e3 = _entity(entity_type="C", start=10, end=20, score=0.7)
        result = merge_and_deduplicate([e1, e2, e3])
        # e2 beats e1 (extended to [0,15)), then e2 beats e3 (extended to [0,20))
        assert len(result) == 1
        assert result[0].entity_type == "B"
        assert result[0].start == 0
        assert result[0].end == 20

    def test_three_cascading_last_wins(self):
        """Cascading where the last entity has the highest score."""
        e1 = _entity(entity_type="A", start=0, end=10, score=0.5)
        e2 = _entity(entity_type="B", start=5, end=15, score=0.6)
        e3 = _entity(entity_type="C", start=10, end=20, score=0.9)
        result = merge_and_deduplicate([e1, e2, e3])
        # e2 beats e1 (extended to [0,15)), then e3 beats e2 (extended to [0,20))
        assert len(result) == 1
        assert result[0].entity_type == "C"
        assert result[0].start == 0
        assert result[0].end == 20


class TestIdenticalEntities:
    """Exact duplicates should collapse to one."""

    def test_identical_entities_collapsed_to_one(self):
        e1 = _entity(start=0, end=5, score=0.9, source="presidio")
        e2 = _entity(start=0, end=5, score=0.9, source="regex")
        result = merge_and_deduplicate([e1, e2])
        assert len(result) == 1
        assert result[0].start == 0
        assert result[0].end == 5

    def test_three_identical_collapsed(self):
        entities = [_entity(start=0, end=5, score=0.9) for _ in range(3)]
        result = merge_and_deduplicate(entities)
        assert len(result) == 1


class TestFullyContained:
    """One entity is fully contained within another."""

    def test_contained_entity_with_lower_score_removed(self):
        outer = _entity(entity_type="FULL_NAME", start=0, end=20, score=0.9)
        inner = _entity(entity_type="FIRST_NAME", start=5, end=10, score=0.7)
        result = merge_and_deduplicate([outer, inner])
        assert result == [outer]

    def test_contained_entity_with_higher_score_wins(self):
        outer = _entity(entity_type="FULL_NAME", start=0, end=20, score=0.5)
        inner = _entity(entity_type="EMAIL", start=5, end=10, score=0.9)
        result = merge_and_deduplicate([outer, inner])
        # Inner wins but is extended to cover outer's full span [0,20)
        assert len(result) == 1
        assert result[0].entity_type == "EMAIL"
        assert result[0].start == 0
        assert result[0].end == 20

    def test_contained_same_score_longer_wins(self):
        """Same score, the longer (outer) entity should win."""
        outer = _entity(entity_type="FULL_NAME", start=0, end=20, score=0.8)
        inner = _entity(entity_type="FIRST_NAME", start=5, end=10, score=0.8)
        result = merge_and_deduplicate([outer, inner])
        assert result == [outer]


class TestMultipleSeparateGroups:
    """Multiple independent groups of overlapping entities."""

    def test_two_separate_overlap_groups(self):
        # Group 1: positions 0-15
        g1_a = _entity(entity_type="PERSON", start=0, end=10, score=0.7)
        g1_b = _entity(entity_type="EMAIL", start=5, end=15, score=0.9)
        # Group 2: positions 50-65
        g2_a = _entity(entity_type="PHONE", start=50, end=60, score=0.6)
        g2_b = _entity(entity_type="SSN", start=55, end=65, score=0.8)

        result = merge_and_deduplicate([g1_a, g1_b, g2_a, g2_b])
        assert len(result) == 2
        # Group 1 winner extended to [0,15)
        assert result[0].entity_type == "EMAIL"
        assert result[0].start == 0
        assert result[0].end == 15
        # Group 2 winner extended to [50,65)
        assert result[1].entity_type == "SSN"
        assert result[1].start == 50
        assert result[1].end == 65

    def test_mixed_overlapping_and_non_overlapping(self):
        standalone = _entity(entity_type="DATE", start=30, end=40, score=0.95)
        overlap_a = _entity(entity_type="PERSON", start=0, end=10, score=0.6)
        overlap_b = _entity(entity_type="NAME", start=5, end=12, score=0.8)

        result = merge_and_deduplicate([standalone, overlap_a, overlap_b])
        assert len(result) == 2
        # Overlap winner extended to [0,12)
        assert result[0].entity_type == "NAME"
        assert result[0].start == 0
        assert result[0].end == 12
        assert result[1] == standalone


class TestSortingStability:
    """Verify output is always sorted by start position."""

    def test_output_sorted_by_start(self):
        entities = [
            _entity(start=30, end=35, score=0.9),
            _entity(start=0, end=5, score=0.9),
            _entity(start=15, end=20, score=0.9),
        ]
        result = merge_and_deduplicate(entities)
        starts = [e.start for e in result]
        assert starts == sorted(starts)

    def test_same_score_same_length_stable_selection(self):
        """When score and length are equal, the first entity (by position) is kept."""
        e1 = _entity(entity_type="A", start=0, end=5, score=0.8, source="presidio")
        e2 = _entity(entity_type="B", start=3, end=8, score=0.8, source="regex")
        result = merge_and_deduplicate([e1, e2])
        assert len(result) == 1
        # Both have same score and same length (5); first selected wins
        # but extended to cover e2's suffix [0,8)
        assert result[0].entity_type == "A"
        assert result[0].start == 0
        assert result[0].end == 8
