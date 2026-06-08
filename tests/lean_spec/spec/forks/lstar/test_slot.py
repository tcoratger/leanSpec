"""Tests for the Slot justification math."""

from __future__ import annotations

import pytest

from lean_spec.spec.forks.lstar.slot import Slot


class TestIsJustifiableAfter:
    """Distance rules deciding whether a slot may receive new justification votes."""

    @pytest.mark.parametrize(
        ("distance_from_finalized", "is_justifiable"),
        [
            (0, True),  # immediate window
            (1, True),
            (2, True),
            (3, True),
            (4, True),
            (5, True),  # last slot of the immediate window
            (6, True),  # pronic 2*3
            (7, False),
            (8, False),
            (9, True),  # perfect square 3**2
            (10, False),
            (11, False),
            (12, True),  # pronic 3*4
            (13, False),
            (14, False),
            (15, False),
            (16, True),  # perfect square 4**2
            (17, False),
            (18, False),
            (19, False),
            (20, True),  # pronic 4*5
            (21, False),
            (22, False),
            (23, False),
            (24, False),
            (25, True),  # perfect square 5**2
            (26, False),
            (27, False),
            (28, False),
            (29, False),
            (30, True),  # pronic 5*6
        ],
    )
    def test_follows_distance_pattern(
        self, distance_from_finalized: int, is_justifiable: bool
    ) -> None:
        """A slot is justifiable when its distance from finalization is small, square, or pronic."""
        finalized_slot = Slot(0)
        candidate_slot = Slot(distance_from_finalized)

        assert candidate_slot.is_justifiable_after(finalized_slot) is is_justifiable

    def test_depends_on_distance_not_absolute_slot(self) -> None:
        """Justifiability is decided by the gap from finalization, not the absolute slot number."""
        finalized_slot = Slot(100)

        assert Slot(106).is_justifiable_after(finalized_slot) is True  # distance 6, pronic
        assert Slot(107).is_justifiable_after(finalized_slot) is False  # distance 7
        assert Slot(109).is_justifiable_after(finalized_slot) is True  # distance 9, perfect square

    def test_allows_slot_equal_to_finalized(self) -> None:
        """The finalized slot itself sits at distance zero and is justifiable."""
        finalized_slot = Slot(42)

        assert finalized_slot.is_justifiable_after(finalized_slot) is True

    def test_rejects_slot_before_finalized(self) -> None:
        """A candidate earlier than the finalized slot is a programming error."""
        finalized_slot = Slot(5)

        with pytest.raises(AssertionError) as exception_info:
            Slot(4).is_justifiable_after(finalized_slot)

        assert str(exception_info.value) == "Candidate slot must not be before finalized slot"


class TestJustifiedIndexAfter:
    """Mapping a slot to its position in the relative justification bitfield."""

    @pytest.mark.parametrize(
        ("candidate_slot_value", "finalized_slot_value"),
        [
            (5, 5),  # the finalized slot itself
            (3, 5),  # a slot before finalization
            (0, 0),  # genesis at the genesis boundary
        ],
    )
    def test_returns_none_at_or_before_finalized(
        self, candidate_slot_value: int, finalized_slot_value: int
    ) -> None:
        """Slots at or before finalization have no index in the tracked bitfield."""
        candidate_slot = Slot(candidate_slot_value)
        finalized_slot = Slot(finalized_slot_value)

        assert candidate_slot.justified_index_after(finalized_slot) is None

    @pytest.mark.parametrize(
        ("candidate_slot_value", "finalized_slot_value", "expected_index"),
        [
            (6, 5, 0),  # first slot after finalization maps to index 0
            (7, 5, 1),
            (10, 5, 4),
            (1, 0, 0),
            (5, 0, 4),
            (13, 10, 2),
        ],
    )
    def test_maps_slot_distance_to_zero_based_index(
        self, candidate_slot_value: int, finalized_slot_value: int, expected_index: int
    ) -> None:
        """The first slot after finalization is index 0, each later slot one higher."""
        candidate_slot = Slot(candidate_slot_value)
        finalized_slot = Slot(finalized_slot_value)

        assert candidate_slot.justified_index_after(finalized_slot) == expected_index
