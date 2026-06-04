"""Tests for the Interval time unit."""

from __future__ import annotations

import pytest

from lean_spec.spec.forks import Interval, Slot
from lean_spec.spec.forks.lstar.config import INTERVALS_PER_SLOT


class TestIntervalFromSlot:
    """Tests for Interval.from_slot()."""

    @pytest.mark.parametrize(
        ("slot", "expected_interval"),
        [
            # Genesis slot starts at interval 0.
            (0, 0),
            # Each slot spans INTERVALS_PER_SLOT (5) intervals.
            (1, 5),
            (2, 10),
            (3, 15),
            (10, 50),
            (100, 500),
            # Large slot stays exact: no overflow, no rounding.
            (1_000_000, 5_000_000),
        ],
    )
    def test_maps_slot_to_its_starting_interval(self, slot: int, expected_interval: int) -> None:
        """A slot maps to the interval count at its first interval."""
        assert Interval.from_slot(Slot(slot)) == Interval(expected_interval)

    @pytest.mark.parametrize("slot", [0, 1, 7, 42, 1000])
    def test_advancing_one_slot_adds_one_slot_of_intervals(self, slot: int) -> None:
        """Advancing a single slot adds exactly INTERVALS_PER_SLOT intervals."""
        step = Interval.from_slot(Slot(slot + 1)) - Interval.from_slot(Slot(slot))
        assert step == Interval(INTERVALS_PER_SLOT)

    def test_return_type_is_interval(self) -> None:
        """Return value is an Interval instance, not a plain Uint64."""
        assert isinstance(Interval.from_slot(Slot(2)), Interval)
