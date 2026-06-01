"""Interval time unit."""

from __future__ import annotations

from lean_spec.spec.ssz import Uint64

from .config import INTERVALS_PER_SLOT
from .slot import Slot


class Interval(Uint64):
    """Interval count since genesis."""

    @classmethod
    def from_slot(cls, slot: Slot) -> Interval:
        """
        Convert a slot number to the interval at that slot's start.

        Each slot spans a fixed number of intervals.
        This gives the first interval of the given slot.

        Args:
            slot: Slot number since genesis.

        Returns:
            Interval count at the start of the given slot.
        """
        # Slot boundaries fall on exact multiples of the interval count.
        #
        # The two values are distinct unsigned types, so drop to plain ints to multiply.
        return cls(int(slot) * int(INTERVALS_PER_SLOT))
