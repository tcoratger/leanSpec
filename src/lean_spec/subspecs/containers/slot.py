"""Slot container."""

from __future__ import annotations

from functools import total_ordering

from lean_spec.types import Uint64


@total_ordering
class Slot(Uint64):
    """Represents a slot number as a 64-bit unsigned integer."""

    def is_justifiable_after(self, finalized_slot: Slot) -> bool:
        """
        Checks if this slot is a valid candidate for justification after a given finalized slot.

        According to the 3SF-mini specification, a slot is justifiable if its
        distance (`delta`) from the last finalized slot is:
          1. Less than or equal to 5.
          2. A perfect square (e.g., 9, 16, 25...).
          3. A pronic number (of the form x^2 + x, e.g., 6, 12, 20...).

        Args:
            finalized_slot: The last slot that was finalized.

        Returns:
            True if the slot is justifiable, False otherwise.

        Raises:
            AssertionError: If this slot is earlier than the finalized slot.
        """
        # Ensure the candidate slot is not before the finalized slot.
        assert self >= finalized_slot, "Candidate slot must not be before finalized slot"

        # Calculate the distance in slots from the last finalized slot.
        delta = (self - finalized_slot).as_int()

        return (
            # Rule 1: The first 5 slots after finalization are always justifiable.
            #
            # Examples: delta = 0, 1, 2, 3, 4, 5
            delta <= 5
            # Rule 2: Slots at perfect square distances are justifiable.
            #
            # Examples: delta = 1, 4, 9, 16, 25, 36, 49, 64, ...
            # Check: sqrt(delta) is a whole number (no fractional part)
            or (delta**0.5) % 1 == 0
            # Rule 3: Slots at pronic number distances are justifiable.
            #
            # Pronic numbers have the form n(n+1): 2, 6, 12, 20, 30, 42, 56, ...
            # Mathematical insight: For pronic delta = n(n+1), we have:
            #   delta + 0.25 = n^2 + n + 0.25 = (n + 0.5)^2
            #   Therefore sqrt(delta + 0.25) = n + 0.5
            or ((delta + 0.25) ** 0.5) % 1 == 0.5
        )
