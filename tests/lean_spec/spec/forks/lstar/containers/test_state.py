"""Tests for the lstar State container."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from lean_spec.spec.forks import Slot
from tests.lean_spec.helpers import make_genesis_state


def test_is_slot_justified_raises_on_out_of_bounds() -> None:
    # For slots > finalized_slot, the bitfield must be long enough to cover the slot.
    # If it is not, this indicates an inconsistent state and should fail fast.
    with pytest.raises(IndexError):
        make_genesis_state(num_validators=1).justified_slots.is_slot_justified(Slot(0), Slot(1))


class TestStateImmutability:
    """Frozen-model semantics forbid post-construction mutation."""

    def test_assigning_slot_raises(self) -> None:
        """Assigning a new slot on a constructed state raises."""
        genesis_state = make_genesis_state(num_validators=1)
        with pytest.raises(ValidationError, match="frozen"):
            genesis_state.slot = Slot(1)
