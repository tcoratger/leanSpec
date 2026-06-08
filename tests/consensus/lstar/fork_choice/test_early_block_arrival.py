"""
Test vectors for blocks delivered ahead of the store clock.

Block import has no arrival-time gate: a block whose slot has not begun
on the local clock still imports and becomes head. These vectors pin
that behavior so clients agree on early-block handling bit-for-bit.
"""

import pytest

from consensus_testing import (
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
    TickStep,
)
from lean_spec.spec.forks import Interval, Slot

pytestmark = pytest.mark.valid_until("Lstar")


def test_block_ahead_of_store_clock_is_imported(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A slot-1 block delivered while the clock sits at genesis still imports.

    Fixture state: the store clock never ticks, so store time stays at
    interval 0 while the head advances to the early block.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                tick_to_slot=False,
                checks=StoreChecks(time=Interval(0), head_slot=Slot(1)),
            ),
        ],
    )


def test_early_block_then_clock_catches_up(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The clock reaching the early block's slot leaves the head unchanged.

    Fixture state: slot-1 block imports at interval 0, then a tick to
    the start of slot 2 only advances time.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                tick_to_slot=False,
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            TickStep(
                interval=10,
                checks=StoreChecks(time=Interval(10), head_slot=Slot(1)),
            ),
        ],
    )
