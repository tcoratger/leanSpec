"""Attestation Target Selection and Safe Target Computation"""

import pytest
from consensus_testing import (
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)

from lean_spec.subspecs.containers.slot import Slot

pytestmark = pytest.mark.valid_until("Devnet")


def test_attestation_target_at_genesis_initially(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation target stays at genesis before safe target updates.

    Scenario
    --------
    Process two blocks at slots 1 and 2.

    Expected:
        - After slot 1: target = slot 0 (walkback to safe_target)
        - After slot 2: target = slot 0 (walkback to safe_target)

    Why This Matters
    ----------------
    Initially, the safe target is at genesis (slot 0). The attestation target
    walks back to safe_target to maintain separation between head votes
    (fork choice) and target votes (BFT finality). The chain bootstraps
    via update_safe_target at interval 3.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_target_slot=Slot(0),
                ),
            ),
        ],
    )


def test_attestation_target_advances_with_attestations(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation target advances as attestation weight accumulates.

    Scenario
    --------
    Build a longer chain (slots 1-5) where attestations cause target advancement.

    Expected:
        - Initial blocks: target stays at genesis (slot 0)
        - Later blocks: target advances as walkback from head reaches further slots
        - Target remains behind head for safety

    Why This Matters
    ----------------
    As validators attest to blocks, the safe target advances, which in turn
    allows the attestation target to move forward.

    This demonstrates the dynamic nature of target selection: conservative initially,
    but advancing as consensus strengthens through attestation accumulation.

    The target advances only when sufficient attestation weight supports it.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),  # Walks back to safe_target
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_target_slot=Slot(0),  # Walks back to safe_target
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_target_slot=Slot(0),  # Walks back to safe_target
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4)),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    attestation_target_slot=Slot(1),  # 3-step walkback from 4 → 1
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_target_slot=Slot(2),  # 3-step walkback from 5 → 2
                ),
            ),
        ],
    )


def test_attestation_target_with_slot_gaps(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation target handles missed slots correctly.

    Scenario
    --------
    Process blocks at slots 1, 3, 5 (skipping even slots).

    Expected:
        - Targets advance despite gaps
        - Targets remain justifiable
        - Safe target stays valid

    Why This Matters
    ----------------
    Missed slots are common when proposers fail or network partitions occur.

    The target selection must handle sparse block production gracefully,
    ensuring validators can still make progress even with gaps in the chain.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_target_slot=Slot(0),  # Walks back 5→3→1→0, at safe_target
                ),
            ),
        ],
    )


def test_attestation_target_with_extended_chain(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation target advances progressively over extended chain.

    Scenario
    --------
    Build a longer chain (slots 1-8) observing target advancement pattern.

    Expected:
        - Initial slots: target at genesis (conservative)
        - Middle slots: target advances to slot 1
        - Target advances gradually, not jumping to head

    Why This Matters
    ----------------
    Over extended chains, the target selection should show smooth,
    gradual advancement as attestation weight accumulates.

    The target lags behind the head, providing a stable reference point that
    advances only when sufficient consensus has formed. This prevents validators
    from attesting too far ahead without adequate safety guarantees.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4)),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    attestation_target_slot=Slot(1),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_target_slot=Slot(2),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(6)),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    attestation_target_slot=Slot(3),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7)),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    attestation_target_slot=Slot(4),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(8)),
                checks=StoreChecks(
                    head_slot=Slot(8),
                    attestation_target_slot=Slot(5),
                ),
            ),
        ],
    )


def test_attestation_target_justifiable_constraint(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation target advances while respecting justifiability rules.

    Scenario
    --------
    Build a 10-slot chain and observe how the attestation target advances
    over time while remaining justifiable relative to genesis (finalized at slot 0).

    Justifiability Rules (see Slot.is_justifiable_after)
    -----------------------------------------------------

    The target starts from current head and looks back at most 3 slots towards safe target.

    Then, a slot is deemed justifiable at distance delta from finalization if:
    1. delta ≤ 5
    2. delta is a perfect square (1, 4, 9, 16, 25, ...)
    3. delta is a pronic number (2, 6, 12, 20, 30, ...)

    Why This Matters
    ----------------
    The justifiability rules prevent long-range attacks by restricting which
    checkpoints validators can attest to. The mathematical pattern (perfect squares
    and pronic numbers) creates increasingly sparse justifiable slots as the chain
    grows beyond finalization, providing security guarantees.

    The test verifies that the target selection algorithm respects these rules
    and never selects a non-justifiable target.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(i)),
                checks=StoreChecks(
                    head_slot=Slot(i),
                    attestation_target_slot=Slot(
                        # Mapping of current slot -> expected target slot
                        # Walkback stops at safe_target (slot 0) then
                        # justifiability is checked: delta = target - finalized
                        {
                            1: 0,  # Walks back to safe_target
                            2: 0,  # Walks back to safe_target
                            3: 0,  # Walks back to safe_target
                            4: 1,  # 3-step walkback from 4 → 1, delta 1 ≤ 5
                            5: 2,  # 3-step walkback from 5 → 2, delta 2 ≤ 5
                            6: 3,  # 3-step walkback from 6 → 3, delta 3 ≤ 5
                            7: 4,  # 3-step walkback from 7 → 4, delta 4 ≤ 5
                            8: 5,  # 3-step walkback from 8 → 5, delta 5 ≤ 5
                            9: 6,  # delta = 6, pronic number (2*3)
                            10: 6,  # delta = 7, not justifiable → walks to 6
                            11: 6,  # delta = 8, not justifiable → walks to 6
                            12: 9,  # delta = 9, perfect square (3^2)
                            13: 9,  # delta = 10, not justifiable → walks to 9
                            14: 9,  # delta = 11, not justifiable → walks to 9
                            15: 12,  # delta = 12, pronic number (3*4)
                            16: 12,  # delta = 13, not justifiable → walks to 12
                            17: 12,  # delta = 14, not justifiable → walks to 12
                            18: 12,  # delta = 15, not justifiable → walks to 12
                            19: 16,  # delta = 16, perfect square (4^2)
                            20: 16,  # delta = 17, not justifiable → walks to 16
                            21: 16,  # delta = 18, not justifiable → walks to 16
                            22: 16,  # delta = 19, not justifiable → walks to 16
                            23: 20,  # delta = 20, pronic number (4*5)
                            24: 20,  # delta = 21, not justifiable → walks to 20
                            25: 20,  # delta = 22, not justifiable → walks to 20
                            26: 20,  # delta = 23, not justifiable → walks to 20
                            27: 20,  # delta = 24, not justifiable → walks to 20
                            28: 25,  # delta = 25, perfect square (5^2)
                            29: 25,  # delta = 26, not justifiable → walks to 25
                            30: 25,  # delta = 27, not justifiable → walks to 25
                        }[i]
                    ),
                ),
            )
            for i in range(1, 31)
        ],
    )
