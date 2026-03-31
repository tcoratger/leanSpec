"""Attestation Source Divergence"""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    AttestationStep,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAttestationSpec,
    StoreChecks,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_gossip_attestation_accepted_after_fork_advances_justified(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Gossip attestation is valid when the global justified diverges from head.

    Scenario
    --------
    Four validators. The chain forks at slot 1::

        genesis ── slot 1 ("common") ─┬── slot 2 ── slot 3  (head, V0 weight)
                                      └── slot 4            (fork, V1+V2+V3 justify "common")

    The fork block carries attestations from 3 of 4 validators for the fork
    point. This crosses the 2/3 threshold and advances the store-wide justified
    checkpoint to slot 1.

    The head chain has not seen those votes, so its state still holds the
    genesis justified checkpoint (slot 0). After the fork is processed:

    - Store-wide justified: slot 1
    - Head state justified: slot 0

    A gossip attestation is then produced at slot 5. The attestation target
    walks back 3 slots from head (slot 3) and lands on genesis (slot 0).

    The source must come from the head state (slot 0) so that the
    monotonicity invariant holds (source.slot <= target.slot). Using the
    store-wide value (slot 1) would violate it and be rejected.
    """
    fork_choice_test(
        steps=[
            # Common ancestor — the fork point for both chains.
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            # Main chain, first extension.
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="common", label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            # Main chain, second extension.
            # V0 attests for block_2, giving this branch LMD-GHOST weight
            # so that it stays head after the fork block arrives.
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="block_2",
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            # Minority fork. V1, V2, V3 attest for the fork point.
            # 3 of 4 validators cross the 2/3 threshold, advancing the
            # store-wide justified checkpoint to slot 1. Head stays on
            # the main chain thanks to V0's weight.
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="common",
                    label="fork_block",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                                ValidatorIndex(3),
                            ],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="common",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="common",
                ),
            ),
            # Gossip attestation from V3 at slot 5.
            #
            # This exercises the attestation production code path.
            # The target walks back to genesis (slot 0). The source must
            # be slot 0 (head state) so that source <= target holds.
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(3),
                    slot=Slot(5),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                ),
            ),
        ],
    )
