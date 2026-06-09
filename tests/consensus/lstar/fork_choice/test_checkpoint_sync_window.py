"""Checkpoint sync: justifiability window and embedded-checkpoint normalization."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
    TickStep,
    build_anchor,
)
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.config import SECONDS_PER_SLOT

pytestmark = pytest.mark.valid_until("Lstar")


ANCHOR_SLOT = Slot(10)
"""Slot at which every test in this module places the trust anchor."""

NUM_VALIDATORS = 4
"""Validator count. Three-of-four reaches the 2/3 justification threshold."""


def test_post_anchor_vote_follows_embedded_finalized_window(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A post-anchor target stays unjustified because the window follows the state slot.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the store is seeded from a mid-chain anchor at slot 10.
    - the anchor state carries an embedded finalized slot of 0 from genesis.
    - the store pins justified and finalized to the anchor slot 10.
    - the chain:
        anchor(10) -> target_11(11) -> voter_12(12)
    - voter_12 includes V0, V1, V2's votes for target_11.
    - target_11 sits one slot above the anchor, a delta of 1 from slot 10.
    - target_11 sits eleven slots above the embedded finalized slot 0.
    - the votes name the anchor as their source.

    When
    ----
    - the vote that would justify target_11 is imported in voter_12.

    Then
    ----
    - target_11 is justifiable only when measured from the anchor slot 10.
    - target_11 is not justifiable when measured from the embedded finalized slot 0.
    - the state transition measures from the embedded slot, so the vote is ignored.
    - justified stays pinned to the anchor at slot 10.
    - finalized stays pinned to the anchor at slot 10.

    Window
    ------
    - the justifiability window is measured from the state's embedded finalized slot.
    - checkpoint sync does not rebase that window onto the anchor slot.
    """
    anchor_state, anchor_block = build_anchor(
        num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=anchor_block,
        steps=[
            BlockStep(
                block=BlockSpec(
                    slot=Slot(11),
                    parent_label="genesis",
                    label="target_11",
                ),
                checks=StoreChecks(
                    head_slot=Slot(11),
                    head_root_label="target_11",
                    latest_justified_slot=ANCHOR_SLOT,
                    latest_finalized_slot=ANCHOR_SLOT,
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(12),
                    parent_label="target_11",
                    label="voter_12",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(12),
                            target_slot=Slot(11),
                            target_root_label="target_11",
                            source_root_label="genesis",
                            source_slot=ANCHOR_SLOT,
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(12),
                    head_root_label="voter_12",
                    latest_justified_slot=ANCHOR_SLOT,
                    latest_justified_root_label="genesis",
                    latest_finalized_slot=ANCHOR_SLOT,
                    latest_finalized_root_label="genesis",
                ),
            ),
        ],
    )


def test_anchor_above_block_slot_is_normalized_to_block_slot(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Embedded checkpoints above the anchor block slot are normalized down to it.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - a mid-chain anchor at slot 10 built by the helper.
    - the anchor state is rewritten so its embedded justified slot is 20.
    - the anchor state is rewritten so its embedded finalized slot is 20.
    - both embedded checkpoints now sit above the anchor block slot 10.

    When
    ----
    - the store is seeded from this anchor and the clock ticks to slot 10.

    Then
    ----
    - the store does not reject the above-block-slot checkpoints.
    - the store silently overrides justified to the anchor block at slot 10.
    - the store silently overrides finalized to the anchor block at slot 10.
    - head is the anchor block at slot 10.

    Behavior
    --------
    - store seeding pins both checkpoints to the anchor block slot.
    - it ignores the embedded checkpoint slots, even when they sit above the block.
    - whether to reject this inconsistency instead is a spec decision to confirm.
    """
    anchor_state, anchor_block = build_anchor(
        num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    anchor_root = hash_tree_root(anchor_block)
    above_block_slot = Checkpoint(root=anchor_root, slot=Slot(20))
    anchor_state = anchor_state.model_copy(
        update={
            "latest_justified": above_block_slot,
            "latest_finalized": above_block_slot,
        }
    )

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=anchor_block,
        steps=[
            TickStep(
                time=int(ANCHOR_SLOT) * int(SECONDS_PER_SLOT),
                checks=StoreChecks(
                    head_slot=ANCHOR_SLOT,
                    head_root_label="genesis",
                    latest_justified_slot=ANCHOR_SLOT,
                    latest_justified_root_label="genesis",
                    latest_finalized_slot=ANCHOR_SLOT,
                    latest_finalized_root_label="genesis",
                ),
            ),
        ],
    )
