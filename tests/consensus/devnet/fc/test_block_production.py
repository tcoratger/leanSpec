"""Fork Choice: Block Production — Fixed-Point Justification Loop

The block builder in ``State.build_block`` uses a fixed-point loop to select
attestation data from the store's aggregated payloads. Only entries whose
``source`` matches the *current* justified checkpoint are eligible. When
processing selected attestations justifies a new slot, the loop repeats and
entries that were previously ineligible may now match.

No existing spec test filler exercises this multi-pass behavior through the
fork-choice block-production path.

Reference: https://github.com/leanEthereum/leanSpec/issues/564
"""

import pytest
from consensus_testing import (
    AggregatedAttestationCheck,
    AggregatedAttestationSpec,
    AttestationCheck,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationSpec,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_block_builder_fixed_point_advances_justification(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Fixed-point loop: justification from attestation A unlocks attestation B.

    Scenario
    --------
    Four validators. Linear chain through slot 4::

        genesis(0) -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4)

    At slot 3 a supermajority attestation justifies slot 1, setting the
    baseline for the fixed-point test.

    Then two aggregated attestations are submitted via gossip:

    - Attestation A: source=slot 1 (block_1), target=slot 2 (block_2)
      Validators {0, 1, 2} — supermajority with 4 validators.
    - Attestation B: source=slot 2 (block_2), target=slot 4 (block_4)
      Validators {1, 2, 3} — supermajority, but source slot 2 is NOT
      justified when the builder starts.

    Delivery mechanism: ``GossipAggregatedAttestationStep`` puts payloads
    into ``latest_new_aggregated_payloads``.  A ``TickStep`` advances time
    past interval 4 of the slot, triggering ``accept_new_attestations``
    which migrates the payloads to ``latest_known_aggregated_payloads``.
    The subsequent ``BlockStep`` at slot 5 calls
    ``build_signed_block_with_store`` which passes
    ``latest_known_aggregated_payloads`` to ``State.build_block``.

    A bare ``BlockStep`` at slot 5 (no ``attestations`` field) triggers
    block production.

    Fixed-point behavior inside ``build_block``:

    1. Pass 1 — current_justified = slot 1.
       A matches (source=1 == current_justified). Selected.
       Candidate STF processes A → justifies slot 2, finalizes slot 1.
       current_justified advances to slot 2. Loop continues.
    2. Pass 2 — current_justified = slot 2.
       B matches (source=2 == current_justified). Selected.
       Candidate STF processes B → justifies slot 4.
       current_justified advances to slot 4. Loop continues.
    3. Pass 3 — no new matching entries. Break.

    Post-state assertions:

    - ``latest_justified_slot = 4`` (B's target).
    - ``latest_finalized_slot = 1`` (A justifies slot 2 with source=1;
      no gap between 1 and 2 → finalizes slot 1.  B does NOT advance
      finalization because slot 3, at delta=2 from finalized_slot=1, is
      justifiable (pronic: 1×2) and creates a gap.)
    - The block body contains two distinct aggregated attestations matching
      the participant sets of A and B.

    Why ``GossipAggregatedAttestationStep`` with tick-based migration:

    ``AggregatedAttestationSpec`` derives ``source`` from the parent
    state's ``latest_justified``, so both A and B would receive the same
    source and the fixed-point loop would never be exercised.  Raw gossip
    via ``AttestationStep`` is validated but not stored (non-aggregator).
    ``GossipAggregatedAttestationStep`` stores proofs in
    ``latest_new_aggregated_payloads``; a tick to interval 4 migrates them
    to ``latest_known_aggregated_payloads`` where ``build_block`` reads
    them, avoiding the ``aggregate()`` lone-proof drop.
    """
    fork_choice_test(
        steps=[
            # ── Build linear chain ────────────────────────────────────
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            # Justify slot 1: supermajority (3/4) attestation in-block.
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(3),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="block_1",
                    latest_finalized_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), label="block_4"),
                checks=StoreChecks(head_slot=Slot(4)),
            ),
            # ── Tick past aggregate interval ──────────────────────────
            # Store is at interval 20 (slot 4, interval 0).
            # Tick to 18s = interval 22 (slot 4, interval 2).
            # This passes through the aggregate interval (22 % 5 = 2)
            # while latest_new_aggregated_payloads is still empty,
            # so nothing gets dropped.
            TickStep(time=18),
            # ── Gossip aggregated attestation A: source=1, target=2 ──
            # Validators {0, 1, 2}. Immediately selectable by the
            # builder because current_justified = slot 1.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(5),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="block_1",
                    source_slot=Slot(1),
                ),
            ),
            # ── Gossip aggregated attestation B: source=2, target=4 ──
            # Validators {1, 2, 3}. Source slot 2 is NOT yet justified;
            # only unlocked after A's supermajority justifies slot 2.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(5),
                    target_slot=Slot(4),
                    target_root_label="block_4",
                    source_root_label="block_2",
                    source_slot=Slot(2),
                ),
            ),
            # ── Tick to accept new attestations ───────────────────────
            # Tick from interval 22 to interval 25 (= 20s with
            # genesis_time=0). This passes through interval 24
            # (slot 4, interval 4) which triggers
            # accept_new_attestations(), migrating A and B from
            # latest_new_aggregated_payloads to
            # latest_known_aggregated_payloads.
            TickStep(
                time=20,
                checks=StoreChecks(
                    latest_justified_slot=Slot(1),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="known",
                            source_slot=Slot(1),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            location="known",
                            source_slot=Slot(2),
                            target_slot=Slot(4),
                        ),
                    ],
                ),
            ),
            # ── Produce block at slot 5 ───────────────────────────────
            # No explicit attestations — the builder picks up the
            # already-known aggregated payloads in build_block.
            BlockStep(
                block=BlockSpec(slot=Slot(5), label="block_5"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    latest_justified_slot=Slot(4),
                    latest_justified_root_label="block_4",
                    latest_finalized_slot=Slot(1),
                    latest_finalized_root_label="block_1",
                    block_attestation_count=2,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={0, 1, 2},
                            target_slot=Slot(2),
                        ),
                        AggregatedAttestationCheck(
                            participants={1, 2, 3},
                            target_slot=Slot(4),
                        ),
                    ],
                ),
            ),
        ],
    )
