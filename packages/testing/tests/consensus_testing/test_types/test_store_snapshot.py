"""Tests for the canonical store snapshot emitted after every fork choice step."""

from __future__ import annotations

from consensus_testing.genesis import make_genesis_store
from consensus_testing.keys import create_dummy_signature
from consensus_testing.test_types.store_snapshot import (
    AggregatedPoolEntry,
    AttestationPoolEntry,
    BlockWeightEntry,
    StoreSnapshot,
)
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Interval, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregationBits,
    AttestationData,
    SingleMessageAggregate,
)
from lean_spec.spec.forks.lstar.containers.store import AttestationSignatureEntry
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import ByteList512KiB, Uint64


class TestStoreSnapshotFromStore:
    """Tests for capturing the canonical observables of a store."""

    def test_from_store_pins_ordering_and_finalized_slot_boundary(self) -> None:
        """Whole snapshot matches an explicit expected, pinning sorts and the strict cutoff."""
        # Build a real chain genesis(0) <- one(1) <- two(2) over four validators.
        # The genesis store finalizes the genesis block at slot 0.
        fork = LstarSpec()
        store = make_genesis_store(num_validators=4, keyed=False)
        genesis_root = next(iter(store.blocks))
        genesis_state = store.states[genesis_root]
        validator_count = Uint64(4)

        block_one, state_one, _, _ = fork.build_block(
            genesis_state,
            slot=Slot(1),
            proposer_index=ValidatorIndex.proposer_for_slot(Slot(1), validator_count),
            parent_root=genesis_root,
            known_block_roots={genesis_root},
        )
        root_one = hash_tree_root(block_one)
        block_two, state_two, _, _ = fork.build_block(
            state_one,
            slot=Slot(2),
            proposer_index=ValidatorIndex.proposer_for_slot(Slot(2), validator_count),
            parent_root=root_one,
            known_block_roots={genesis_root, root_one},
        )
        root_two = hash_tree_root(block_two)

        # Two distinct votes drive both fork-choice weight and pool coverage.
        # Vote on two: validators 0, 1, 3 name the slot-2 head.
        # Vote on one: validator 2 names the slot-1 head.
        genesis_checkpoint = Checkpoint(root=genesis_root, slot=Slot(0))
        checkpoint_one = Checkpoint(root=root_one, slot=Slot(1))
        checkpoint_two = Checkpoint(root=root_two, slot=Slot(2))
        vote_on_two = AttestationData(
            slot=Slot(2),
            head=checkpoint_two,
            target=checkpoint_two,
            source=genesis_checkpoint,
        )
        vote_on_one = AttestationData(
            slot=Slot(1),
            head=checkpoint_one,
            target=checkpoint_one,
            source=genesis_checkpoint,
        )

        # Two payloads back the slot-2 vote, inserted high-set-first to force the nested sort.
        payload_two_singleton = SingleMessageAggregate(
            participants=AggregationBits.from_indices([ValidatorIndex(3)]),
            proof=ByteList512KiB(data=b"\xaa"),
        )
        payload_two_pair = SingleMessageAggregate(
            participants=AggregationBits.from_indices([ValidatorIndex(0), ValidatorIndex(1)]),
            proof=ByteList512KiB(data=b"\xbb"),
        )
        payload_one = SingleMessageAggregate(
            participants=AggregationBits.from_indices([ValidatorIndex(2)]),
            proof=ByteList512KiB(data=b"\xcc"),
        )
        payload_one_new = SingleMessageAggregate(
            participants=AggregationBits.from_indices([ValidatorIndex(1)]),
            proof=ByteList512KiB(data=b"\xdd"),
        )

        populated_store = store.model_copy(
            update={
                "blocks": {**store.blocks, root_one: block_one, root_two: block_two},
                "states": {**store.states, root_one: state_one, root_two: state_two},
                "head": root_two,
                "safe_target": root_one,
                "latest_known_aggregated_payloads": {
                    vote_on_two: {payload_two_singleton, payload_two_pair},
                    vote_on_one: {payload_one},
                },
                "latest_new_aggregated_payloads": {vote_on_one: {payload_one_new}},
                "attestation_signatures": {
                    vote_on_two: {
                        AttestationSignatureEntry(ValidatorIndex(2), create_dummy_signature()),
                        AttestationSignatureEntry(ValidatorIndex(0), create_dummy_signature()),
                    },
                },
            }
        )

        captured_snapshot = StoreSnapshot.from_store(populated_store)

        # Fixture state: data roots fix the pool ordering, block roots fix the weight ordering.
        vote_on_one_data_root = hash_tree_root(vote_on_one)
        vote_on_two_data_root = hash_tree_root(vote_on_two)
        block_roots_ascending = sorted([genesis_root, root_one, root_two])

        # Weight on two: votes from validators 0, 1, 3 land on the slot-2 head.
        # Weight on one: those three flow down to its ancestor plus validator 2's own vote.
        # The genesis block sits exactly at the finalized slot, so the strict cutoff drops it.
        expected_snapshot = StoreSnapshot(
            time=Interval.from_slot(Slot(0)),
            head_root=root_two,
            safe_target_root=root_one,
            latest_justified=Checkpoint(root=genesis_root, slot=Slot(0)),
            latest_finalized=Checkpoint(root=genesis_root, slot=Slot(0)),
            block_roots=block_roots_ascending,
            block_weights=sorted(
                [
                    BlockWeightEntry(root=root_two, weight=3),
                    BlockWeightEntry(root=root_one, weight=4),
                ],
                key=lambda block_weight: block_weight.root,
            ),
            attestation_signatures=[
                AttestationPoolEntry(data_root=vote_on_two_data_root, validator_indices=[0, 2]),
            ],
            new_aggregated_payloads=[
                AggregatedPoolEntry(data_root=vote_on_one_data_root, participant_sets=[[1]]),
            ],
            known_aggregated_payloads=sorted(
                [
                    AggregatedPoolEntry(data_root=vote_on_one_data_root, participant_sets=[[2]]),
                    AggregatedPoolEntry(
                        data_root=vote_on_two_data_root, participant_sets=[[0, 1], [3]]
                    ),
                ],
                key=lambda pool_entry: pool_entry.data_root,
            ),
        )

        assert captured_snapshot == expected_snapshot

    def test_from_store_excludes_block_exactly_at_finalized_slot(self) -> None:
        """A block whose slot equals the finalized slot stays out of the weight list."""
        # The genesis block lives at slot 0, exactly the finalized slot of a genesis store.
        store = make_genesis_store(num_validators=4, keyed=False)
        genesis_root = next(iter(store.blocks))

        captured_snapshot = StoreSnapshot.from_store(store)

        # Membership still records the genesis block, so pruning behavior stays visible.
        assert captured_snapshot.block_roots == [genesis_root]
        # The strict cutoff keeps the at-boundary block out of fork-choice weights.
        assert captured_snapshot.block_weights == []
