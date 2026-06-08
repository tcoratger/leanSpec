"""Tests for validator duties: attestation targets, block production, and proposal timing."""

from __future__ import annotations

import pytest

from consensus_testing.keys import XmssKeyManager
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Interval, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import AttestationSignatureEntry, Store
from lean_spec.spec.forks.lstar.config import JUSTIFICATION_LOOKBACK_SLOTS
from lean_spec.spec.forks.lstar.containers import (
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    GenesisConfig,
    SignedAttestation,
    SingleMessageAggregate,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Bytes32, Uint64
from tests.lean_spec.helpers import (
    TEST_VALIDATOR_INDEX,
    make_aggregated_proof,
    make_empty_block_body,
    make_store,
)


class TestGetAttestationTarget:
    """Tests for Store.get_attestation_target() method."""

    def test_attestation_target_at_genesis(self, spec: LstarSpec, observer_store: Store) -> None:
        """Target at genesis should be the genesis block."""
        target = spec.get_attestation_target(observer_store)

        genesis_hash = observer_store.head
        genesis_block = observer_store.blocks[genesis_hash]

        assert target.root == genesis_hash
        assert target.slot == genesis_block.slot

    def test_attestation_target_returns_checkpoint(
        self, spec: LstarSpec, observer_store: Store
    ) -> None:
        """get_attestation_target should return a Checkpoint."""
        target = spec.get_attestation_target(observer_store)

        assert isinstance(target, Checkpoint)
        assert target.root in observer_store.blocks
        assert target.slot == observer_store.blocks[target.root].slot

    def test_attestation_target_walks_back_toward_safe_target(
        self,
        observer_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Target should walk back toward safe_target when head is ahead."""
        store = observer_store

        # Build a chain of blocks to advance the head
        for slot_num in range(1, 6):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))

            store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)

        # Head has advanced (the exact slot depends on forkchoice without attestations)
        head_slot = store.blocks[store.head].slot
        assert head_slot >= Slot(1), "Head should have advanced from genesis"

        # The safe_target should still be at genesis (no attestations to advance it)
        assert store.blocks[store.safe_target].slot == Slot(0)

        # Get attestation target
        target = spec.get_attestation_target(store)

        # Target should be walked back from head toward safe_target
        # It cannot exceed JUSTIFICATION_LOOKBACK_SLOTS steps back from head
        target_slot = target.slot

        # The target should be at most JUSTIFICATION_LOOKBACK_SLOTS behind head
        assert int(target_slot) >= int(head_slot) - int(JUSTIFICATION_LOOKBACK_SLOTS)

    def test_attestation_target_respects_justifiable_slots(
        self,
        observer_store: Store,
        spec: LstarSpec,
    ) -> None:
        """Target should land on a slot that is_justifiable_after the finalized slot."""
        store = observer_store

        # Build chain to advance head significantly
        for slot_num in range(1, 10):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = spec.produce_block_with_signatures(store, slot, proposer)

        target = spec.get_attestation_target(store)
        finalized_slot = store.latest_finalized.slot

        # The target slot must be justifiable after the finalized slot
        assert target.slot.is_justifiable_after(finalized_slot)

    def test_attestation_target_ignores_stale_safe_target_below_finalized(
        self,
        observer_store: Store,
        spec: LstarSpec,
    ) -> None:
        """A stale safe target behind finalization must not pull target selection below it."""
        store = observer_store
        roots: dict[Slot, Bytes32] = {}

        for slot_num in range(1, 7):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)
            roots[slot] = hash_tree_root(block)

        finalized = Checkpoint(root=roots[Slot(4)], slot=Slot(4))
        store = store.model_copy(
            update={"latest_justified": finalized, "latest_finalized": finalized}
        )
        assert store.blocks[store.safe_target].slot == Slot(0)

        target = spec.get_attestation_target(store)

        assert target == finalized

    def test_attestation_target_walks_back_to_nearest_justifiable_slot(
        self,
        observer_store: Store,
        spec: LstarSpec,
    ) -> None:
        """A non-justifiable candidate slot must step back to the nearest justifiable one."""
        store = observer_store
        roots: dict[Slot, Bytes32] = {}

        for slot_num in range(1, 12):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)
            roots[slot] = hash_tree_root(block)

        # Fixture state: finalized and safe target at slot 0, head at slot 10.
        # The lookback walk takes 3 steps from slot 10 and lands on slot 7.
        # Distance 7 from finalization is neither <= 5, a perfect square, nor pronic.
        # Distance 6 is pronic (2 * 3), so slot 6 is the nearest justifiable slot below.
        assert store.blocks[store.head].slot == Slot(10)
        assert not Slot(7).is_justifiable_after(Slot(0))
        assert Slot(6).is_justifiable_after(Slot(0))

        target = spec.get_attestation_target(store)

        assert target == Checkpoint(root=roots[Slot(6)], slot=Slot(6))

    def test_attestation_target_uses_safe_target_when_ahead_of_finalized(
        self,
        observer_store: Store,
        spec: LstarSpec,
    ) -> None:
        """When the safe target leads finalization, it is the walk's lower bound."""
        store = observer_store
        roots: dict[Slot, Bytes32] = {}

        for slot_num in range(1, 5):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)
            roots[slot] = hash_tree_root(block)

        # Fixture state: finalized at slot 1, safe target at slot 3, head at slot 4.
        # The safe target leads finalization, so it sets the lower bound at slot 3.
        finalized = Checkpoint(root=roots[Slot(1)], slot=Slot(1))
        store = store.model_copy(
            update={
                "safe_target": roots[Slot(3)],
                "latest_justified": finalized,
                "latest_finalized": finalized,
            }
        )

        target = spec.get_attestation_target(store)

        assert target == Checkpoint(root=roots[Slot(3)], slot=Slot(3))

    def test_attestation_target_consistency_with_head(
        self, observer_store: Store, spec: LstarSpec
    ) -> None:
        """Target should be on the path from head to finalized checkpoint."""
        store = observer_store

        # Build a simple chain
        for slot_num in range(1, 4):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = spec.produce_block_with_signatures(store, slot, proposer)

        target = spec.get_attestation_target(store)

        # Walk from head back to target and verify the path exists
        current_root = store.head
        found_target = False

        while current_root in store.blocks:
            if current_root == target.root:
                found_target = True
                break
            block = store.blocks[current_root]
            if block.parent_root == Bytes32.zero():
                break
            current_root = block.parent_root

        assert found_target, "Target should be an ancestor of head"


class TestBlockProduction:
    """Test validator block production functionality."""

    def test_produce_block_basic(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test basic block production by authorized proposer."""
        slot = Slot(1)
        validator_index = ValidatorIndex(1)  # Proposer for slot 1

        store, block, _signatures = spec.produce_block_with_signatures(
            sample_store, slot, validator_index
        )
        # Verify block structure
        assert block.slot == slot
        assert block.proposer_index == validator_index
        assert block.parent_root == sample_store.head
        assert isinstance(block.body, BlockBody)
        assert block.state_root != Bytes32.zero()  # Should have computed state root

        # Verify block was added to store
        block_hash = hash_tree_root(block)
        assert block_hash in store.blocks
        assert block_hash in store.states

    def test_produce_block_unauthorized_proposer(
        self, sample_store: Store, spec: LstarSpec
    ) -> None:
        """Test block production fails for unauthorized proposer."""
        slot = Slot(1)
        wrong_validator = ValidatorIndex(2)  # Not proposer for slot 1

        with pytest.raises(AssertionError) as exception_info:
            spec.produce_block_with_signatures(sample_store, slot, wrong_validator)
        assert str(exception_info.value) == (
            f"Validator {wrong_validator} is not the proposer for slot {slot}"
        )

    def test_produce_block_with_attestations(
        self, sample_store: Store, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """Test block production includes available attestations."""
        head_block = sample_store.blocks[sample_store.head]

        # Add some attestations to the store
        head_checkpoint = Checkpoint(root=sample_store.head, slot=head_block.slot)
        data_5 = AttestationData(
            slot=head_block.slot,
            head=head_checkpoint,
            target=spec.get_attestation_target(sample_store),
            source=sample_store.latest_justified,
        )
        signed_5 = SignedAttestation(
            validator_index=ValidatorIndex(5),
            data=data_5,
            signature=key_manager.sign_attestation_data(ValidatorIndex(5), data_5),
        )
        data_6 = AttestationData(
            slot=head_block.slot,
            head=head_checkpoint,
            target=spec.get_attestation_target(sample_store),
            source=sample_store.latest_justified,
        )
        signed_6 = SignedAttestation(
            validator_index=ValidatorIndex(6),
            data=data_6,
            signature=key_manager.sign_attestation_data(ValidatorIndex(6), data_6),
        )

        proof_5 = make_aggregated_proof(key_manager, [ValidatorIndex(5)], signed_5.data)
        proof_6 = make_aggregated_proof(key_manager, [ValidatorIndex(6)], signed_6.data)

        # Build payloads keyed by attestation data.
        # If data_5 == data_6 (same slot/head/target/source), they share a key.
        known_payloads: dict[AttestationData, set[SingleMessageAggregate]] = {}
        known_payloads.setdefault(signed_5.data, set()).add(proof_5)
        known_payloads.setdefault(signed_6.data, set()).add(proof_6)

        gossip_signatures = {}
        gossip_signatures.setdefault(signed_5.data, set()).add(
            AttestationSignatureEntry(ValidatorIndex(5), signed_5.signature)
        )
        gossip_signatures.setdefault(signed_6.data, set()).add(
            AttestationSignatureEntry(ValidatorIndex(6), signed_6.signature)
        )

        sample_store = sample_store.model_copy(
            update={
                "latest_known_aggregated_payloads": known_payloads,
                "attestation_signatures": gossip_signatures,
            }
        )

        slot = Slot(2)
        validator_index = ValidatorIndex(2)  # Proposer for slot 2

        store, block, signatures = spec.produce_block_with_signatures(
            sample_store,
            slot,
            validator_index,
        )

        # Block should include the attestations we added.
        # Attestations may be aggregated, so check the count matches.
        assert len(block.body.attestations) == len(signatures)

        # Verify block structure is correct
        assert block.slot == slot
        assert block.proposer_index == validator_index
        assert block.state_root != Bytes32.zero()

        # Verify each aggregated signature proof
        for aggregate_attestation, proof in zip(
            block.body.attestations.data, signatures, strict=True
        ):
            participants = proof.participants.to_validator_indices()
            public_keys = [
                key_manager[validator_index].attestation_keypair.public_key
                for validator_index in participants
            ]
            proof.verify(
                public_keys=public_keys,
                message=hash_tree_root(aggregate_attestation.data),
                slot=aggregate_attestation.data.slot,
            )

    def test_produce_block_sequential_slots(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test producing blocks in sequential slots."""
        # Produce block for slot 1
        sample_store, block1, _signatures1 = spec.produce_block_with_signatures(
            sample_store,
            Slot(1),
            ValidatorIndex(1),
        )
        block1_hash = hash_tree_root(block1)

        # Verify first block is properly created
        assert block1.slot == Slot(1)
        assert block1.proposer_index == ValidatorIndex(1)
        assert block1_hash in sample_store.blocks
        assert block1_hash in sample_store.states

        # Without any attestations, the forkchoice will stay on genesis
        # This is the expected behavior: block1 exists but isn't the head
        # So block2 should build on genesis, not block1

        # Produce block for slot 2 (will build on genesis due to forkchoice)
        sample_store, block2, _signatures2 = spec.produce_block_with_signatures(
            sample_store,
            Slot(2),
            ValidatorIndex(2),
        )

        # Verify block properties
        assert block2.slot == Slot(2)
        assert block2.proposer_index == ValidatorIndex(2)

        # The parent should be genesis (the current head), not block1
        genesis_hash = sample_store.head
        assert block2.parent_root == genesis_hash

        # Both blocks should exist in the store
        block2_hash = hash_tree_root(block2)
        assert block1_hash in sample_store.blocks
        assert block2_hash in sample_store.blocks
        assert genesis_hash in sample_store.blocks

    def test_produce_block_empty_attestations(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test block production with no available attestations."""
        slot = Slot(3)
        validator_index = ValidatorIndex(3)

        # Ensure no attestations in store (clear aggregated payloads)
        sample_store = sample_store.model_copy(update={"latest_known_aggregated_payloads": {}})

        store, block, _signatures = spec.produce_block_with_signatures(
            sample_store,
            slot,
            validator_index,
        )

        # Should produce valid block with empty attestations
        assert len(block.body.attestations) == 0
        assert block.slot == slot
        assert block.proposer_index == validator_index
        assert block.state_root != Bytes32.zero()

    def test_produce_block_state_consistency(
        self, sample_store: Store, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """Test that produced block's state is consistent with block content."""
        slot = Slot(4)
        validator_index = ValidatorIndex(4)

        # Add some attestations to test state computation
        head_block = sample_store.blocks[sample_store.head]
        head_checkpoint = Checkpoint(root=sample_store.head, slot=head_block.slot)
        data_7 = AttestationData(
            slot=head_block.slot,
            head=head_checkpoint,
            target=spec.get_attestation_target(sample_store),
            source=sample_store.latest_justified,
        )
        signed_7 = SignedAttestation(
            validator_index=ValidatorIndex(7),
            data=data_7,
            signature=key_manager.sign_attestation_data(ValidatorIndex(7), data_7),
        )

        proof_7 = make_aggregated_proof(key_manager, [ValidatorIndex(7)], signed_7.data)

        sample_store = sample_store.model_copy(
            update={
                "latest_known_aggregated_payloads": {signed_7.data: {proof_7}},
                "attestation_signatures": {
                    signed_7.data: {
                        AttestationSignatureEntry(ValidatorIndex(7), signed_7.signature)
                    },
                },
            }
        )

        store, block, signatures = spec.produce_block_with_signatures(
            sample_store,
            slot,
            validator_index,
        )
        block_hash = hash_tree_root(block)

        # Verify the stored state matches the block's state root
        stored_state = store.states[block_hash]
        assert hash_tree_root(stored_state) == block.state_root

        # Verify each aggregated proof binds to its attestation in the block.
        for aggregate_attestation, proof in zip(
            block.body.attestations.data, signatures, strict=True
        ):
            participants = proof.participants.to_validator_indices()
            public_keys = [
                key_manager[validator_index].attestation_keypair.public_key
                for validator_index in participants
            ]
            proof.verify(
                public_keys=public_keys,
                message=hash_tree_root(aggregate_attestation.data),
                slot=aggregate_attestation.data.slot,
            )


class TestValidatorIntegration:
    """Test integration between block production and attestations."""

    def test_block_production_then_attestation(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test producing a block then creating attestation for it."""
        # Proposer produces block for slot 1
        proposer_slot = Slot(1)
        proposer_index = ValidatorIndex(1)
        spec.produce_block_with_signatures(sample_store, proposer_slot, proposer_index)

        # Update store state after block production
        sample_store = spec.update_head(sample_store)

        # Other validator creates attestation for slot 2
        attestor_slot = Slot(2)
        attestor_index = ValidatorIndex(7)
        attestation_data = spec.produce_attestation_data(sample_store, attestor_slot)
        attestation = Attestation(validator_index=attestor_index, data=attestation_data)

        # Attestation should reference the new block as head (if it became head)
        assert attestation.validator_index == attestor_index
        assert attestation.data.slot == attestor_slot

        # The attestation should be consistent with current forkchoice state
        assert attestation.data.source == sample_store.latest_justified

    def test_multiple_validators_coordination(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test multiple validators producing blocks and attestations."""
        # Validator 1 produces block for slot 1
        sample_store, block1, _signatures1 = spec.produce_block_with_signatures(
            sample_store,
            Slot(1),
            ValidatorIndex(1),
        )
        block1_hash = hash_tree_root(block1)

        # Validators 2-5 create attestations for slot 2
        # These will be based on the current forkchoice head (genesis)
        attestations = []
        for i in range(2, 6):
            attestation_data = spec.produce_attestation_data(sample_store, Slot(2))
            attestation = Attestation(validator_index=ValidatorIndex(i), data=attestation_data)
            attestations.append(attestation)

        # All attestations should be consistent
        first_attestation = attestations[0]
        for attestation in attestations[1:]:
            assert attestation.data.head.root == first_attestation.data.head.root
            assert attestation.data.target.root == first_attestation.data.target.root
            assert attestation.data.source.root == first_attestation.data.source.root

        # Validator 2 produces next block for slot 2
        # After processing block1, head should be block1 (fork choice walks the tree)
        # So block2 will build on block1
        sample_store, block2, _signatures2 = spec.produce_block_with_signatures(
            sample_store,
            Slot(2),
            ValidatorIndex(2),
        )

        # Verify block properties
        assert block2.slot == Slot(2)
        assert block2.proposer_index == ValidatorIndex(2)

        # Both blocks should exist in the store
        block2_hash = hash_tree_root(block2)
        assert block1_hash in sample_store.blocks
        assert block2_hash in sample_store.blocks

        # block1 builds on genesis, block2 builds on block1 (current head)
        # Get the original genesis hash from the store's blocks
        genesis_hash = min(
            (
                root
                for root in sample_store.blocks.keys()
                if sample_store.blocks[root].slot == Slot(0)
            ),
            key=lambda root: root,
        )
        assert block1.parent_root == genesis_hash
        assert block2.parent_root == block1_hash

    def test_validator_edge_cases(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test edge cases in validator operations."""
        # Test with validator index equal to number of validators - 1
        max_validator = ValidatorIndex(7)  # Last validator (0-indexed, 8 total)
        slot = Slot(7)  # This validator's slot

        # Should be able to produce block
        store, block, _signatures = spec.produce_block_with_signatures(
            sample_store,
            slot,
            max_validator,
        )
        assert block.proposer_index == max_validator

        # Should be able to produce attestation
        attestation_data = spec.produce_attestation_data(sample_store, Slot(10))
        attestation = Attestation(validator_index=max_validator, data=attestation_data)
        assert attestation.validator_index == max_validator

    def test_validator_operations_empty_store(self, spec: LstarSpec) -> None:
        """Test validator operations with minimal store state."""
        store = make_store(num_validators=3)

        # Should be able to produce block and attestation
        store, block, _signatures = spec.produce_block_with_signatures(
            store,
            Slot(1),
            ValidatorIndex(1),
        )
        attestation_data = spec.produce_attestation_data(store, Slot(1))
        attestation = Attestation(validator_index=ValidatorIndex(2), data=attestation_data)

        assert isinstance(block, Block)
        assert isinstance(attestation, Attestation)


class TestValidatorErrorHandling:
    """Test error handling in validator operations."""

    def test_produce_block_wrong_proposer(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test error when wrong validator tries to produce block."""
        slot = Slot(5)
        wrong_proposer = ValidatorIndex(3)  # Should be validator 5 for slot 5

        with pytest.raises(AssertionError) as exc_info:
            spec.produce_block_with_signatures(sample_store, slot, wrong_proposer)

        assert "is not the proposer for slot" in str(exc_info.value)

    def test_produce_block_missing_parent_state(self, spec: LstarSpec) -> None:
        """Test error when parent state is missing."""
        config = GenesisConfig(genesis_time=Uint64(1000))
        checkpoint = Checkpoint(root=Bytes32(b"missing" + b"\x00" * 25), slot=Slot(0))

        # Create store with missing parent state
        store = Store(
            time=Interval(100),
            config=config,
            head=Bytes32(b"nonexistent" + b"\x00" * 21),
            safe_target=Bytes32(b"nonexistent" + b"\x00" * 21),
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            blocks={},  # No blocks
            states={},  # No states
            validator_index=TEST_VALIDATOR_INDEX,
        )

        # The forkchoice head walk asserts that the justified root is known.
        # Calling produce_block on a store whose latest_justified.root is
        # missing from blocks must fail loudly with that invariant message.
        with pytest.raises(AssertionError) as exception_info:
            spec.produce_block_with_signatures(store, Slot(1), ValidatorIndex(1))
        assert str(exception_info.value) == (
            f"start_root {checkpoint.root.hex()} not in store.blocks"
        )

    def test_validator_operations_invalid_parameters(
        self, sample_store: Store, spec: LstarSpec
    ) -> None:
        """Test validator operations with invalid parameters."""
        # Very large validator index (should work mathematically)
        large_validator = ValidatorIndex(1000000)
        large_slot = Slot(1000000)

        # Get the state to determine number of validators
        genesis_hash = sample_store.head
        state = sample_store.states[genesis_hash]
        num_validators = len(state.validators)

        # Proposer comparison should work (though likely not match).
        is_proposer = large_validator == ValidatorIndex.proposer_for_slot(
            large_slot, Uint64(num_validators)
        )
        assert isinstance(is_proposer, bool)

        # Attestation can be created for any validator
        attestation_data = spec.produce_attestation_data(sample_store, Slot(1))
        attestation = Attestation(validator_index=large_validator, data=attestation_data)
        assert attestation.validator_index == large_validator


class TestProposalHeadTiming:
    """Test proposal head timing logic."""

    def test_get_proposal_head_basic(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test getting proposal head for a slot."""
        # Add a block to make the test more realistic
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=make_empty_block_body(),
        )
        genesis_hash = hash_tree_root(genesis_block)

        # Use immutable update to add block
        new_blocks = dict(sample_store.blocks)
        new_blocks[genesis_hash] = genesis_block
        sample_store = sample_store.model_copy(update={"blocks": new_blocks, "head": genesis_hash})

        # Get proposal head for slot 0
        store, head = spec.get_proposal_head(sample_store, Slot(0))

        # Should return the store's head
        assert head == store.head

    def test_get_proposal_head_advances_time(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test that get_proposal_head advances store time appropriately."""
        initial_time = sample_store.time

        # Get proposal head for a future slot
        future_slot = Slot(5)
        store, _ = spec.get_proposal_head(sample_store, future_slot)

        # Time may have advanced (depending on slot timing)
        # This is mainly testing that the call doesn't fail
        assert store.time >= initial_time

    def test_get_proposal_head_processes_attestations(
        self, sample_store: Store, spec: LstarSpec
    ) -> None:
        """Test that get_proposal_head processes pending aggregated payloads."""
        # Attestations are now tracked via aggregated payloads
        # Test simplified to verify the method runs correctly
        store, head = spec.get_proposal_head(sample_store, Slot(1))

        # get_proposal_head should have called accept_new_attestations
        # which migrates new payloads to known payloads
        assert len(store.latest_new_aggregated_payloads) == 0
