"""Tests for Store attestation data pruning."""

from lean_spec.subspecs.containers import (
    AttestationData,
    Block,
    BlockBody,
    Checkpoint,
    State,
)
from lean_spec.subspecs.containers.attestation import AggregationBits
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.validator import Validator, ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof, SignatureKey
from lean_spec.types import Bytes32, Bytes52, Uint64
from lean_spec.types.byte_arrays import ByteListMiB
from tests.lean_spec.helpers import TEST_VALIDATOR_ID, make_mock_signature


def _make_attestation_data(
    slot: Slot,
    target_slot: Slot,
    target_root: Bytes32,
    source_slot: Slot,
    source_root: Bytes32,
) -> AttestationData:
    """Create attestation data with specific target and source checkpoints."""
    return AttestationData(
        slot=slot,
        head=Checkpoint(root=target_root, slot=target_slot),
        target=Checkpoint(root=target_root, slot=target_slot),
        source=Checkpoint(root=source_root, slot=source_slot),
    )


def _create_test_store() -> tuple[Store, Block, State]:
    """Create a basic store with genesis state for testing."""
    validators = Validators(
        data=[
            Validator(
                pubkey=Bytes52(b"\x00" * 52),
                index=ValidatorIndex(i),
            )
            for i in range(3)
        ]
    )
    genesis_state = State.generate_genesis(genesis_time=Uint64(0), validators=validators)
    genesis_block = Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    store = Store.get_forkchoice_store(
        genesis_state,
        genesis_block,
        validator_id=TEST_VALIDATOR_ID,
    )
    return store, genesis_block, genesis_state


def test_prunes_entries_with_target_at_finalized() -> None:
    """Verify entries with target.slot == finalized slot are pruned."""
    store, _, _ = _create_test_store()

    # Create attestation data with target.slot == 5
    attestation_data = _make_attestation_data(
        slot=Slot(5),
        target_slot=Slot(5),
        target_root=Bytes32(b"\x01" * 32),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )
    data_root = attestation_data.data_root_bytes()
    sig_key = SignatureKey(ValidatorIndex(1), data_root)

    # Set up store with attestation data and finalized slot at 5
    store = store.model_copy(
        update={
            "attestation_data_by_root": {data_root: attestation_data},
            "gossip_signatures": {sig_key: make_mock_signature()},
            "latest_finalized": Checkpoint(root=Bytes32(b"\xff" * 32), slot=Slot(5)),
        }
    )

    # Verify data exists before pruning
    assert data_root in store.attestation_data_by_root
    assert sig_key in store.gossip_signatures

    # Prune should remove entries where target.slot <= finalized.slot
    pruned_store = store.prune_stale_attestation_data()

    assert data_root not in pruned_store.attestation_data_by_root
    assert sig_key not in pruned_store.gossip_signatures


def test_prunes_entries_with_target_before_finalized() -> None:
    """Verify entries with target.slot < finalized slot are pruned."""
    store, _, _ = _create_test_store()

    # Create attestation data with target.slot == 3
    attestation_data = _make_attestation_data(
        slot=Slot(3),
        target_slot=Slot(3),
        target_root=Bytes32(b"\x01" * 32),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )
    data_root = attestation_data.data_root_bytes()
    sig_key = SignatureKey(ValidatorIndex(1), data_root)

    # Set up store with finalized slot at 5 (greater than target.slot)
    store = store.model_copy(
        update={
            "attestation_data_by_root": {data_root: attestation_data},
            "gossip_signatures": {sig_key: make_mock_signature()},
            "latest_finalized": Checkpoint(root=Bytes32(b"\xff" * 32), slot=Slot(5)),
        }
    )

    # Verify data exists before pruning
    assert data_root in store.attestation_data_by_root
    assert sig_key in store.gossip_signatures

    # Prune should remove entries where target.slot <= finalized.slot
    pruned_store = store.prune_stale_attestation_data()

    assert data_root not in pruned_store.attestation_data_by_root
    assert sig_key not in pruned_store.gossip_signatures


def test_keeps_entries_with_target_after_finalized() -> None:
    """Verify entries with target.slot > finalized slot are kept."""
    store, _, _ = _create_test_store()

    # Create attestation data with target.slot == 10
    attestation_data = _make_attestation_data(
        slot=Slot(10),
        target_slot=Slot(10),
        target_root=Bytes32(b"\x01" * 32),
        source_slot=Slot(5),
        source_root=Bytes32(b"\x02" * 32),
    )
    data_root = attestation_data.data_root_bytes()
    sig_key = SignatureKey(ValidatorIndex(1), data_root)

    # Set up store with finalized slot at 5 (less than target.slot)
    store = store.model_copy(
        update={
            "attestation_data_by_root": {data_root: attestation_data},
            "gossip_signatures": {sig_key: make_mock_signature()},
            "latest_finalized": Checkpoint(root=Bytes32(b"\xff" * 32), slot=Slot(5)),
        }
    )

    # Verify data exists before pruning
    assert data_root in store.attestation_data_by_root
    assert sig_key in store.gossip_signatures

    # Prune should keep entries where target.slot > finalized.slot
    pruned_store = store.prune_stale_attestation_data()

    assert data_root in pruned_store.attestation_data_by_root
    assert sig_key in pruned_store.gossip_signatures
    assert pruned_store.attestation_data_by_root[data_root] == attestation_data


def test_prunes_related_structures_together() -> None:
    """Verify all four data structures are pruned atomically."""
    store, _, _ = _create_test_store()

    # Create stale attestation data
    stale_attestation = _make_attestation_data(
        slot=Slot(3),
        target_slot=Slot(3),
        target_root=Bytes32(b"\x01" * 32),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )
    stale_root = stale_attestation.data_root_bytes()
    stale_key = SignatureKey(ValidatorIndex(1), stale_root)

    # Create fresh attestation data
    fresh_attestation = _make_attestation_data(
        slot=Slot(10),
        target_slot=Slot(10),
        target_root=Bytes32(b"\x02" * 32),
        source_slot=Slot(5),
        source_root=Bytes32(b"\xff" * 32),
    )
    fresh_root = fresh_attestation.data_root_bytes()
    fresh_key = SignatureKey(ValidatorIndex(2), fresh_root)

    # Create mock aggregated proof (empty proof data for testing)
    mock_proof = AggregatedSignatureProof(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(1)]),
        proof_data=ByteListMiB(data=b""),
    )

    # Set up store with both stale and fresh entries in all structures
    store = store.model_copy(
        update={
            "attestation_data_by_root": {
                stale_root: stale_attestation,
                fresh_root: fresh_attestation,
            },
            "gossip_signatures": {
                stale_key: make_mock_signature(),
                fresh_key: make_mock_signature(),
            },
            "latest_new_aggregated_payloads": {
                stale_key: [mock_proof],
                fresh_key: [mock_proof],
            },
            "latest_known_aggregated_payloads": {
                stale_key: [mock_proof],
                fresh_key: [mock_proof],
            },
            "latest_finalized": Checkpoint(root=Bytes32(b"\xff" * 32), slot=Slot(5)),
        }
    )

    # Verify all data exists before pruning
    assert stale_root in store.attestation_data_by_root
    assert stale_key in store.gossip_signatures
    assert stale_key in store.latest_new_aggregated_payloads
    assert stale_key in store.latest_known_aggregated_payloads
    assert fresh_root in store.attestation_data_by_root
    assert fresh_key in store.gossip_signatures
    assert fresh_key in store.latest_new_aggregated_payloads
    assert fresh_key in store.latest_known_aggregated_payloads

    pruned_store = store.prune_stale_attestation_data()

    # Stale entries should be removed from all structures
    assert stale_root not in pruned_store.attestation_data_by_root
    assert stale_key not in pruned_store.gossip_signatures
    assert stale_key not in pruned_store.latest_new_aggregated_payloads
    assert stale_key not in pruned_store.latest_known_aggregated_payloads

    # Fresh entries should be preserved in all structures
    assert fresh_root in pruned_store.attestation_data_by_root
    assert fresh_key in pruned_store.gossip_signatures
    assert fresh_key in pruned_store.latest_new_aggregated_payloads
    assert fresh_key in pruned_store.latest_known_aggregated_payloads


def test_returns_self_when_nothing_to_prune() -> None:
    """Verify optimization returns same instance when no pruning needed."""
    store, _, _ = _create_test_store()

    # Create fresh attestation data (target.slot > finalized.slot)
    fresh_attestation = _make_attestation_data(
        slot=Slot(10),
        target_slot=Slot(10),
        target_root=Bytes32(b"\x01" * 32),
        source_slot=Slot(5),
        source_root=Bytes32(b"\x02" * 32),
    )
    data_root = fresh_attestation.data_root_bytes()
    sig_key = SignatureKey(ValidatorIndex(1), data_root)

    # Set up store with only fresh entries and finalized slot at 5
    store = store.model_copy(
        update={
            "attestation_data_by_root": {data_root: fresh_attestation},
            "gossip_signatures": {sig_key: make_mock_signature()},
            "latest_finalized": Checkpoint(root=Bytes32(b"\xff" * 32), slot=Slot(5)),
        }
    )

    # Verify data exists before pruning
    assert data_root in store.attestation_data_by_root
    assert sig_key in store.gossip_signatures

    pruned_store = store.prune_stale_attestation_data()

    # Should return the same instance (identity check)
    assert pruned_store is store


def test_handles_empty_attestation_data() -> None:
    """Verify pruning works correctly when attestation_data_by_root is empty."""
    store, _, _ = _create_test_store()

    # Ensure store has empty attestation data
    assert len(store.attestation_data_by_root) == 0

    # Pruning should not fail and should return same instance
    pruned_store = store.prune_stale_attestation_data()

    assert pruned_store is store
    assert len(pruned_store.attestation_data_by_root) == 0


def test_prunes_multiple_validators_same_data_root() -> None:
    """Verify pruning removes entries for multiple validators with same data root."""
    store, _, _ = _create_test_store()

    # Create stale attestation data
    stale_attestation = _make_attestation_data(
        slot=Slot(3),
        target_slot=Slot(3),
        target_root=Bytes32(b"\x01" * 32),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )
    data_root = stale_attestation.data_root_bytes()

    # Multiple validators signed the same attestation data
    sig_key_1 = SignatureKey(ValidatorIndex(1), data_root)
    sig_key_2 = SignatureKey(ValidatorIndex(2), data_root)

    store = store.model_copy(
        update={
            "attestation_data_by_root": {data_root: stale_attestation},
            "gossip_signatures": {
                sig_key_1: make_mock_signature(),
                sig_key_2: make_mock_signature(),
            },
            "latest_finalized": Checkpoint(root=Bytes32(b"\xff" * 32), slot=Slot(5)),
        }
    )

    # Verify data exists before pruning
    assert data_root in store.attestation_data_by_root
    assert sig_key_1 in store.gossip_signatures
    assert sig_key_2 in store.gossip_signatures

    pruned_store = store.prune_stale_attestation_data()

    # Both validators' signatures should be removed
    assert data_root not in pruned_store.attestation_data_by_root
    assert sig_key_1 not in pruned_store.gossip_signatures
    assert sig_key_2 not in pruned_store.gossip_signatures


def test_mixed_stale_and_fresh_entries() -> None:
    """Verify correct pruning behavior with a mix of stale and fresh entries."""
    store, _, _ = _create_test_store()

    # Create multiple attestations at different slots
    attestations = [
        _make_attestation_data(
            slot=Slot(i),
            target_slot=Slot(i),
            target_root=Bytes32(bytes([i]) * 32),
            source_slot=Slot(0),
            source_root=Bytes32.zero(),
        )
        for i in range(1, 11)  # Slots 1-10
    ]

    attestation_data_map = {att.data_root_bytes(): att for att in attestations}
    gossip_sigs = {
        SignatureKey(ValidatorIndex(i), att.data_root_bytes()): make_mock_signature()
        for i, att in enumerate(attestations, start=1)
    }

    # Finalized at slot 5 means slots 1-5 are stale, 6-10 are fresh
    store = store.model_copy(
        update={
            "attestation_data_by_root": attestation_data_map,
            "gossip_signatures": gossip_sigs,
            "latest_finalized": Checkpoint(root=Bytes32(b"\xff" * 32), slot=Slot(5)),
        }
    )

    # Verify all data exists before pruning
    for att in attestations:
        assert att.data_root_bytes() in store.attestation_data_by_root

    pruned_store = store.prune_stale_attestation_data()

    # Entries with target.slot <= 5 should be pruned (slots 1-5)
    for att in attestations[:5]:
        assert att.data_root_bytes() not in pruned_store.attestation_data_by_root

    # Entries with target.slot > 5 should be kept (slots 6-10)
    for att in attestations[5:]:
        assert att.data_root_bytes() in pruned_store.attestation_data_by_root
