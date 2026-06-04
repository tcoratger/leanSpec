"""Tests for attestation signature aggregation."""

from __future__ import annotations

from consensus_testing.keys import XmssKeyManager

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import AttestationSignatureEntry
from lean_spec.spec.forks.lstar.spec import LstarSpec
from tests.lean_spec.helpers import (
    make_attestation_data_simple,
    make_bytes32,
    make_store,
)


def test_aggregated_signatures_prefers_full_gossip_payload(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    store = make_store(num_validators=2, key_manager=container_key_manager)
    head_state = store.states[store.head]
    source = Checkpoint(root=make_bytes32(1), slot=Slot(0))
    attestation_data = make_attestation_data_simple(
        Slot(2), make_bytes32(3), make_bytes32(4), source=source
    )
    attestation_signatures = {
        attestation_data: {
            AttestationSignatureEntry(
                ValidatorIndex(i),
                container_key_manager.sign_attestation_data(ValidatorIndex(i), attestation_data),
            )
            for i in range(2)
        }
    }

    store.attestation_signatures = attestation_signatures
    _, results = spec.aggregate(store)

    assert len(results) == 1
    assert set(results[0].proof.participants.to_validator_indices()) == {
        ValidatorIndex(0),
        ValidatorIndex(1),
    }

    public_keys = [
        head_state.validators[ValidatorIndex(i)].get_attestation_public_key() for i in range(2)
    ]
    results[0].proof.verify(
        public_keys=public_keys,
        message=hash_tree_root(attestation_data),
        slot=attestation_data.slot,
    )


def test_aggregate_with_empty_attestation_signatures(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """Empty attestations list should return empty results."""
    store = make_store(num_validators=2, key_manager=container_key_manager)
    _, results = spec.aggregate(store)

    assert results == []


def test_aggregated_signatures_with_multiple_data_groups(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """Multiple attestation data groups should be processed independently."""
    store = make_store(num_validators=4, key_manager=container_key_manager)
    source = Checkpoint(root=make_bytes32(22), slot=Slot(0))
    attestation_data1 = make_attestation_data_simple(
        Slot(9), make_bytes32(23), make_bytes32(24), source=source
    )
    attestation_data2 = make_attestation_data_simple(
        Slot(10), make_bytes32(25), make_bytes32(26), source=source
    )

    attestation_signatures = {
        attestation_data1: {
            AttestationSignatureEntry(
                ValidatorIndex(0),
                container_key_manager.sign_attestation_data(ValidatorIndex(0), attestation_data1),
            ),
            AttestationSignatureEntry(
                ValidatorIndex(1),
                container_key_manager.sign_attestation_data(ValidatorIndex(1), attestation_data1),
            ),
        },
        attestation_data2: {
            AttestationSignatureEntry(
                ValidatorIndex(2),
                container_key_manager.sign_attestation_data(ValidatorIndex(2), attestation_data2),
            ),
            AttestationSignatureEntry(
                ValidatorIndex(3),
                container_key_manager.sign_attestation_data(ValidatorIndex(3), attestation_data2),
            ),
        },
    }

    store.attestation_signatures = attestation_signatures
    _, results = spec.aggregate(store)

    assert len(results) == 2

    for signed_attestation in results:
        participants = signed_attestation.proof.participants.to_validator_indices()
        public_keys = [
            container_key_manager[validator_index].attestation_keypair.public_key
            for validator_index in participants
        ]
        signed_attestation.proof.verify(
            public_keys=public_keys,
            message=hash_tree_root(signed_attestation.data),
            slot=signed_attestation.data.slot,
        )


def test_aggregate_with_no_signatures(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """
    Test edge case where the store has no attestation signatures or payloads.

    Returns empty results (no attestations can be aggregated without signatures).
    """
    store = make_store(num_validators=2, key_manager=container_key_manager)
    _, results = spec.aggregate(store)

    assert results == []
