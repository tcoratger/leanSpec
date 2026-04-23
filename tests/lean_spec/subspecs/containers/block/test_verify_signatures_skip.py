"""Tests for the skip_aggregate_verify flag on SignedBlock.verify_signatures."""

from __future__ import annotations

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.containers.block.block import BlockSignatures
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import Bytes32
from tests.lean_spec.helpers import (
    make_aggregated_proof,
    make_signed_block_from_store,
    make_store,
)


def test_skip_aggregate_verify_bypasses_stark(
    key_manager: XmssKeyManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """skip_aggregate_verify=True must not invoke AggregatedSignatureProof.verify."""
    base = make_store(num_validators=3, key_manager=key_manager)
    data = base.produce_attestation_data(Slot(1))
    proof = make_aggregated_proof(key_manager, [ValidatorIndex(1), ValidatorIndex(2)], data)
    producer = base.model_copy(update={"latest_known_aggregated_payloads": {data: {proof}}})
    consumer, signed_block = make_signed_block_from_store(
        producer, key_manager, Slot(1), ValidatorIndex(1)
    )

    def _raise_if_called(*args: object, **kwargs: object) -> None:
        pytest.fail("AggregatedSignatureProof.verify must not be called")

    monkeypatch.setattr(AggregatedSignatureProof, "verify", _raise_if_called)

    validators = consumer.states[consumer.head].validators
    assert signed_block.verify_signatures(validators, skip_aggregate_verify=True) is True


def test_skip_aggregate_verify_preserves_proposer_verify(key_manager: XmssKeyManager) -> None:
    """Skipping the aggregate verify must not skip the proposer signature verify."""
    base = make_store(num_validators=3, key_manager=key_manager)
    data = base.produce_attestation_data(Slot(1))
    proof = make_aggregated_proof(key_manager, [ValidatorIndex(1), ValidatorIndex(2)], data)
    producer = base.model_copy(update={"latest_known_aggregated_payloads": {data: {proof}}})
    consumer, signed_block = make_signed_block_from_store(
        producer, key_manager, Slot(1), ValidatorIndex(1)
    )

    # Sign with a different validator: shape-valid XMSS, wrong proposer.
    bad_sig = key_manager.sign_block_root(
        ValidatorIndex(2), signed_block.block.slot, Bytes32.zero()
    )
    corrupted = signed_block.model_copy(
        update={
            "signature": BlockSignatures(
                attestation_signatures=signed_block.signature.attestation_signatures,
                proposer_signature=bad_sig,
            )
        }
    )

    validators = consumer.states[consumer.head].validators
    with pytest.raises(AssertionError, match="Proposer block signature verification failed"):
        corrupted.verify_signatures(validators, skip_aggregate_verify=True)
