"""Tests for the selective store-state checks used by fork choice vectors."""

from __future__ import annotations

import pytest

from consensus_testing.genesis import (
    make_genesis_state,
    make_genesis_store,
    reconstruct_block_from_header,
)
from consensus_testing.test_types.store_checks import StoreChecks
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Uint64


class TestSelectiveScalarCheck:
    """Selective scalar validation in the store-state checks."""

    def test_set_matching_scalar_field_passes(self) -> None:
        """A set scalar field that equals the store value validates without raising."""
        store = make_genesis_store(num_validators=4, keyed=False)

        StoreChecks(latest_justified_slot=Slot(0)).validate_against_store(store, step_index=0)

    def test_set_mismatching_scalar_field_raises_full_message(self) -> None:
        """A set scalar field that disagrees with the store raises the full mismatch message."""
        store = make_genesis_store(num_validators=4, keyed=False)

        with pytest.raises(AssertionError) as exception_info:
            StoreChecks(latest_justified_slot=Slot(5)).validate_against_store(store, step_index=2)

        assert str(exception_info.value) == "Step 2: latest_justified_slot = 0, expected 5"

    def test_unset_scalar_field_is_skipped(self) -> None:
        """An omitted scalar field is never read, so a value that would mismatch is ignored."""
        store = make_genesis_store(num_validators=4, keyed=False)

        # The genesis justified slot is 0, so a checker pinning slot 5 would fail.
        # Pinning only the matching store time leaves the justified slot unset.
        # An unset field must be skipped, so the check passes despite the latent mismatch.
        StoreChecks(time=store.time).validate_against_store(store, step_index=0)


class TestAttestationTargetSlotConsistency:
    """The attestation target slot-and-root consistency branch."""

    def test_coherent_genesis_target_passes(self) -> None:
        """The genesis target resolves to the genesis block at slot 0 and validates."""
        store = make_genesis_store(num_validators=4, keyed=False)

        StoreChecks(attestation_target_slot=Slot(0)).validate_against_store(store, step_index=0)

    def test_coherent_target_on_two_block_chain_passes(self) -> None:
        """On a two-block chain the target resolves to the genesis block at slot 0."""
        fork = LstarSpec()
        genesis_state = make_genesis_state(num_validators=4)
        genesis_block = reconstruct_block_from_header(genesis_state)
        genesis_root = hash_tree_root(genesis_block)
        child_block, _, _, _ = fork.build_block(
            genesis_state,
            slot=Slot(1),
            proposer_index=ValidatorIndex.proposer_for_slot(Slot(1), Uint64(4)),
            parent_root=genesis_root,
            known_block_roots={genesis_root},
        )
        child_root = hash_tree_root(child_block)

        store = make_genesis_store(num_validators=4, keyed=False).model_copy(
            update={
                "blocks": {genesis_root: genesis_block, child_root: child_block},
                "head": child_root,
            }
        )

        StoreChecks(attestation_target_slot=Slot(0)).validate_against_store(store, step_index=3)
