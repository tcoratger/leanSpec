"""Tests for the LstarSpec delegator surface (Stage 4A of #686).

LstarSpec exposes container methods (state transition, fork choice, block
production, signature verification) as fork-class methods that delegate to
the underlying State / Store / SignedBlock methods. Stage 4A only adds the
surface; the bodies stay on the containers and call sites are unchanged.

Each test verifies that the delegator forwards its arguments to the
corresponding container method and returns the container method's result
unchanged. This locks the surface in place before Stage 4C moves the bodies.
"""

from unittest.mock import patch

from lean_spec.forks.lstar import State, Store
from lean_spec.forks.lstar.containers import Block, SignedAttestation, SignedBlock
from lean_spec.forks.lstar.containers.attestation import (
    AggregatedAttestation,
    SignedAggregatedAttestation,
)
from lean_spec.forks.lstar.spec import LstarSpec
from lean_spec.subspecs.chain.clock import Interval
from lean_spec.subspecs.xmss.interface import TARGET_SIGNATURE_SCHEME
from lean_spec.types import Bytes32, Slot, ValidatorIndex
from tests.lean_spec.helpers.builders import (
    make_genesis_data,
    make_keyed_genesis_state,
    make_signed_block,
    make_validators,
)

_NUM_VALIDATORS = 3
_VALIDATOR_ID = ValidatorIndex(0)
_SENTINEL = object()
"""Unique object returned by patched container methods to confirm delegators forward unchanged."""


def _spec() -> LstarSpec:
    """Construct a fresh LstarSpec for each delegator test."""
    return LstarSpec()


class TestStateDelegators:
    """LstarSpec methods that delegate to State."""

    def test_state_transition_forwards(self) -> None:
        """state_transition delegator forwards to State.state_transition."""
        state = make_keyed_genesis_state(_NUM_VALIDATORS)
        block = Block.model_construct(slot=Slot(1))

        with patch.object(State, "state_transition", return_value=_SENTINEL) as mock:
            result = _spec().state_transition(state, block, valid_signatures=False)

        mock.assert_called_once_with(block, False)
        assert result is _SENTINEL

    def test_process_slots_forwards(self) -> None:
        """process_slots delegator forwards to State.process_slots."""
        state = make_keyed_genesis_state(_NUM_VALIDATORS)
        target = Slot(7)

        with patch.object(State, "process_slots", return_value=_SENTINEL) as mock:
            result = _spec().process_slots(state, target)

        mock.assert_called_once_with(target)
        assert result is _SENTINEL

    def test_process_block_forwards(self) -> None:
        """process_block delegator forwards to State.process_block."""
        state = make_keyed_genesis_state(_NUM_VALIDATORS)
        block = Block.model_construct(slot=Slot(1))

        with patch.object(State, "process_block", return_value=_SENTINEL) as mock:
            result = _spec().process_block(state, block)

        mock.assert_called_once_with(block)
        assert result is _SENTINEL

    def test_process_block_header_forwards(self) -> None:
        """process_block_header delegator forwards to State.process_block_header."""
        state = make_keyed_genesis_state(_NUM_VALIDATORS)
        block = Block.model_construct(slot=Slot(1))

        with patch.object(State, "process_block_header", return_value=_SENTINEL) as mock:
            result = _spec().process_block_header(state, block)

        mock.assert_called_once_with(block)
        assert result is _SENTINEL

    def test_process_attestations_forwards(self) -> None:
        """process_attestations delegator forwards to State.process_attestations."""
        state = make_keyed_genesis_state(_NUM_VALIDATORS)
        attestations: list[AggregatedAttestation] = []

        with patch.object(State, "process_attestations", return_value=_SENTINEL) as mock:
            result = _spec().process_attestations(state, attestations)

        mock.assert_called_once_with(attestations)
        assert result is _SENTINEL

    def test_build_block_forwards(self) -> None:
        """build_block delegator forwards to State.build_block."""
        state = make_keyed_genesis_state(_NUM_VALIDATORS)
        slot = Slot(1)
        proposer_index = ValidatorIndex(1)
        parent_root = Bytes32.zero()
        known_block_roots = {parent_root}

        with patch.object(State, "build_block", return_value=_SENTINEL) as mock:
            result = _spec().build_block(
                state,
                slot=slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                known_block_roots=known_block_roots,
            )

        mock.assert_called_once_with(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots=known_block_roots,
            aggregated_payloads=None,
        )
        assert result is _SENTINEL


class TestSignedBlockDelegator:
    """LstarSpec method that delegates to SignedBlock."""

    def test_verify_signatures_forwards(self) -> None:
        """verify_signatures delegator forwards to SignedBlock.verify_signatures."""
        validators = make_validators(_NUM_VALIDATORS)
        signed_block = make_signed_block(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        with patch.object(SignedBlock, "verify_signatures", return_value=True) as mock:
            result = _spec().verify_signatures(signed_block, validators)

        mock.assert_called_once_with(validators, TARGET_SIGNATURE_SCHEME)
        assert result is True


class TestStoreDelegators:
    """LstarSpec methods that delegate to Store."""

    def _store(self) -> Store:
        """Build a genesis store for delegator tests."""
        return make_genesis_data(num_validators=_NUM_VALIDATORS, validator_id=_VALIDATOR_ID).store

    def test_on_block_forwards(self) -> None:
        """on_block delegator forwards to Store.on_block."""
        store = self._store()
        signed_block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(1),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        with patch.object(Store, "on_block", return_value=_SENTINEL) as mock:
            result = _spec().on_block(store, signed_block)

        mock.assert_called_once_with(signed_block, TARGET_SIGNATURE_SCHEME)
        assert result is _SENTINEL

    def test_on_tick_forwards(self) -> None:
        """on_tick delegator forwards to Store.on_tick."""
        store = self._store()
        target = Interval.from_slot(Slot(1))

        with patch.object(Store, "on_tick", return_value=_SENTINEL) as mock:
            result = _spec().on_tick(store, target, has_proposal=True, is_aggregator=True)

        mock.assert_called_once_with(target, True, True)
        assert result is _SENTINEL

    def test_on_gossip_attestation_forwards(self) -> None:
        """on_gossip_attestation delegator forwards to Store.on_gossip_attestation."""
        store = self._store()
        attestation = SignedAttestation.model_construct()

        with patch.object(Store, "on_gossip_attestation", return_value=_SENTINEL) as mock:
            result = _spec().on_gossip_attestation(store, attestation, is_aggregator=True)

        mock.assert_called_once_with(attestation, TARGET_SIGNATURE_SCHEME, True)
        assert result is _SENTINEL

    def test_on_gossip_aggregated_attestation_forwards(self) -> None:
        """Aggregated-attestation delegator forwards to the Store method."""
        store = self._store()
        attestation = SignedAggregatedAttestation.model_construct()

        with patch.object(
            Store, "on_gossip_aggregated_attestation", return_value=_SENTINEL
        ) as mock:
            result = _spec().on_gossip_aggregated_attestation(store, attestation)

        mock.assert_called_once_with(attestation)
        assert result is _SENTINEL

    def test_produce_attestation_data_forwards(self) -> None:
        """produce_attestation_data delegator forwards to Store.produce_attestation_data."""
        store = self._store()
        slot = Slot(2)

        with patch.object(Store, "produce_attestation_data", return_value=_SENTINEL) as mock:
            result = _spec().produce_attestation_data(store, slot)

        mock.assert_called_once_with(slot)
        assert result is _SENTINEL

    def test_produce_block_with_signatures_forwards(self) -> None:
        """Block-production delegator forwards to Store.produce_block_with_signatures."""
        store = self._store()
        slot = Slot(2)
        validator_index = ValidatorIndex(1)

        with patch.object(Store, "produce_block_with_signatures", return_value=_SENTINEL) as mock:
            result = _spec().produce_block_with_signatures(store, slot, validator_index)

        mock.assert_called_once_with(slot, validator_index)
        assert result is _SENTINEL

    def test_get_proposal_head_forwards(self) -> None:
        """get_proposal_head delegator forwards to Store.get_proposal_head."""
        store = self._store()
        slot = Slot(2)

        with patch.object(Store, "get_proposal_head", return_value=_SENTINEL) as mock:
            result = _spec().get_proposal_head(store, slot)

        mock.assert_called_once_with(slot)
        assert result is _SENTINEL
