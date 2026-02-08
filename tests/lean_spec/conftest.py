"""
Shared pytest fixtures for all lean_spec tests.

Provides core fixtures used across multiple test modules.
Import these fixtures automatically via pytest discovery.
"""

from __future__ import annotations

import pytest
from consensus_testing.keys import XmssKeyManager, get_shared_key_manager

from lean_spec.subspecs.containers import Block, State
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from tests.lean_spec.helpers import (
    make_genesis_block,
    make_genesis_state,
    make_validators_from_key_manager,
)


@pytest.fixture
def key_manager() -> XmssKeyManager:
    """XMSS key manager for signing attestations."""
    return get_shared_key_manager(max_slot=Slot(20))


@pytest.fixture
def genesis_state() -> State:
    """Genesis state with 3 validators at time 0."""
    return make_genesis_state(num_validators=3, genesis_time=0)


@pytest.fixture
def genesis_block(genesis_state: State) -> Block:
    """Genesis block matching the genesis_state fixture."""
    return make_genesis_block(genesis_state)


@pytest.fixture
def base_store(genesis_state: State, genesis_block: Block) -> Store:
    """Fork choice store initialized with genesis."""
    return Store.get_forkchoice_store(
        genesis_state,
        genesis_block,
        validator_id=ValidatorIndex(0),
    )


@pytest.fixture
def validators_with_keys(key_manager: XmssKeyManager) -> Validators:
    """12 validators with real XMSS public keys."""
    return make_validators_from_key_manager(key_manager, count=12)


@pytest.fixture
def keyed_genesis_state(validators_with_keys: Validators) -> State:
    """Genesis state with real XMSS keys."""
    return make_genesis_state(validators=validators_with_keys)


@pytest.fixture
def keyed_genesis_block(keyed_genesis_state: State) -> Block:
    """Genesis block matching the keyed genesis state."""
    return make_genesis_block(keyed_genesis_state)


@pytest.fixture
def keyed_store(keyed_genesis_state: State, keyed_genesis_block: Block) -> Store:
    """Fork choice store with real XMSS keys, validator_id=0."""
    return Store.get_forkchoice_store(
        keyed_genesis_state, keyed_genesis_block, validator_id=ValidatorIndex(0)
    )


@pytest.fixture
def observer_store(keyed_genesis_state: State, keyed_genesis_block: Block) -> Store:
    """Fork choice store with validator_id=None (non-validator observer)."""
    return Store.get_forkchoice_store(keyed_genesis_state, keyed_genesis_block, validator_id=None)
