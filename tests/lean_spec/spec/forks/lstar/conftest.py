"""
Shared pytest fixtures for lstar fork tests.

Provides stores and key managers used across fork choice, validator duty,
timeline, aggregation, and container tests.
"""

from __future__ import annotations

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.spec.forks import Interval, Slot
from lean_spec.spec.forks.lstar import Store
from tests.lean_spec.helpers import TEST_VALIDATOR_INDEX, make_store


@pytest.fixture
def pruning_store() -> Store:
    """Store with 3 validators for pruning tests."""
    return make_store(num_validators=3, validator_index=TEST_VALIDATOR_INDEX)


@pytest.fixture
def sample_store(store_factory):
    """Store with 8 validators, genesis_time=1000, time=100."""
    store = store_factory(num_validators=8, genesis_time=1000)
    return store.model_copy(update={"time": Interval(100)})


@pytest.fixture
def container_key_manager() -> XmssKeyManager:
    """Key manager for container tests."""
    return XmssKeyManager.shared(max_slot=Slot(20))
