"""Shared fixtures for container tests."""

from __future__ import annotations

import pytest
from consensus_testing.keys import XmssKeyManager, get_shared_key_manager

from lean_spec.subspecs.containers.slot import Slot


@pytest.fixture
def container_key_manager() -> XmssKeyManager:
    """Key manager for container tests."""
    return get_shared_key_manager(max_slot=Slot(20))
