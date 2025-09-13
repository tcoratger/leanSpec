"""Tests for forkchoice helper functions."""

from typing import Dict

import pytest

from lean_spec.subspecs.containers import Block, BlockBody, Checkpoint, State
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice.helpers import (
    get_fork_choice_head,
    get_latest_justified,
    get_vote_target,
)
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, ValidatorIndex


@pytest.fixture
def sample_blocks() -> Dict[Bytes32, Block]:
    """Create a valid, linked chain of sample blocks for testing."""
    genesis = Block(
        slot=Slot(0),
        proposer_index=0,
        parent_root=Bytes32(b"\x00" * 32),
        state_root=Bytes32(b"genesis_state" + b"\x00" * 19),
        body=BlockBody(attestations=[]),
    )
    genesis_hash = hash_tree_root(genesis)

    block_a = Block(
        slot=Slot(1),
        proposer_index=1,
        parent_root=genesis_hash,  # FIX: Correctly link to genesis's hash
        state_root=Bytes32(b"state_a" + b"\x00" * 25),
        body=BlockBody(attestations=[]),
    )
    block_a_hash = hash_tree_root(block_a)

    block_b = Block(
        slot=Slot(2),
        proposer_index=2,
        parent_root=block_a_hash,  # FIX: Correctly link to block_a's hash
        state_root=Bytes32(b"state_b" + b"\x00" * 25),
        body=BlockBody(attestations=[]),
    )
    block_b_hash = hash_tree_root(block_b)

    # FIX: Use the actual block hashes as keys
    return {
        genesis_hash: genesis,
        block_a_hash: block_a,
        block_b_hash: block_b,
    }


def test_get_fork_choice_head_with_votes(sample_blocks: Dict[Bytes32, Block]) -> None:
    """Test fork choice head selection with votes."""
    # Get actual hashes from the corrected fixture
    genesis_hash = list(sample_blocks.keys())[0]
    block_b_hash = list(sample_blocks.keys())[2]

    votes = {
        ValidatorIndex(0): Checkpoint(
            root=block_b_hash,
            slot=Slot(2),
        ),
    }

    head = get_fork_choice_head(
        sample_blocks,
        genesis_hash,
        votes,
    )

    # Should choose block_b since it has a vote
    assert head == block_b_hash


def test_get_fork_choice_head_no_votes(sample_blocks: Dict[Bytes32, Block]) -> None:
    """Test fork choice head with no votes."""
    genesis_hash = list(sample_blocks.keys())[0]
    votes: Dict[ValidatorIndex, Checkpoint] = {}

    head = get_fork_choice_head(
        sample_blocks,
        genesis_hash,
        votes,
    )

    # With no votes, should return genesis (starting point)
    assert head == genesis_hash


def test_get_latest_justified_empty() -> None:
    """Test get_latest_justified with empty states."""
    result = get_latest_justified({})
    assert result is None


def test_get_latest_justified() -> None:
    """Test get_latest_justified with states."""
    checkpoint1 = Checkpoint(root=Bytes32(b"test1" + b"\x00" * 27), slot=Slot(10))
    checkpoint2 = Checkpoint(root=Bytes32(b"test2" + b"\x00" * 27), slot=Slot(20))

    # Create mock states with minimal required fields
    # NOTE: Using a simple class mock as State has many fields.
    class MockState:
        def __init__(self, justified: Checkpoint):
            self.latest_justified = justified

    states: Dict[Bytes32, State] = {
        Bytes32(b"state1" + b"\x00" * 26): MockState(checkpoint1),  # type: ignore
        # Higher slot
        Bytes32(b"state2" + b"\x00" * 26): MockState(checkpoint2),  # type: ignore
    }

    result = get_latest_justified(states)
    assert result == checkpoint2  # Should return the one with higher slot


def test_get_vote_target(sample_blocks: Dict[Bytes32, Block]) -> None:
    """Test get_vote_target function."""
    # Reuse the valid linked blocks from the fixture
    genesis_hash = list(sample_blocks.keys())[0]
    head_hash = list(sample_blocks.keys())[2]  # block_b as head
    head_block = sample_blocks[head_hash]

    finalized = Checkpoint(root=genesis_hash, slot=Slot(0))

    target = get_vote_target(
        head=head_hash,
        safe_target=head_hash,  # Assume safe_target is the same as head
        latest_finalized=finalized,
        blocks=sample_blocks,
    )

    # Target should be the head block since head_slot - finalized_slot is > 3
    # and head_slot is justifiable.
    assert target.root == head_hash
    assert target.slot == head_block.slot
