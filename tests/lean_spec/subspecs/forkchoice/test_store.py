"""Tests for the forkchoice Store class."""

import pytest

from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    Checkpoint,
    Config,
    SignedVote,
    Vote,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.types import Bytes32, Uint64, ValidatorIndex


@pytest.fixture
def sample_config() -> Config:
    """Create a sample configuration."""
    return Config(
        genesis_time=Uint64(1000),
        num_validators=100,
    )


@pytest.fixture
def sample_checkpoint() -> Checkpoint:
    """Create a sample checkpoint."""
    return Checkpoint(
        root=Bytes32(b"test_root" + b"\x00" * 23),
        slot=Slot(0),
    )


@pytest.fixture
def sample_store(sample_config: Config, sample_checkpoint: Checkpoint) -> Store:
    """Create a sample forkchoice store."""
    return Store(
        time=Uint64(100),
        config=sample_config,
        head=Bytes32(b"head_root" + b"\x00" * 23),
        safe_target=Bytes32(b"safe_root" + b"\x00" * 23),
        latest_justified=sample_checkpoint,
        latest_finalized=sample_checkpoint,
    )


def test_store_creation(sample_store: Store) -> None:
    """Test basic Store creation."""
    assert sample_store.time == Uint64(100)
    assert len(sample_store.blocks) == 0
    assert len(sample_store.states) == 0
    assert len(sample_store.latest_known_votes) == 0
    assert len(sample_store.latest_new_votes) == 0


def test_store_validation(sample_store: Store) -> None:
    """Test Store.validate_attestation() method."""
    # Create blocks for validation
    source_block = Block(
        slot=Slot(10),
        proposer_index=Uint64(0),
        parent_root=Bytes32(b"\x00" * 32),
        state_root=Bytes32(b"state1" + b"\x00" * 26),
        body=BlockBody(attestations=[]),
    )
    target_block = Block(
        slot=Slot(20),
        proposer_index=Uint64(1),
        parent_root=Bytes32(b"source" + b"\x00" * 26),
        state_root=Bytes32(b"state2" + b"\x00" * 26),
        body=BlockBody(attestations=[]),
    )

    # Add blocks to store
    sample_store.blocks[Bytes32(b"source" + b"\x00" * 26)] = source_block
    sample_store.blocks[Bytes32(b"target" + b"\x00" * 26)] = target_block

    # Valid attestation
    vote = Vote(
        validator_id=Uint64(0),
        slot=Slot(25),
        head=Checkpoint(
            root=Bytes32(b"target" + b"\x00" * 26),
            slot=Slot(20),
        ),
        source=Checkpoint(
            root=Bytes32(b"source" + b"\x00" * 26),
            slot=Slot(10),
        ),
        target=Checkpoint(
            root=Bytes32(b"target" + b"\x00" * 26),
            slot=Slot(20),
        ),
    )

    signed_vote = SignedVote(
        data=vote,
        signature=Bytes32(b"signature" + b"\x00" * 23),
    )

    # Should not raise any exception
    sample_store.validate_attestation(signed_vote)


def test_store_process_attestation(sample_store: Store) -> None:
    """Test Store.process_attestation() method."""
    # Create blocks for validation
    source_block = Block(
        slot=Slot(10),
        proposer_index=Uint64(0),
        parent_root=Bytes32(b"\x00" * 32),
        state_root=Bytes32(b"state1" + b"\x00" * 26),
        body=BlockBody(attestations=[]),
    )
    target_block = Block(
        slot=Slot(20),
        proposer_index=Uint64(1),
        parent_root=Bytes32(b"source" + b"\x00" * 26),
        state_root=Bytes32(b"state2" + b"\x00" * 26),
        body=BlockBody(attestations=[]),
    )

    # Add blocks to store
    sample_store.blocks[Bytes32(b"source" + b"\x00" * 26)] = source_block
    sample_store.blocks[Bytes32(b"target" + b"\x00" * 26)] = target_block

    # Create attestation
    vote = Vote(
        validator_id=Uint64(0),
        slot=Slot(20),
        head=Checkpoint(
            root=Bytes32(b"target" + b"\x00" * 26),
            slot=Slot(20),
        ),
        source=Checkpoint(
            root=Bytes32(b"source" + b"\x00" * 26),
            slot=Slot(10),
        ),
        target=Checkpoint(
            root=Bytes32(b"target" + b"\x00" * 26),
            slot=Slot(20),
        ),
    )

    signed_vote = SignedVote(
        data=vote,
        signature=Bytes32(b"signature" + b"\x00" * 23),
    )

    # Process as network attestation
    sample_store.process_attestation(signed_vote, is_from_block=False)

    # Vote should be in new votes (stores target checkpoint)
    assert ValidatorIndex(0) in sample_store.latest_new_votes
    assert sample_store.latest_new_votes[ValidatorIndex(0)] == vote.target

    # Process as block attestation
    sample_store.process_attestation(signed_vote, is_from_block=True)

    # Vote should move to known votes and be removed from new votes
    assert ValidatorIndex(0) in sample_store.latest_known_votes
    assert ValidatorIndex(0) not in sample_store.latest_new_votes
    assert sample_store.latest_known_votes[ValidatorIndex(0)] == vote.target


def test_store_advance_time(sample_store: Store) -> None:
    """Test Store.advance_time() method."""
    initial_time = sample_store.time.as_int()
    target_time = sample_store.config.genesis_time.as_int() + 200  # Much later time

    sample_store.advance_time(target_time, has_proposal=True)

    # Time should advance
    assert sample_store.time.as_int() > initial_time


def test_store_accept_new_votes(sample_store: Store) -> None:
    """Test Store.accept_new_votes() method."""
    # Add some new votes
    checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(1))
    sample_store.latest_new_votes[ValidatorIndex(0)] = checkpoint

    sample_store.accept_new_votes()

    # New votes should be moved to known votes
    assert len(sample_store.latest_new_votes) == 0
    assert ValidatorIndex(0) in sample_store.latest_known_votes
    assert sample_store.latest_known_votes[ValidatorIndex(0)] == checkpoint
