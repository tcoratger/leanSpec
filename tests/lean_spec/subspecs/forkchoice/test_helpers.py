"""Tests for pure forkchoice helper functions."""

from typing import Dict

import pytest

from lean_spec.subspecs.containers import Block, BlockBody, Checkpoint, State
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice.helpers import (
    get_fork_choice_head,
    get_latest_justified,
)
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64, ValidatorIndex


@pytest.fixture
def sample_blocks() -> Dict[Bytes32, Block]:
    """Create a valid, linked chain of sample blocks for testing."""
    genesis = Block(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32(b"\x00" * 32),
        state_root=Bytes32(b"genesis" + b"\x00" * 25),
        body=BlockBody(attestations=[]),
    )
    genesis_hash = hash_tree_root(genesis)

    block_a = Block(
        slot=Slot(1),
        proposer_index=Uint64(1),
        parent_root=genesis_hash,
        state_root=Bytes32(b"block_a" + b"\x00" * 25),
        body=BlockBody(attestations=[]),
    )
    block_a_hash = hash_tree_root(block_a)

    block_b = Block(
        slot=Slot(2),
        proposer_index=Uint64(2),
        parent_root=block_a_hash,
        state_root=Bytes32(b"block_b" + b"\x00" * 25),
        body=BlockBody(attestations=[]),
    )
    block_b_hash = hash_tree_root(block_b)

    return {
        genesis_hash: genesis,
        block_a_hash: block_a,
        block_b_hash: block_b,
    }


class TestForkChoiceHeadFunction:
    """Test the pure get_fork_choice_head helper function."""

    def test_get_fork_choice_head_with_votes(self, sample_blocks: Dict[Bytes32, Block]) -> None:
        """Test get_fork_choice_head with validator votes."""
        root_hash = list(sample_blocks.keys())[0]
        target_hash = list(sample_blocks.keys())[2]  # block_b

        # Create votes pointing to target
        votes = {ValidatorIndex(0): Checkpoint(root=target_hash, slot=Slot(2))}

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_votes=votes, min_score=0
        )

        assert head == target_hash

    def test_get_fork_choice_head_no_votes(self, sample_blocks: Dict[Bytes32, Block]) -> None:
        """Test get_fork_choice_head with no votes returns the root."""
        root_hash = list(sample_blocks.keys())[0]

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_votes={}, min_score=0
        )

        assert head == root_hash

    def test_get_fork_choice_head_with_min_score(self, sample_blocks: Dict[Bytes32, Block]) -> None:
        """Test get_fork_choice_head respects minimum score."""
        root_hash = list(sample_blocks.keys())[0]
        target_hash = list(sample_blocks.keys())[2]  # block_b

        # Single vote, but require min_score of 2
        votes = {ValidatorIndex(0): Checkpoint(root=target_hash, slot=Slot(2))}

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_votes=votes, min_score=2
        )

        # Should fall back to root since min_score not met
        assert head == root_hash

    def test_get_fork_choice_head_multiple_votes(self, sample_blocks: Dict[Bytes32, Block]) -> None:
        """Test get_fork_choice_head with multiple votes."""
        root_hash = list(sample_blocks.keys())[0]
        target_hash = list(sample_blocks.keys())[2]  # block_b

        # Multiple votes for same target
        votes = {
            ValidatorIndex(0): Checkpoint(root=target_hash, slot=Slot(2)),
            ValidatorIndex(1): Checkpoint(root=target_hash, slot=Slot(2)),
            ValidatorIndex(2): Checkpoint(root=target_hash, slot=Slot(2)),
        }

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_votes=votes, min_score=0
        )

        assert head == target_hash


class TestLatestJustifiedFunction:
    """Test the pure get_latest_justified helper function."""

    def test_get_latest_justified_empty(self) -> None:
        """Test get_latest_justified with empty states."""
        result = get_latest_justified({})
        assert result is None

    def test_get_latest_justified_single_state(self) -> None:
        """Test get_latest_justified with a single state."""
        checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(5))

        class MockState:
            def __init__(self, justified: Checkpoint):
                self.latest_justified = justified

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): MockState(checkpoint),  # type: ignore
        }

        result = get_latest_justified(states)
        assert result == checkpoint

    def test_get_latest_justified_multiple_states(self) -> None:
        """Test get_latest_justified with states having different justified slots."""
        checkpoint1 = Checkpoint(root=Bytes32(b"test1" + b"\x00" * 27), slot=Slot(10))
        checkpoint2 = Checkpoint(
            root=Bytes32(b"test2" + b"\x00" * 27), slot=Slot(20)
        )  # Higher slot

        class MockState:
            def __init__(self, justified: Checkpoint):
                self.latest_justified = justified

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): MockState(checkpoint1),  # type: ignore
            Bytes32(b"state2" + b"\x00" * 26): MockState(checkpoint2),  # type: ignore
        }

        result = get_latest_justified(states)
        assert result == checkpoint2  # Should return the one with higher slot

    def test_get_latest_justified_tie_breaking(self) -> None:
        """Test get_latest_justified when multiple states have same justified slot."""
        checkpoint1 = Checkpoint(root=Bytes32(b"test1" + b"\x00" * 27), slot=Slot(10))
        checkpoint2 = Checkpoint(root=Bytes32(b"test2" + b"\x00" * 27), slot=Slot(10))

        class MockState:
            def __init__(self, justified: Checkpoint):
                self.latest_justified = justified

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): MockState(checkpoint1),  # type: ignore
            Bytes32(b"state2" + b"\x00" * 26): MockState(checkpoint2),  # type: ignore
        }

        result = get_latest_justified(states)
        # Should return one of them consistently
        assert result in [checkpoint1, checkpoint2]
        assert result.slot == Slot(10)


class TestJustifiableSlotFunction:
    """Test the slot justification logic using Slot.is_justifiable_after method."""

    def test_is_justifiable_slot_basic_cases(self) -> None:
        """Test basic justifiable slot cases."""
        finalized_slot = Slot(10)

        # Delta <= 5 should be justifiable
        assert (
            Slot(finalized_slot.as_int() + 0).is_justifiable_after(finalized_slot) is True
        )  # delta = 0
        assert (
            Slot(finalized_slot.as_int() + 1).is_justifiable_after(finalized_slot) is True
        )  # delta = 1
        assert (
            Slot(finalized_slot.as_int() + 5).is_justifiable_after(finalized_slot) is True
        )  # delta = 5

    def test_is_justifiable_slot_perfect_squares(self) -> None:
        """Test that perfect squares are justifiable."""
        finalized_slot = Slot(10)

        # Perfect squares should be justifiable
        assert (
            Slot(finalized_slot.as_int() + 4).is_justifiable_after(finalized_slot) is True
        )  # delta = 4 = 2^2
        assert (
            Slot(finalized_slot.as_int() + 9).is_justifiable_after(finalized_slot) is True
        )  # delta = 9 = 3^2
        assert (
            Slot(finalized_slot.as_int() + 16).is_justifiable_after(finalized_slot) is True
        )  # delta = 16 = 4^2
        assert (
            Slot(finalized_slot.as_int() + 25).is_justifiable_after(finalized_slot) is True
        )  # delta = 25 = 5^2

    def test_is_justifiable_slot_pronic_numbers(self) -> None:
        """Test that pronic numbers (x^2 + x) are justifiable."""
        finalized_slot = Slot(10)

        # Pronic numbers (x^2 + x) should be justifiable
        assert (
            Slot(finalized_slot.as_int() + 6).is_justifiable_after(finalized_slot) is True
        )  # delta = 6 = 2*3 = 2^2+2
        assert (
            Slot(finalized_slot.as_int() + 12).is_justifiable_after(finalized_slot) is True
        )  # delta = 12 = 3*4 = 3^2+3
        assert (
            Slot(finalized_slot.as_int() + 20).is_justifiable_after(finalized_slot) is True
        )  # delta = 20 = 4*5 = 4^2+4
        assert (
            Slot(finalized_slot.as_int() + 30).is_justifiable_after(finalized_slot) is True
        )  # delta = 30 = 5*6 = 5^2+5

    def test_is_justifiable_slot_non_justifiable(self) -> None:
        """Test slots that should not be justifiable."""
        finalized_slot = Slot(10)

        # Non-justifiable slots
        assert (
            Slot(finalized_slot.as_int() + 7).is_justifiable_after(finalized_slot) is False
        )  # delta = 7
        assert (
            Slot(finalized_slot.as_int() + 8).is_justifiable_after(finalized_slot) is False
        )  # delta = 8
        assert (
            Slot(finalized_slot.as_int() + 10).is_justifiable_after(finalized_slot) is False
        )  # delta = 10
        assert (
            Slot(finalized_slot.as_int() + 11).is_justifiable_after(finalized_slot) is False
        )  # delta = 11
        assert (
            Slot(finalized_slot.as_int() + 13).is_justifiable_after(finalized_slot) is False
        )  # delta = 13

    def test_is_justifiable_slot_edge_cases(self) -> None:
        """Test edge cases in slot justification."""
        # Test with finalized_slot = 0
        finalized_slot = Slot(0)
        assert Slot(0).is_justifiable_after(finalized_slot) is True  # Same slot
        assert Slot(1).is_justifiable_after(finalized_slot) is True  # delta = 1
        assert Slot(4).is_justifiable_after(finalized_slot) is True  # delta = 4 = 2^2
        assert Slot(6).is_justifiable_after(finalized_slot) is True  # delta = 6 = 2^2+2

        # Test large deltas
        assert Slot(100).is_justifiable_after(finalized_slot) is True  # delta = 100 = 10^2
        assert Slot(101).is_justifiable_after(finalized_slot) is False  # delta = 101 (not special)
        assert Slot(110).is_justifiable_after(finalized_slot) is True  # delta = 110 = 10^2+10

    def test_is_justifiable_slot_validation(self) -> None:
        """Test slot justification input validation."""
        # Should raise assertion error if candidate < finalized_slot
        with pytest.raises(
            AssertionError, match="Candidate slot must not be before finalized slot"
        ):
            Slot(5).is_justifiable_after(Slot(10))  # candidate < finalized_slot

        with pytest.raises(
            AssertionError, match="Candidate slot must not be before finalized slot"
        ):
            Slot(99).is_justifiable_after(Slot(100))  # candidate < finalized_slot

        # Should work fine when candidate >= finalized_slot
        assert Slot(10).is_justifiable_after(Slot(10)) is True  # Equal
        assert Slot(11).is_justifiable_after(Slot(10)) is True  # Greater
