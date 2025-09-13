"""Tests for checkpoint justification and finalization logic."""

from typing import Dict

import pytest

from lean_spec.subspecs.containers import (
    Checkpoint,
    State,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice.helpers import get_latest_justified
from lean_spec.types import Bytes32


class TestJustificationLogic:
    """Test checkpoint justification logic."""

    def test_get_latest_justified_empty(self) -> None:
        """Test get_latest_justified with empty states."""
        result = get_latest_justified({})
        assert result is None

    def test_get_latest_justified_single_state(self) -> None:
        """Test get_latest_justified with a single state."""
        checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(5))

        # Create mock state with minimal required fields
        class MockState:
            def __init__(self, justified: Checkpoint):
                self.latest_justified = justified

        state = MockState(checkpoint)
        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): state  # type: ignore
        }

        result = get_latest_justified(states)
        assert result == checkpoint

    def test_get_latest_justified_multiple_states(self) -> None:
        """Test get_latest_justified with multiple states."""
        checkpoint1 = Checkpoint(root=Bytes32(b"test1" + b"\x00" * 27), slot=Slot(10))
        checkpoint2 = Checkpoint(
            root=Bytes32(b"test2" + b"\x00" * 27), slot=Slot(20)
        )  # Higher slot
        checkpoint3 = Checkpoint(root=Bytes32(b"test3" + b"\x00" * 27), slot=Slot(15))

        # Create mock states with minimal required fields
        class MockState:
            def __init__(self, justified: Checkpoint):
                self.latest_justified = justified

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): MockState(checkpoint1),  # type: ignore
            Bytes32(b"state2" + b"\x00" * 26): MockState(checkpoint2),  # type: ignore
            Bytes32(b"state3" + b"\x00" * 26): MockState(checkpoint3),  # type: ignore
        }

        result = get_latest_justified(states)
        assert result == checkpoint2  # Should return the one with highest slot

    def test_get_latest_justified_tie_breaking(self) -> None:
        """Test get_latest_justified with tied slots."""
        # Two checkpoints with same slot
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
        # Should return one of them consistently (based on max() implementation)
        assert result in [checkpoint1, checkpoint2]
        assert result.slot == Slot(10)

    def test_get_latest_justified_zero_slot(self) -> None:
        """Test get_latest_justified with genesis (slot 0) checkpoints."""
        genesis_checkpoint = Checkpoint(root=Bytes32(b"genesis" + b"\x00" * 25), slot=Slot(0))

        class MockState:
            def __init__(self, justified: Checkpoint):
                self.latest_justified = justified

        states: Dict[Bytes32, State] = {
            Bytes32(b"genesis_state" + b"\x00" * 19): MockState(genesis_checkpoint),  # type: ignore
        }

        result = get_latest_justified(states)
        assert result == genesis_checkpoint
        assert result.slot == Slot(0)

    def test_get_latest_justified_large_slots(self) -> None:
        """Test get_latest_justified with large slot numbers."""
        checkpoint1 = Checkpoint(root=Bytes32(b"test1" + b"\x00" * 27), slot=Slot(1000))
        checkpoint2 = Checkpoint(root=Bytes32(b"test2" + b"\x00" * 27), slot=Slot(999))
        checkpoint3 = Checkpoint(root=Bytes32(b"test3" + b"\x00" * 27), slot=Slot(1001))  # Highest

        class MockState:
            def __init__(self, justified: Checkpoint):
                self.latest_justified = justified

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): MockState(checkpoint1),  # type: ignore
            Bytes32(b"state2" + b"\x00" * 26): MockState(checkpoint2),  # type: ignore
            Bytes32(b"state3" + b"\x00" * 26): MockState(checkpoint3),  # type: ignore
        }

        result = get_latest_justified(states)
        assert result == checkpoint3
        assert result.slot == Slot(1001)


class TestFinalizationLogic:
    """Test checkpoint finalization logic."""

    def test_finalization_progression(self) -> None:
        """Test that finalization progresses correctly."""
        # This is a conceptual test since finalization logic is complex
        # and involves state transitions

        # Create checkpoints representing finalization progression
        genesis = Checkpoint(root=Bytes32(b"genesis" + b"\x00" * 25), slot=Slot(0))
        epoch_1 = Checkpoint(root=Bytes32(b"epoch1" + b"\x00" * 26), slot=Slot(32))
        epoch_2 = Checkpoint(root=Bytes32(b"epoch2" + b"\x00" * 26), slot=Slot(64))

        # Test progression: genesis -> epoch_1 -> epoch_2
        assert genesis.slot < epoch_1.slot < epoch_2.slot

        # Verify checkpoint structure
        assert isinstance(genesis.root, Bytes32)
        assert isinstance(genesis.slot, Slot)
        assert genesis.root != epoch_1.root != epoch_2.root

    def test_finalization_requirements(self) -> None:
        """Test finalization requirements (conceptual)."""
        # Finalization typically requires:
        # 1. Justified checkpoint
        # 2. Supermajority support
        # 3. Proper epoch boundaries

        justified = Checkpoint(root=Bytes32(b"justified" + b"\x00" * 23), slot=Slot(32))
        finalized = Checkpoint(root=Bytes32(b"finalized" + b"\x00" * 23), slot=Slot(0))

        # Finalized should be earlier than or equal to justified
        assert finalized.slot <= justified.slot

        # Both should be valid checkpoints
        assert isinstance(justified, Checkpoint)
        assert isinstance(finalized, Checkpoint)
        assert len(justified.root) == 32
        assert len(finalized.root) == 32

    def test_checkpoint_ordering(self) -> None:
        """Test checkpoint ordering for finalization logic."""
        checkpoints = [
            Checkpoint(root=Bytes32(b"cp3" + b"\x00" * 29), slot=Slot(96)),
            Checkpoint(root=Bytes32(b"cp1" + b"\x00" * 29), slot=Slot(32)),
            Checkpoint(root=Bytes32(b"cp2" + b"\x00" * 29), slot=Slot(64)),
            Checkpoint(root=Bytes32(b"cp0" + b"\x00" * 29), slot=Slot(0)),
        ]

        # Sort by slot for finalization order
        sorted_checkpoints = sorted(checkpoints, key=lambda cp: cp.slot)

        expected_slots = [Slot(0), Slot(32), Slot(64), Slot(96)]
        actual_slots = [cp.slot for cp in sorted_checkpoints]

        assert actual_slots == expected_slots

    def test_checkpoint_equality(self) -> None:
        """Test checkpoint equality for finalization comparisons."""
        root = Bytes32(b"same_root" + b"\x00" * 23)
        slot = Slot(42)

        cp1 = Checkpoint(root=root, slot=slot)
        cp2 = Checkpoint(root=root, slot=slot)
        cp3 = Checkpoint(root=root, slot=Slot(43))  # Different slot

        assert cp1 == cp2  # Same root and slot
        assert cp1 != cp3  # Different slot
        assert cp1.root == cp2.root == cp3.root  # Same root
        assert cp1.slot == cp2.slot != cp3.slot  # Different slots


class TestJustificationSlotLogic:
    """Test slot justification logic."""

    def test_slot_justification_basic(self) -> None:
        """Test basic slot justification rules."""
        # Test basic cases from the specification
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

    def test_slot_justification_edge_cases(self) -> None:
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

    def test_slot_justification_validation(self) -> None:
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


class TestCheckpointValidation:
    """Test checkpoint validation logic."""

    def test_checkpoint_creation(self) -> None:
        """Test checkpoint creation and validation."""
        root = Bytes32(b"test_root" + b"\x00" * 23)
        slot = Slot(42)

        checkpoint = Checkpoint(root=root, slot=slot)

        assert checkpoint.root == root
        assert checkpoint.slot == slot
        assert isinstance(checkpoint.root, Bytes32)
        assert isinstance(checkpoint.slot, Slot)

    def test_checkpoint_root_validation(self) -> None:
        """Test checkpoint root field validation."""
        # Test with valid 32-byte root
        valid_root = Bytes32(b"a" * 32)
        checkpoint = Checkpoint(root=valid_root, slot=Slot(0))
        assert len(checkpoint.root) == 32

    def test_checkpoint_slot_validation(self) -> None:
        """Test checkpoint slot field validation."""
        root = Bytes32(b"test" + b"\x00" * 28)

        # Test various slot values
        checkpoint_0 = Checkpoint(root=root, slot=Slot(0))
        checkpoint_large = Checkpoint(root=root, slot=Slot(999999))

        assert checkpoint_0.slot == Slot(0)
        assert checkpoint_large.slot == Slot(999999)
        assert checkpoint_0.slot < checkpoint_large.slot
