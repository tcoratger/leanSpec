"""Unit tests for advancing checkpoints by slot."""

from __future__ import annotations

from lean_spec.types import Bytes32, Checkpoint, Slot

# Two distinct roots to verify slot drives the choice, not root content.
ROOT_A = Bytes32(b"\xa0" * 32)
ROOT_B = Bytes32(b"\xb0" * 32)


def test_advance_to_returns_candidate_on_higher_slot() -> None:
    """A candidate at a strictly higher slot replaces the receiver."""
    current = Checkpoint(root=ROOT_A, slot=Slot(3))
    candidate = Checkpoint(root=ROOT_B, slot=Slot(4))
    assert current.advance_to(candidate) == candidate


def test_advance_to_keeps_self_on_lower_slot() -> None:
    """A candidate at a lower slot is ignored."""
    current = Checkpoint(root=ROOT_A, slot=Slot(4))
    candidate = Checkpoint(root=ROOT_B, slot=Slot(3))
    assert current.advance_to(candidate) == current


def test_advance_to_keeps_self_on_slot_tie() -> None:
    """On a slot tie the receiver wins regardless of root."""
    current = Checkpoint(root=ROOT_A, slot=Slot(7))
    candidate = Checkpoint(root=ROOT_B, slot=Slot(7))
    assert current.advance_to(candidate) == current
    # Symmetric: the receiver of the call always wins on a tie.
    assert candidate.advance_to(current) == candidate


def test_advance_to_is_idempotent() -> None:
    """Calling against the same checkpoint returns the receiver unchanged."""
    cp = Checkpoint(root=ROOT_A, slot=Slot(2))
    assert cp.advance_to(cp) == cp
