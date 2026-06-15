"""Tests for consensus_testing.rejection."""

from __future__ import annotations

import pytest

from consensus_testing.rejection import classify_rejection
from lean_spec.spec.forks import RejectionReason, SpecRejectionError
from lean_spec.spec.forks.lstar.containers import AggregationError


def test_spec_rejection_error_returns_its_carried_reason() -> None:
    """A SpecRejectionError resolves to the reason it carries."""
    rejection = SpecRejectionError(RejectionReason.STATE_ROOT_MISMATCH, "state root drift")
    assert classify_rejection(rejection) == RejectionReason.STATE_ROOT_MISMATCH


def test_aggregation_error_returns_invalid_signature() -> None:
    """An AggregationError resolves to the INVALID_SIGNATURE reason."""
    assert classify_rejection(AggregationError("proof failed")) == RejectionReason.INVALID_SIGNATURE


def test_exception_without_reason_raises_value_error_with_full_message() -> None:
    """An exception carrying no reason raises ValueError with the full guidance message."""
    with pytest.raises(ValueError) as exception_info:
        classify_rejection(ValueError("x"))
    assert str(exception_info.value) == (
        "no rejection reason carried by ValueError: x\n"
        "Spec rejections must raise the typed rejection error with a reason."
    )
