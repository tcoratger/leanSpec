"""Tests for the rejection message matcher in the consensus fixture base module."""

import pytest

from consensus_testing.test_fixtures.base import ExpectedRejection
from lean_spec.spec.forks import RejectionReason


class TestAssertMessageMatchesExactMessage:
    """Tests for full-equality matching against exact_message."""

    def test_equal_message_passes(self) -> None:
        """A raised message equal to exact_message matches without raising."""
        expectation = ExpectedRejection(
            reason=RejectionReason.STATE_ROOT_MISMATCH,
            exact_message="state root mismatch",
        )
        expectation.assert_message_matches(ValueError("state root mismatch"), "Verifier")

    def test_message_differing_by_suffix_fails(self) -> None:
        """A raised message differing only by a trailing suffix fails full equality."""
        expectation = ExpectedRejection(
            reason=RejectionReason.STATE_ROOT_MISMATCH,
            exact_message="state root mismatch",
        )
        with pytest.raises(AssertionError) as exception_info:
            expectation.assert_message_matches(
                ValueError("state root mismatch at head"), "Verifier"
            )
        assert str(exception_info.value) == (
            "Verifier failed with wrong error message.\n"
            "  Expected exact message: 'state root mismatch'\n"
            "  Actual message: 'state root mismatch at head'"
        )


class TestAssertMessageMatchesSubstring:
    """Tests for substring matching against message_substring."""

    def test_substring_present_passes(self) -> None:
        """A raised message containing the substring matches without raising."""
        expectation = ExpectedRejection(
            reason=RejectionReason.UNKNOWN_PARENT_BLOCK,
            message_substring="parent block",
        )
        expectation.assert_message_matches(ValueError("unknown parent block"), "Verifier")

    def test_substring_absent_fails(self) -> None:
        """A raised message missing the substring fails with the full matcher message."""
        expectation = ExpectedRejection(
            reason=RejectionReason.UNKNOWN_PARENT_BLOCK,
            message_substring="missing source",
        )
        with pytest.raises(AssertionError) as exception_info:
            expectation.assert_message_matches(ValueError("unknown parent block"), "Verifier")
        assert str(exception_info.value) == (
            "Verifier failed with wrong error message.\n"
            "  Expected message containing: 'missing source'\n"
            "  Actual message: 'unknown parent block'"
        )


class TestAssertMessageMatchesPrecedence:
    """Tests pinning that exact_message governs when both fields are set."""

    def test_exact_message_rejects_a_message_that_only_contains_the_substring(self) -> None:
        """A message holding the substring but not exactly equal still fails on exact_message."""
        expectation = ExpectedRejection(
            reason=RejectionReason.STATE_ROOT_MISMATCH,
            exact_message="state root mismatch",
            message_substring="mismatch",
        )
        with pytest.raises(AssertionError) as exception_info:
            expectation.assert_message_matches(
                ValueError("state root mismatch at head"), "Verifier"
            )
        assert str(exception_info.value) == (
            "Verifier failed with wrong error message.\n"
            "  Expected exact message: 'state root mismatch'\n"
            "  Actual message: 'state root mismatch at head'"
        )

    def test_both_satisfied_passes(self) -> None:
        """A message equal to exact_message and containing the substring matches cleanly."""
        expectation = ExpectedRejection(
            reason=RejectionReason.STATE_ROOT_MISMATCH,
            exact_message="state root mismatch",
            message_substring="mismatch",
        )
        expectation.assert_message_matches(ValueError("state root mismatch"), "Verifier")
