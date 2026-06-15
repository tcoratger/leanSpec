"""Tests for the selective-check behavior of StateExpectation."""

import pytest

from consensus_testing.genesis import make_genesis_state
from consensus_testing.test_types.state_expectation import StateExpectation
from lean_spec.spec.forks import Slot


def test_set_field_matching_actual_value_passes() -> None:
    """A set field that equals the state's actual value validates without error."""
    genesis_state = make_genesis_state(num_validators=3)

    StateExpectation(slot=Slot(0)).validate_against_state(genesis_state)


def test_set_field_mismatching_actual_value_raises_with_full_message() -> None:
    """A set field that disagrees with the state raises the exact mismatch message."""
    genesis_state = make_genesis_state(num_validators=3)

    with pytest.raises(AssertionError) as assertion_failure:
        StateExpectation(slot=Slot(99)).validate_against_state(genesis_state)

    assert str(assertion_failure.value) == "State validation failed: slot = 0, expected 99"


def test_unset_field_is_never_validated() -> None:
    """An omitted field is skipped even when its actual value would mismatch."""
    genesis_state_with_five_validators = make_genesis_state(num_validators=5)

    # The expectation sets only the slot, leaving validator_count unset.
    # The state holds five validators, so a set validator_count of three would fail.
    expectation_omitting_validator_count = StateExpectation(slot=Slot(0))

    # Omission means skip, so the mismatching count is never checked.
    expectation_omitting_validator_count.validate_against_state(genesis_state_with_five_validators)

    # Setting that same field to the mismatching value does enforce it and fails.
    with pytest.raises(AssertionError) as assertion_failure:
        StateExpectation(validator_count=3).validate_against_state(
            genesis_state_with_five_validators
        )

    assert str(assertion_failure.value) == (
        "State validation failed: validator_count = 5, expected 3"
    )
