"""Tests for SubnetId and ValidatorIndex scalar types."""

import pytest

from lean_spec.spec.forks import Slot, SubnetId, ValidatorIndex
from lean_spec.spec.ssz import Uint64


class TestSubnetId:
    """Construction and type identity for the subnet identifier."""

    def test_inherits_from_uint64(self) -> None:
        """The subnet identifier is a Uint64 subclass."""
        assert issubclass(SubnetId, Uint64)

    def test_instance_is_both_subnet_id_and_uint64(self) -> None:
        """An instance carries the subnet identity and the underlying integer type."""
        subnet = SubnetId(7)
        assert isinstance(subnet, SubnetId)
        assert isinstance(subnet, Uint64)
        assert int(subnet) == 7


class TestValidatorIndex:
    """Construction and type identity for the validator index."""

    def test_inherits_from_uint64(self) -> None:
        """The validator index is a Uint64 subclass."""
        assert issubclass(ValidatorIndex, Uint64)

    def test_instance_is_both_validator_index_and_uint64(self) -> None:
        """An instance carries the validator identity and the underlying integer type."""
        index = ValidatorIndex(42)
        assert isinstance(index, ValidatorIndex)
        assert isinstance(index, Uint64)
        assert int(index) == 42


class TestProposerForSlot:
    """Round-robin proposer selection by slot modulo the registry size."""

    @pytest.mark.parametrize(
        ("slot", "num_validators", "expected_proposer_index"),
        [
            # In-range slot, no wrap past the registry size.
            (0, 10, 0),
            (7, 10, 7),
            (9, 10, 9),
            # Wraparound past the registry size.
            (10, 10, 0),
            (23, 10, 3),
            (100, 10, 0),
            # Single-validator registry: index zero proposes every slot.
            (0, 1, 0),
            (1, 1, 0),
            (1_000_000, 1, 0),
            # Larger registry, large slot.
            (12_345, 1_000, 345),
        ],
    )
    def test_round_robin_assignment(
        self, slot: int, num_validators: int, expected_proposer_index: int
    ) -> None:
        """The proposer for a given slot is the slot modulo the registry size."""
        assert ValidatorIndex.proposer_for_slot(
            Slot(slot), Uint64(num_validators)
        ) == ValidatorIndex(expected_proposer_index)

    def test_return_type_is_validator_index(self) -> None:
        """The classmethod returns a strict ValidatorIndex, not a plain int."""
        proposer_index = ValidatorIndex.proposer_for_slot(Slot(5), Uint64(7))
        assert isinstance(proposer_index, ValidatorIndex)


class TestIsWithinRegistry:
    """Bounds check for validator indices against the registry size."""

    @pytest.mark.parametrize(
        ("index", "num_validators", "expected"),
        [
            # Strictly within the registry.
            (0, 10, True),
            (5, 10, True),
            (9, 10, True),
            # Right at the boundary.
            (4, 5, True),
            (5, 5, False),
            # Out of bounds.
            (10, 10, False),
            (100, 10, False),
            # Single-validator registry: only index zero is in range.
            (0, 1, True),
            (1, 1, False),
        ],
    )
    def test_is_in_bounds(self, index: int, num_validators: int, expected: bool) -> None:
        """An index is valid exactly when it is strictly less than the registry size."""
        assert ValidatorIndex(index).is_within_registry(Uint64(num_validators)) is expected


class TestComputeSubnetId:
    """Subnet assignment by validator index modulo committee count."""

    @pytest.mark.parametrize(
        ("validator_index", "num_committees", "expected_subnet_id"),
        [
            # No wrap: validator index already inside the committee range.
            (0, 8, 0),
            (3, 8, 3),
            (7, 8, 7),
            # Wraparound past the committee count.
            (8, 8, 0),
            (15, 8, 7),
            (16, 8, 0),
            # Single committee: every validator maps to subnet zero.
            (0, 1, 0),
            (1, 1, 0),
            (12_345, 1, 0),
            # Realistic distribution: 64 committees with a large validator index.
            (1_000_000, 64, 1_000_000 % 64),
        ],
    )
    def test_modulo_committee_count(
        self, validator_index: int, num_committees: int, expected_subnet_id: int
    ) -> None:
        """The subnet for a validator is its index modulo the committee count."""
        assert ValidatorIndex(validator_index).compute_subnet_id(
            Uint64(num_committees)
        ) == SubnetId(expected_subnet_id)

    def test_return_type_is_subnet_id(self) -> None:
        """The method returns a strict SubnetId, not a plain Uint64 or int."""
        subnet_id = ValidatorIndex(5).compute_subnet_id(Uint64(64))
        assert isinstance(subnet_id, SubnetId)
