"""Tests for the pure subnet subscription planner."""

from __future__ import annotations

from lean_spec.subspecs.chain.config import ATTESTATION_COMMITTEE_COUNT
from lean_spec.subspecs.networking.gossipsub.subscription import (
    compute_subscription_subnets,
)
from lean_spec.types import SubnetId, ValidatorIndex


class TestComputeSubscriptionSubnets:
    """Tests for the pure subnet planner."""

    def test_no_validators_no_aggregator(self) -> None:
        """A passive node subscribes to no attestation subnets."""
        assert (
            compute_subscription_subnets(
                [],
                committee_count=ATTESTATION_COMMITTEE_COUNT,
                is_aggregator=False,
                extra_subnets=(),
            )
            == frozenset()
        )

    def test_validators_drive_subnets(self) -> None:
        """Validator indices contribute their derived subnet ids."""
        indices = [ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)]
        expected = frozenset(i.compute_subnet_id(ATTESTATION_COMMITTEE_COUNT) for i in indices)

        assert (
            compute_subscription_subnets(
                indices,
                committee_count=ATTESTATION_COMMITTEE_COUNT,
                is_aggregator=False,
                extra_subnets=(),
            )
            == expected
        )

    def test_extras_ignored_when_not_aggregator(self) -> None:
        """Extra subnets do nothing on a non-aggregator node."""
        assert (
            compute_subscription_subnets(
                [],
                committee_count=ATTESTATION_COMMITTEE_COUNT,
                is_aggregator=False,
                extra_subnets=(SubnetId(7), SubnetId(8)),
            )
            == frozenset()
        )

    def test_aggregator_unions_extras(self) -> None:
        """Aggregator mode unions validator-derived and extra subnets."""
        indices = [ValidatorIndex(0)]
        extras = (SubnetId(5), SubnetId(9))
        derived = {i.compute_subnet_id(ATTESTATION_COMMITTEE_COUNT) for i in indices}

        assert compute_subscription_subnets(
            indices,
            committee_count=ATTESTATION_COMMITTEE_COUNT,
            is_aggregator=True,
            extra_subnets=extras,
        ) == frozenset(derived | set(extras))
