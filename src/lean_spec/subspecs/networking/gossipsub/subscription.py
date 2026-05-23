"""
Subnet subscription planning for the node.

Maps validator identity and aggregator role to the set of attestation
subnets the node must subscribe to at boot. Separated from networking
lifecycle so it can be tested as a pure function and so the spec rule
("aggregators advertise extra subnets, validators always sit on their
own subnet") lives in one readable place.
"""

from __future__ import annotations

from collections.abc import Iterable

from lean_spec.types import SubnetId, Uint64, ValidatorIndex


def compute_subscription_subnets(
    validator_indices: Iterable[ValidatorIndex],
    *,
    committee_count: Uint64,
    is_aggregator: bool,
    extra_subnets: Iterable[SubnetId] = (),
) -> frozenset[SubnetId]:
    """
    Compute the set of attestation subnets the node must subscribe to.

    Validator-derived subnets are the load-bearing ones: missing them
    breaks the attestation mesh for the owned validators. The aggregator
    extras are advisory subnets the operator wants this node to also see.

    Args:
        validator_indices: Validator indices this node owns secret keys for.
        committee_count: ATTESTATION_COMMITTEE_COUNT for the active fork;
            decides which subnet a given validator hashes to.
        is_aggregator: True if the node is configured to aggregate. When
            False, extra_subnets is ignored even if non-empty.
        extra_subnets: Additional subnets requested by the operator (only
            consulted when is_aggregator is True).

    Returns:
        Immutable set of subnet ids; empty when there are no validators and
        the node is not configured as an aggregator.

    Notes:
        The spec is silent on the aggregator-without-validators corner;
        callers are expected to reject that combination upstream rather
        than expecting a magic fallback here.
    """
    derived = {idx.compute_subnet_id(committee_count) for idx in validator_indices}
    if is_aggregator:
        derived.update(extra_subnets)
    return frozenset(derived)
