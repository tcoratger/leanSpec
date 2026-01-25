"""Aggregation bits for tracking validator participation."""

from __future__ import annotations

from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.types import Boolean, Uint64
from lean_spec.types.bitfields import BaseBitlist


class AggregationBits(BaseBitlist):
    """
    Bitlist representing validator participation in an attestation or signature.

    A general-purpose bitfield for tracking which validators have participated
    in some collective action (attestation, signature aggregation, etc.).
    """

    LIMIT = VALIDATOR_REGISTRY_LIMIT

    @classmethod
    def from_validator_indices(cls, indices: list[Uint64]) -> AggregationBits:
        """
        Construct aggregation bits from a set of validator indices.

        Args:
            indices: Validator indices to set in the bitlist.

        Returns:
            AggregationBits with the corresponding indices set to True.

        Raises:
            AssertionError: If no indices are provided.
            AssertionError: If any index is outside the supported LIMIT.
        """
        # Require at least one validator for a valid aggregation.
        if not indices:
            raise AssertionError("Aggregated attestation must reference at least one validator")

        # Convert to a set of native ints.
        #
        # This combines int conversion and deduplication in a single O(N) pass.
        ids = {int(i) for i in indices}

        # Validate bounds: max index must be within registry limit.
        if (max_id := max(ids)) >= cls.LIMIT:
            raise AssertionError("Validator index out of range for aggregation bits")

        # Build bit list:
        # - True at positions present in indices,
        # - False elsewhere.
        return cls(data=[Boolean(i in ids) for i in range(max_id + 1)])

    def to_validator_indices(self) -> list[Uint64]:
        """
        Extract all validator indices encoded in these aggregation bits.

        Returns:
            List of validator indices, sorted in ascending order.

        Raises:
            AssertionError: If no bits are set.
        """
        # Extract indices where bit is set; fail if none found.
        if not (indices := [Uint64(i) for i, bit in enumerate(self.data) if bool(bit)]):
            raise AssertionError("Aggregated attestation must reference at least one validator")

        return indices
