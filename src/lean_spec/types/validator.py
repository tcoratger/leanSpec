"""Validator-side scalar types — fork-stable.

Defines the integer-keyed validator identifier and the networking subnet id.
The XMSS-bound `Validator` container itself stays in the fork package because
its key shape is signature-scheme specific.
"""

from lean_spec.types.slot import Slot
from lean_spec.types.uint import Uint64


class SubnetId(Uint64):
    """Subnet identifier (0-63) for attestation subnet partitioning."""


class ValidatorIndex(Uint64):
    """Represents a validator's unique index as a 64-bit unsigned integer."""

    def is_proposer_for(self, slot: Slot, num_validators: Uint64) -> bool:
        """
        Check if this validator is the proposer for the given slot.

        Uses round-robin proposer selection per the lean protocol spec.
        """
        return int(slot) % int(num_validators) == int(self)

    def is_valid(self, num_validators: Uint64) -> bool:
        """Check if this index is within valid bounds for a registry of given size."""
        return int(self) < int(num_validators)

    def compute_subnet_id(self, num_committees: Uint64) -> SubnetId:
        """Compute the attestation subnet id for this validator.

        Args:
            num_committees: Positive number of committees.

        Returns:
            A SubnetId in 0..(num_committees-1).
        """
        return SubnetId(int(self) % int(num_committees))
