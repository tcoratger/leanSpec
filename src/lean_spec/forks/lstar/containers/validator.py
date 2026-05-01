"""Validator container for the Lean Ethereum consensus specification."""

from __future__ import annotations

import lean_spec.forks.lstar.containers.attestation.aggregation_bits as _aggregation_bits
from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.subspecs.xmss.containers import PublicKey
from lean_spec.types import Boolean, Bytes52, Container, SSZList, ValidatorIndex


class ValidatorIndices(SSZList[ValidatorIndex]):
    """List of validator indices up to registry limit."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    def to_aggregation_bits(self) -> _aggregation_bits.AggregationBits:
        """
        Convert to aggregation bits marking which validators are present.

        Returns:
            AggregationBits with the corresponding indices set to True.

        Raises:
            AssertionError: If no indices are provided.
            AssertionError: If any index is outside the supported LIMIT.
        """
        index_list = self.data

        # Require at least one validator for a valid aggregation.
        if not index_list:
            raise AssertionError("Aggregated attestation must reference at least one validator")

        # Convert to a set of native ints.
        #
        # This combines int conversion and deduplication in a single O(N) pass.
        ids = {int(i) for i in index_list}

        # Validate bounds: max index must be within registry limit.
        if (max_id := max(ids)) >= _aggregation_bits.AggregationBits.LIMIT:
            raise AssertionError("Validator index out of range for aggregation bits")

        # Build bit list:
        # - True at positions present in indices,
        # - False elsewhere.
        return _aggregation_bits.AggregationBits(
            data=[Boolean(i in ids) for i in range(max_id + 1)]
        )


class Validator(Container):
    """Represents a validator's static metadata and operational interface."""

    attestation_pubkey: Bytes52
    """XMSS public key for signing attestations."""

    proposal_pubkey: Bytes52
    """XMSS public key for signing proposer attestations in blocks."""

    index: ValidatorIndex = ValidatorIndex(0)
    """Validator index in the registry."""

    def get_attestation_pubkey(self) -> PublicKey:
        """Get the XMSS public key used for attestation verification."""
        return PublicKey.decode_bytes(bytes(self.attestation_pubkey))

    def get_proposal_pubkey(self) -> PublicKey:
        """Get the XMSS public key used for proposer attestation verification."""
        return PublicKey.decode_bytes(bytes(self.proposal_pubkey))


class Validators(SSZList[Validator]):
    """Validator registry tracked in the state."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
