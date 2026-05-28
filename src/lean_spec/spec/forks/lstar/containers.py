"""The container types for the Lean consensus specification."""

from typing import Self

from lean_spec.subspecs.chain.config import HISTORICAL_ROOTS_LIMIT, VALIDATOR_REGISTRY_LIMIT
from lean_spec.subspecs.xmss.aggregation import TypeOneMultiSignature
from lean_spec.subspecs.xmss.containers import PublicKey, Signature
from lean_spec.types import (
    AggregationBits,
    Boolean,
    ByteList512KiB,
    Bytes32,
    Bytes52,
    Checkpoint,
    Container,
    Slot,
    SSZList,
    Uint64,
    ValidatorIndex,
)
from lean_spec.types.bitfields import BaseBitlist


class Config(Container):
    """
    Holds temporary configuration properties for simplified consensus.

    Note: These fields support a simplified round-robin block production
    in the absence of more complex mechanisms like RANDAO or deposits.
    """

    genesis_time: Uint64
    """The timestamp of the genesis block."""


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


class AttestationData(Container):
    """Attestation content describing the validator's observed chain view."""

    slot: Slot
    """The slot for which the attestation is made."""

    head: Checkpoint
    """The checkpoint representing the head block as observed by the validator."""

    target: Checkpoint
    """The checkpoint representing the target block as observed by the validator."""

    source: Checkpoint
    """The checkpoint representing the source block as observed by the validator."""


class Attestation(Container):
    """Validator specific attestation wrapping shared attestation data."""

    validator_id: ValidatorIndex
    """The index of the validator making the attestation."""

    data: AttestationData
    """The attestation data produced by the validator."""


class SignedAttestation(Attestation):
    """Validator attestation bundled with its signature."""

    signature: Signature
    """Signature aggregation produced by the leanVM (SNARKs in the future)."""


class AggregatedAttestation(Container):
    """Aggregated attestation consisting of participation bits and message."""

    aggregation_bits: AggregationBits
    """Bitfield indicating which validators participated in the aggregation."""

    data: AttestationData
    """Combined attestation data similar to the beacon chain format.

    Multiple validator attestations are aggregated here without the complexity of
    committee assignments.
    """


class SignedAggregatedAttestation(Container):
    """
    A signed aggregated attestation for broadcasting.

    Contains the attestation data and the aggregated signature proof.
    """

    data: AttestationData
    """Combined attestation data similar to the beacon chain format."""

    proof: TypeOneMultiSignature
    """Aggregated single-message proof covering all participating validators."""


class AggregatedAttestations(SSZList[AggregatedAttestation]):
    """List of aggregated attestations included in a block."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class BlockBody(Container):
    """Payload of a block containing attestations."""

    attestations: AggregatedAttestations
    """Attestations in the block. Signatures are folded into the block-level proof."""


class BlockHeader(Container):
    """
    Metadata summarizing a block.

    Contains parent reference, state root, and body hash.
    Smaller than full blocks.
    """

    slot: Slot
    """The slot in which the block was proposed."""

    proposer_index: ValidatorIndex
    """The index of the validator that proposed the block."""

    parent_root: Bytes32
    """The root of the parent block."""

    state_root: Bytes32
    """The root of the state after applying transactions in this block."""

    body_root: Bytes32
    """The root of the block body."""


class Block(Container):
    """A complete block including header and body."""

    slot: Slot
    """The slot in which the block was proposed."""

    proposer_index: ValidatorIndex
    """The index of the validator that proposed the block."""

    parent_root: Bytes32
    """The root of the parent block."""

    state_root: Bytes32
    """The root of the state after applying transactions in this block."""

    body: BlockBody
    """The block's payload."""


class SignedBlock(Container):
    """Envelope carrying a block with a single aggregated proof for all signatures.

    The proof is the SSZ-encoded form of a Type-2 multi-message proof that
    binds every attestation in the body plus the proposer's signature over
    the block root.
    """

    block: Block
    """The block being signed."""

    proof: ByteList512KiB
    """Single full-block proof covering attestations and the proposer signature."""


class HistoricalBlockHashes(SSZList[Bytes32]):
    """List of historical block root hashes up to historical roots limit."""

    LIMIT = int(HISTORICAL_ROOTS_LIMIT)


class JustificationRoots(SSZList[Bytes32]):
    """List of justified block roots up to historical roots limit."""

    LIMIT = int(HISTORICAL_ROOTS_LIMIT)


class JustifiedSlots(BaseBitlist):
    """Bitlist tracking justified slots up to historical roots limit."""

    LIMIT = int(HISTORICAL_ROOTS_LIMIT)

    def is_slot_justified(self, finalized_slot: Slot, target_slot: Slot) -> Boolean:
        """
        Determine if a specific slot is considered justified.

        The check follows these rules:
        - Slots at or before the finalized boundary are implicitly justified.
        - Future slots are checked against the tracked bitfield.

        Args:
            finalized_slot: The anchor point for the tracking window.
            target_slot: The slot to query.

        Returns:
            True if the slot is justified or finalized, False otherwise.

        Raises:
            IndexError: If the target slot is active but outside the tracked range.
        """
        # First, determine the position of the target relative to the anchor.
        #
        # If the result is None, the slot is behind the finalized boundary.
        # By definition, finalized slots are justified.
        if (relative_index := target_slot.justified_index_after(finalized_slot)) is None:
            return Boolean(True)

        # Check the tracked bitfield for the slot's status.
        #
        # We assume the slot is within the tracked range.
        #
        # If the caller asks for a slot too far in the future, it indicates a logic error.
        try:
            return self[relative_index]
        except IndexError as e:
            raise IndexError(
                f"Slot {target_slot} is outside the tracked range "
                f"(finalized_boundary={finalized_slot}, tracked_length={len(self)})"
            ) from e

    def with_justified(
        self,
        finalized_slot: Slot,
        target_slot: Slot,
        value: Boolean,
    ) -> Self:
        """
        Return a new bitfield with the justification status updated.

        This method follows the immutable pattern:
        - Returns 'self' if the slot is finalized (immutable).
        - Returns a clone with the specific bit updated for active slots.

        Args:
            finalized_slot: The anchor point for the tracking window.
            target_slot: The slot to update.
            value: The new justification status.

        Returns:
            A new, updated JustifiedSlots instance.

        Raises:
            IndexError: If the target slot is active but outside the tracked range.
        """
        # Determine the position of the target relative to the anchor.
        #
        # If the slot is behind the finalized boundary, we return 'self' unchanged.
        # We cannot modify the status of finalized history, and treating it as a
        # no-op preserves the immutability of the conceptual chain history.
        if (relative_index := target_slot.justified_index_after(finalized_slot)) is None:
            return self

        # Ensure we are not trying to write to a future slot that does not exist
        # in our tracking list yet. The state must be explicitly extended first.
        if relative_index >= len(self):
            raise IndexError(
                f"Slot {target_slot} is outside the tracked range "
                f"(finalized_boundary={finalized_slot}, tracked_length={len(self)})"
            )

        # Clone and update in one smooth operation.
        #
        # 1. Create a shallow copy of the data list to avoid mutating the original.
        # 2. Update the specific bit in the copy.
        # 3. Use model_copy to return a new instance with the updated data.
        new_data = list(self.data)
        new_data[relative_index] = value

        return self.model_copy(update={"data": new_data})

    def extend_to_slot(self, finalized_slot: Slot, target_slot: Slot) -> Self:
        """
        Extend the tracking capacity to cover a new target slot.

        This prepares the state to process a new block by ensuring the
        bitfield is long enough to store its justification status.
        Gaps are filled with False (unjustified).

        Args:
            finalized_slot: The anchor point for the tracking window.
            target_slot: The slot that must be addressable.

        Returns:
            A new instance with sufficient capacity.
        """
        # Calculate the index required to store the status of the target.
        #
        # If the target is already finalized, no extension is needed because
        # we don't track finalized data.
        if (relative_index := target_slot.justified_index_after(finalized_slot)) is None:
            return self

        # Calculate how many new entries we need to append.
        #
        # Since indices are zero-based, the required capacity is index + 1.
        # If we already have enough capacity, the gap will be zero or negative.
        required_capacity = relative_index + 1
        if (gap_size := required_capacity - len(self)) <= 0:
            return self

        # Return a new instance with the extended data list.
        #
        # We extend the existing data with False values to bridge the gap.
        return self.model_copy(update={"data": list(self.data) + [Boolean(False)] * gap_size})

    def shift_window(self, delta: int) -> Self:
        """
        Advance the tracking window by dropping slots that became finalized.

        A non-positive delta keeps the tracking window unchanged.
        """
        # If the boundary hasn't moved forward, the window stays the same.
        if delta <= 0:
            return self

        # Return a new instance containing only the relevant subset of data.
        return self.model_copy(update={"data": self.data[delta:]})


class JustificationValidators(BaseBitlist):
    """Per-root validator vote bitfields, concatenated into one flat bitlist.

    Each tracked root contributes one bit per registered validator.
    The cap is the maximum tracked roots times the validator registry limit.

    Why this product: a larger cap inflates the bitlist's merkle tree depth.
    That changes the state root for identical data, so this limit is consensus-critical.
    """

    LIMIT = int(HISTORICAL_ROOTS_LIMIT) * int(VALIDATOR_REGISTRY_LIMIT)


class State(Container):
    """The main consensus state object."""

    # Configuration
    config: Config
    """The chain's configuration parameters."""

    # Slot and block tracking
    slot: Slot
    """The current slot number."""

    latest_block_header: BlockHeader
    """The header of the most recent block."""

    # Checkpoints
    latest_justified: Checkpoint
    """The latest justified checkpoint."""

    latest_finalized: Checkpoint
    """The latest finalized checkpoint."""

    # Historical data
    historical_block_hashes: HistoricalBlockHashes
    """A list of historical block root hashes."""

    justified_slots: JustifiedSlots
    """A bitfield indicating which historical slots were justified."""

    validators: Validators
    """Registry of validators tracked by the state."""

    # Justification tracking (flattened for SSZ compatibility)
    justifications_roots: JustificationRoots
    """Roots of justified blocks."""

    justifications_validators: JustificationValidators
    """A bitlist of validators who participated in justifications."""
