"""
Block containers for Lean Ethereum consensus.

Blocks propose changes to the chain.
Each references its parent, forming a chain.
The proposer is determined by slot assignment.
"""

from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.types import Bytes32, Slot, ValidatorIndex
from lean_spec.types.container import Container

from .types import (
    AggregatedAttestations,
    AttestationSignatures,
)


class BlockBody(Container):
    """Payload of a block containing attestations."""

    attestations: AggregatedAttestations
    """Attestations in the block. Signatures are in BlockSignatures."""


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


BlockLookup = dict[Bytes32, Block]
"""Mapping from block root to Block objects."""


class BlockSignatures(Container):
    """Aggregated signature payload for a block."""

    attestation_signatures: AttestationSignatures
    """Aggregated signatures for attestations in the block body."""

    proposer_signature: Signature
    """Signature over the block root using the proposer's proposal key."""


class SignedBlock(Container):
    """Envelope carrying a block and its aggregated signatures."""

    block: Block
    """The block being signed."""

    signature: BlockSignatures
    """Aggregated signature payload for the block."""
