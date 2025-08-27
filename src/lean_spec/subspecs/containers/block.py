"""Block Containers."""

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import Annotated

from ..chain import config
from ..types import Bytes32, uint64
from .vote import Vote


class BlockBody(BaseModel):
    """The body of a block, containing payload data."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    votes: Annotated[
        list[Vote],
        Field(max_length=config.VALIDATOR_REGISTRY_LIMIT),
    ]
    """
    A list of votes included in the block.

    Note: This will eventually be replaced by aggregated attestations.
    """


class BlockHeader(BaseModel):
    """The header of a block, containing metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    slot: uint64
    """The slot in which the block was proposed."""

    proposer_index: uint64
    """The index of the validator that proposed the block."""

    parent_root: Bytes32
    """The root of the parent block."""

    state_root: Bytes32
    """The root of the state after processing the block."""

    body_root: Bytes32
    """The root of the block's body."""


class Block(BaseModel):
    """Represents a single block in the chain."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    slot: uint64
    """The slot in which the block was proposed."""

    proposer_index: uint64
    """The index of the validator that proposed the block."""

    parent_root: Bytes32
    """The root of the parent block."""

    state_root: Bytes32
    """The root of the state after applying transactions in this block."""

    body: BlockBody
    """The block's payload."""


class SignedBlock(BaseModel):
    """A container for a block and the proposer's signature."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    message: Block
    """The block data that was signed."""

    signature: Bytes32
    """
    The proposer's signature of the block message.

    Note: Bytes32 is a placeholder; the actual signature is much larger.
    """
