"""Checkpoint Container."""

from pydantic import BaseModel, ConfigDict

from ..types import Bytes32, uint64


class Checkpoint(BaseModel):
    """Represents a checkpoint in the chain's history."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    root: Bytes32
    """The root hash of the checkpoint's block."""

    slot: uint64
    """The slot number of the checkpoint's block."""
