"""Vote Containers."""

from pydantic import BaseModel, ConfigDict

from ..types import Bytes32, uint64
from .checkpoint import Checkpoint


class Vote(BaseModel):
    """Represents a validator's vote for chain head."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    validator_id: uint64
    """The index of the voting validator."""

    slot: uint64
    """The slot for which this vote is cast."""

    head: Checkpoint
    """The validator's perceived head of the chain."""

    target: Checkpoint
    """The justified checkpoint the validator is voting for."""

    source: Checkpoint
    """The last justified checkpoint known to the validator."""


class SignedVote(BaseModel):
    """A container for a vote and its corresponding signature."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    data: Vote
    """The vote data."""

    signature: Bytes32
    """
    The signature of the vote data.

    Note: Bytes32 is a placeholder; the actual signature is much larger.
    """
