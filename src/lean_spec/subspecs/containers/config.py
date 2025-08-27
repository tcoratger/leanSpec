"""Consensus Configuration Container."""

from pydantic import BaseModel, ConfigDict

from ..types import uint64


class Config(BaseModel):
    """
    Holds temporary configuration properties for simplified consensus.

    Note: These fields support a simplified round-robin block production
    in the absence of more complex mechanisms like RANDAO or deposits.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    num_validators: uint64
    """The total number of validators in the network."""

    genesis_time: uint64
    """The timestamp of the genesis block."""
