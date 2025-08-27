"""Consensus Configuration Container."""

from ..types import StrictBaseModel, uint64


class Config(StrictBaseModel):
    """
    Holds temporary configuration properties for simplified consensus.

    Note: These fields support a simplified round-robin block production
    in the absence of more complex mechanisms like RANDAO or deposits.
    """

    num_validators: uint64
    """The total number of validators in the network."""

    genesis_time: uint64
    """The timestamp of the genesis block."""
