"""
Chain and Consensus Configuration Specification

This file defines the core consensus parameters and chain presets for the
Lean Consensus Experimental Chain.
"""

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import Annotated

# The maximum value for an unsigned 64-bit integer (2**64).
UINT64_MAX = 2**64

# A type alias to represent a uint64.
uint64 = Annotated[int, Field(ge=0, lt=UINT64_MAX)]

# A type alias for basis points, now based on the uint64 type.
#
# A basis point (bps) is 1/100th of a percent. 100% = 10,000 bps.
BasisPoint = Annotated[
    uint64,
    Field(le=10000, description="A value in basis points (1/10000)."),
]


class ChainConfig(BaseModel):
    """
    A model holding the canonical, immutable configuration constants
    for the chain.

    These parameters are considered "presets" and define the fundamental rules
    of the consensus protocol.
    """

    # Configuration to make the model immutable.
    model_config = ConfigDict(frozen=True, extra="forbid")

    # =========================================================================
    # Time Parameters
    #
    # These constants define the timing and deadlines within a single slot.
    # =========================================================================

    SLOT_DURATION_MS: uint64 = Field(
        default=4000,
        description="The fixed duration of a single slot in milliseconds.",
    )

    PROPOSER_REORG_CUTOFF_BPS: BasisPoint = Field(
        default=2500,
        description=(
            "The deadline within a slot (in basis points) for a proposer to "
            "publish a block. Honest validators may re-org blocks published "
            "after this cutoff. (2500 bps = 25% of slot duration)."
        ),
    )

    VOTE_DUE_BPS: BasisPoint = Field(
        default=5000,
        description=(
            "The deadline within a slot (in basis points) by which validators "
            "must submit their votes. (5000 bps = 50% of slot duration)."
        ),
    )

    FAST_CONFIRM_DUE_BPS: BasisPoint = Field(
        default=7500,
        description=(
            "The deadline within a slot (in basis points) for achieving a "
            "fast confirmation. (7500 bps = 75% of slot duration)."
        ),
    )

    VIEW_FREEZE_CUTOFF_BPS: BasisPoint = Field(
        default=7500,
        description=(
            "The cutoff within a slot (in basis points) after which the "
            "current view is considered 'frozen', preventing further changes. "
            "(7500 bps = 75% of slot duration)."
        ),
    )

    # =========================================================================
    # State List Length Presets
    #
    # These constants define the maximum capacity of certain data structures
    # within the consensus state, preventing unbounded growth.
    # =========================================================================

    HISTORICAL_ROOTS_LIMIT: uint64 = Field(
        default=2**18,
        description=(
            "The maximum number of historical block roots to store in the "
            "state. With a 4-second slot, this corresponds to a history of "
            "approximately 12.1 days."
        ),
    )

    VALIDATOR_REGISTRY_LIMIT: uint64 = Field(
        default=2**12,
        description=(
            "The maximum number of validators that can be in the registry."
        ),
    )


# Global constant for the devnet chain configuration.
DEVNET_CONFIG = ChainConfig()
