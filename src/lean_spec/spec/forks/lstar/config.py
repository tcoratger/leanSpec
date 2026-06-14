"""Chain and Consensus Configuration Specification"""

from typing import Final

from lean_spec.spec.ssz import Uint8, Uint64

__all__ = [
    "ATTESTATION_COMMITTEE_COUNT",
    "GOSSIP_DISPARITY_INTERVALS",
    "HISTORICAL_ROOTS_LIMIT",
    "INTERVALS_PER_SLOT",
    "JUSTIFICATION_LOOKBACK_SLOTS",
    "MAX_ATTESTATIONS_DATA",
    "MAX_SLOTS_PER_IMPORT",
    "MILLISECONDS_PER_INTERVAL",
    "MILLISECONDS_PER_SLOT",
    "SECONDS_PER_SLOT",
    "VALIDATOR_REGISTRY_LIMIT",
]

INTERVALS_PER_SLOT: Final = Uint64(5)
"""Number of intervals per slot for forkchoice processing."""

GOSSIP_DISPARITY_INTERVALS: Final = Uint64(1)
"""
Future-slot tolerance for gossip attestations, in intervals.

Bounds the clock skew the time check is willing to absorb when admitting
a vote whose slot has not yet started locally.

One interval is roughly 800 ms.
"""

SECONDS_PER_SLOT: Final = Uint64(4)
"""The fixed duration of a single slot in seconds."""

MILLISECONDS_PER_SLOT: Final = SECONDS_PER_SLOT * Uint64(1000)
"""The fixed duration of a single slot in milliseconds."""

MILLISECONDS_PER_INTERVAL: Final = MILLISECONDS_PER_SLOT // INTERVALS_PER_SLOT
"""Milliseconds per forkchoice processing interval."""

JUSTIFICATION_LOOKBACK_SLOTS: Final = Uint64(3)
"""The number of slots to lookback for justification."""

HISTORICAL_ROOTS_LIMIT: Final = Uint64(2**18)
"""
The maximum number of historical block roots to store in the state.

With a 4-second slot, this corresponds to a history of approximately 12.1 days.
"""

MAX_SLOTS_PER_IMPORT: Final = HISTORICAL_ROOTS_LIMIT
"""
Largest slot gap a single block may advance the state across during import.

Slot processing walks one state copy per skipped slot and appends one history
entry per skipped slot.
A block whose slot exceeds the current state slot by more than the historical
roots capacity would overflow the history list anyway, so it can never extend
the chain.
Bounding the advance here turns an unbounded loop on a far-future wire slot into
a clean rejection instead of an effective hang.
"""

ATTESTATION_COMMITTEE_COUNT: Final = Uint64(1)
"""The number of attestation committees per slot."""

VALIDATOR_REGISTRY_LIMIT: Final = Uint64(2**12)
"""The maximum number of validators that can be in the registry."""

MAX_ATTESTATIONS_DATA: Final = Uint8(8)
"""Maximum number of distinct attestation data entries per block."""
