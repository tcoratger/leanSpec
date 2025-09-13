"""
Forkchoice algorithm constants.

Time-related constants for forkchoice processing and slot timing.
"""

from lean_spec.types import Bytes32

# Time constants
SECONDS_PER_SLOT = 4
"""Seconds per slot in the beacon chain."""

INTERVALS_PER_SLOT = 4
"""Number of intervals per slot for forkchoice processing."""

SECONDS_PER_INTERVAL = SECONDS_PER_SLOT // INTERVALS_PER_SLOT
"""Seconds per forkchoice processing interval."""

# Special values
ZERO_HASH = Bytes32.zero()
"""All-zero hash used as genesis parent."""
