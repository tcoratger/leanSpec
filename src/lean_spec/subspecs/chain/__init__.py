"""Specifications for chain and consensus parameters."""

from .clock import Interval, SlotClock
from .config import DEVNET_CONFIG

__all__ = [
    "DEVNET_CONFIG",
    "Interval",
    "SlotClock",
]
