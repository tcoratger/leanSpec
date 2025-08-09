"""Specification for the Poseidon2 permutation."""

from .constants import ROUND_CONSTANTS_16, ROUND_CONSTANTS_24
from .permutation import (
    PARAMS_16,
    PARAMS_24,
    permute,
)

__all__ = [
    "permute",
    "PARAMS_16",
    "PARAMS_24",
    "ROUND_CONSTANTS_16",
    "ROUND_CONSTANTS_24",
]
