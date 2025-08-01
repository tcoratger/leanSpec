"""Specification for the Poseidon2 permutation."""

from .permutation import (
    PARAMS_16,
    PARAMS_24,
    permute,
)

__all__ = [
    "permute",
    "PARAMS_16",
    "PARAMS_24",
]
