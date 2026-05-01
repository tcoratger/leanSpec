"""
The container types for the Lean consensus specification.

All containers use SSZ encoding. SSZ provides deterministic serialization and
efficient merkleization.

Hash functions used for merkleization differ by devnet. Early devnets use
SHA256. Later devnets will switch to Poseidon1 for better SNARK compatibility.
"""

from .attestation import (
    AggregatedAttestation,
    AggregationBits,
    Attestation,
    AttestationData,
    SignedAggregatedAttestation,
    SignedAttestation,
)
from .block import (
    Block,
    BlockBody,
    BlockHeader,
    SignedBlock,
)
from .config import Config
from .validator import Validator, ValidatorIndices

__all__ = [
    "AggregatedAttestation",
    "AggregationBits",
    "Attestation",
    "AttestationData",
    "Block",
    "BlockBody",
    "BlockHeader",
    "Config",
    "SignedAggregatedAttestation",
    "SignedAttestation",
    "SignedBlock",
    "Validator",
    "ValidatorIndices",
]
