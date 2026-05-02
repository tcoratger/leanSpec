"""Multi-fork dispatch layer for leanSpec consensus specification."""

from .lstar.containers import (
    AggregatedAttestation,
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    BlockHeader,
    Config,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    Validator,
)
from .lstar.containers.block import BlockLookup, BlockSignatures
from .lstar.containers.block.types import AggregatedAttestations, AttestationSignatures
from .lstar.containers.state import State, Validators
from .lstar.spec import LstarSpec
from .lstar.store import AttestationSignatureEntry, Store
from .protocol import ForkProtocol, SpecStateType, SpecStoreType
from .registry import ForkRegistry

FORK_SEQUENCE: list[ForkProtocol] = [LstarSpec()]
"""Ordered oldest to newest. ForkRegistry enforces strictly increasing VERSION."""

DEFAULT_REGISTRY: ForkRegistry = ForkRegistry(FORK_SEQUENCE)
"""Shared registry over the registered forks. Convenient for top-level callers."""

__all__ = [
    "AggregatedAttestation",
    "AggregatedAttestations",
    "Attestation",
    "AttestationData",
    "AttestationSignatureEntry",
    "AttestationSignatures",
    "Block",
    "BlockBody",
    "BlockHeader",
    "BlockLookup",
    "BlockSignatures",
    "Config",
    "DEFAULT_REGISTRY",
    "FORK_SEQUENCE",
    "ForkProtocol",
    "ForkRegistry",
    "LstarSpec",
    "SignedAggregatedAttestation",
    "SignedAttestation",
    "SignedBlock",
    "SpecStateType",
    "SpecStoreType",
    "State",
    "Store",
    "Validator",
    "Validators",
]
