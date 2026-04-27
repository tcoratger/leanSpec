"""Multi-fork dispatch layer for leanSpec consensus specification."""

from .devnet4.containers.state import State
from .devnet4.spec import Devnet4Spec
from .devnet4.store import AttestationSignatureEntry, Store
from .devnet5.spec import Devnet5Spec
from .protocol import ForkProtocol, SpecStateType, SpecStoreType
from .registry import ForkRegistry

FORK_SEQUENCE: list[ForkProtocol] = [Devnet4Spec(), Devnet5Spec()]
"""Ordered oldest to newest. ForkRegistry enforces strictly increasing VERSION."""

DEFAULT_REGISTRY: ForkRegistry = ForkRegistry(FORK_SEQUENCE)
"""Shared registry over the registered forks. Convenient for top-level callers."""

__all__ = [
    "AttestationSignatureEntry",
    "DEFAULT_REGISTRY",
    "Devnet4Spec",
    "Devnet5Spec",
    "FORK_SEQUENCE",
    "ForkProtocol",
    "ForkRegistry",
    "SpecStateType",
    "SpecStoreType",
    "State",
    "Store",
]
