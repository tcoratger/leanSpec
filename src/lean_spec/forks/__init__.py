"""Multi-fork dispatch layer for leanSpec consensus specification."""

from .devnet4.containers.state import State
from .devnet4.spec import Devnet4Spec
from .devnet4.store import AttestationSignatureEntry, Store
from .devnet5.spec import Devnet5Spec
from .protocol import ForkProtocol, SpecStateType, SpecStoreType
from .runner import SpecRunner

FORK_SEQUENCE: list[ForkProtocol] = [Devnet4Spec(), Devnet5Spec()]
"""Ordered oldest to newest. SpecRunner enforces strictly increasing VERSION."""

DEFAULT_RUNNER: SpecRunner = SpecRunner(FORK_SEQUENCE)
"""Shared runner over the registered forks. Convenient for top-level callers."""

__all__ = [
    "AttestationSignatureEntry",
    "DEFAULT_RUNNER",
    "Devnet4Spec",
    "Devnet5Spec",
    "FORK_SEQUENCE",
    "ForkProtocol",
    "SpecRunner",
    "SpecStateType",
    "SpecStoreType",
    "State",
    "Store",
]
