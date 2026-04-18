"""
Multi-fork dispatch layer for leanSpec consensus specification.

For runtime fork dispatch, use SpecRunner.
"""

from .devnet4.spec import Devnet4Spec
from .devnet4.state import State
from .devnet4.store import AttestationSignatureEntry, Store
from .devnet5.spec import Devnet5Spec
from .protocol import ForkProtocol
from .runner import SpecRunner

FORK_SEQUENCE: list[type[ForkProtocol]] = [Devnet4Spec, Devnet5Spec]
"""Ordered oldest to newest. SpecRunner expects this order."""

__all__ = [
    "AttestationSignatureEntry",
    "Devnet4Spec",
    "Devnet5Spec",
    "FORK_SEQUENCE",
    "ForkProtocol",
    "SpecRunner",
    "State",
    "Store",
]
