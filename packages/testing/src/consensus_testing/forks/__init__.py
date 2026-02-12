"""Fork definitions for consensus layer testing."""

from typing import Type

from framework.forks import BaseFork, BaseForkMeta, ForkRegistry

from . import forks as _forks_module
from .forks import Devnet

Fork = Type[BaseFork]

registry = ForkRegistry(_forks_module)

__all__ = [
    "BaseFork",
    "BaseForkMeta",
    "Devnet",
    "Fork",
    "registry",
]
