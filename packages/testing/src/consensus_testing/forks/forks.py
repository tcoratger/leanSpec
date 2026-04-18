"""Consensus fork definitions for test fixture generation.

Each fork class connects the test framework to the spec layer:

- Inherits from the previous fork for ordering (Devnet5 > Devnet4).
- Points to the ForkProtocol implementation via spec_class().
- Points to the State container via state_class().

Adding a new fork requires three things:

1. A class here that inherits from the previous fork.
2. spec_class() pointing to the ForkProtocol implementation.
3. state_class() pointing to the State container (if it changed).
"""

from framework.forks import BaseFork

from lean_spec.forks.devnet4.spec import Devnet4Spec
from lean_spec.forks.devnet4.state import State
from lean_spec.forks.devnet5.spec import Devnet5Spec


class Devnet4(BaseFork):
    """Devnet4 fork — base fork for the lean Ethereum protocol."""

    @classmethod
    def name(cls) -> str:
        """Return the fork name."""
        return "Devnet4"

    @classmethod
    def spec_class(cls) -> type[Devnet4Spec]:
        """Return the ForkProtocol implementation for this fork."""
        return Devnet4Spec

    @classmethod
    def state_class(cls) -> type[State]:
        """Return the State container class for this fork."""
        return State


class Devnet5(Devnet4):
    """Devnet5 fork — inherits from Devnet4, overrides what changes."""

    @classmethod
    def name(cls) -> str:
        """Return the fork name."""
        return "Devnet5"

    @classmethod
    def spec_class(cls) -> type[Devnet5Spec]:
        """Return the ForkProtocol implementation for this fork."""
        return Devnet5Spec

    @classmethod
    def state_class(cls) -> type[State]:
        """Return the State container class for this fork.

        When Devnet5State exists, change this to return Devnet5State.
        """
        return State
