"""Consensus fork definitions for test fixture generation."""

from framework.forks import BaseFork

from lean_spec.forks.devnet4.spec import Devnet4Spec
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
    def state_class(cls) -> type:
        """Return the State container class for this fork."""
        return Devnet4Spec.state_class


class Devnet5(Devnet4):
    """Devnet5 fork — inherits from Devnet4; override state_class when divergence lands."""

    @classmethod
    def name(cls) -> str:
        """Return the fork name."""
        return "Devnet5"

    @classmethod
    def spec_class(cls) -> type[Devnet5Spec]:
        """Return the ForkProtocol implementation for this fork."""
        return Devnet5Spec

    @classmethod
    def state_class(cls) -> type:
        """Return the State container class for this fork."""
        return Devnet5Spec.state_class
