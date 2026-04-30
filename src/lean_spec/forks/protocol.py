"""
Fork protocol interface for leanSpec consensus.

This module is deliberately agnostic of any individual devnet.
"""

from abc import ABC, abstractmethod
from typing import Any, ClassVar, Protocol, Self

from lean_spec.types import Bytes32, SSZList, Uint64


class SpecStateType(Protocol):
    """Structural contract: any fork's State container class exposes genesis."""

    @classmethod
    def generate_genesis(cls, genesis_time: Uint64, validators: SSZList[Any]) -> Self:
        """Construct the fork's genesis state."""
        ...


class SpecBlockType(Protocol):
    """Structural contract: any fork's Block container class."""


class SpecStoreType(Protocol):
    """Structural contract: any fork's Store class exposes anchor construction."""

    head: Bytes32

    @classmethod
    def from_anchor(
        cls,
        state: SpecStateType,
        anchor_block: SpecBlockType,
        validator_id: Uint64 | None,
    ) -> Self:
        """Construct a forkchoice store anchored at the given state/block."""
        ...


class ForkProtocol(ABC):
    """Identity and construction facade for a devnet fork."""

    NAME: ClassVar[str]
    """Fork name, e.g. 'lstar'. Must be unique across the registry."""

    VERSION: ClassVar[int]
    """Strictly monotonic version. Used to order forks in the registry."""

    GOSSIP_DIGEST: ClassVar[str]
    """
    Fork identifier embedded in gossipsub topic names.

    Must match the digest used by other clients on the same network so that
    block, attestation, and aggregation topics route compatibly.
    """

    previous: ClassVar["type[ForkProtocol] | None"]
    """
    Predecessor fork in the upgrade chain, or None for the root fork.

    Forms a linked chain that the registry can walk to derive ordering
    and that upgrade_state can traverse for cross-fork state migrations.
    """

    state_class: type[SpecStateType]
    """Concrete State container class owned by this fork."""

    block_class: type[SpecBlockType]
    """Concrete Block container class owned by this fork."""

    store_class: type[SpecStoreType]
    """Concrete forkchoice Store class owned by this fork."""

    def generate_genesis(self, genesis_time: Uint64, validators: SSZList[Any]) -> SpecStateType:
        """Construct a genesis state using this fork's State class."""
        return self.state_class.generate_genesis(genesis_time, validators)

    def create_store(
        self,
        state: SpecStateType,
        anchor_block: SpecBlockType,
        validator_id: Uint64 | None,
    ) -> SpecStoreType:
        """Construct a forkchoice store anchored at the given state and block."""
        return self.store_class.from_anchor(state, anchor_block, validator_id)

    @abstractmethod
    def upgrade_state(self, state: SpecStateType) -> SpecStateType:
        """
        Migrate state from the previous fork's shape into this fork's shape.

        Every concrete fork must declare this explicitly. The root fork
        (previous is None) returns the input unchanged. Later forks return a
        state of their own shape derived from the predecessor's state.

        Making this abstract is intentional: a silent no-op default would
        hide missed migrations whenever a fork adds a field but forgets to
        override.
        """
