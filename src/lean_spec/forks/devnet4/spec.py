"""Devnet4 fork — identity and construction facade."""

from typing import ClassVar

from lean_spec.forks.devnet4.containers.block import Block

from ..protocol import ForkProtocol
from .containers.state import State
from .store import Store


class Devnet4Spec(ForkProtocol):
    """Devnet4 fork."""

    NAME: ClassVar[str] = "devnet4"
    VERSION: ClassVar[int] = 4
    GOSSIP_DIGEST: ClassVar[str] = "devnet0"

    previous: ClassVar[type[ForkProtocol] | None] = None

    state_class: ClassVar[type[State]] = State
    block_class: ClassVar[type[Block]] = Block
    store_class: ClassVar[type[Store]] = Store
