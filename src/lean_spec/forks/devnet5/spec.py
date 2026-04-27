"""Devnet5 fork — placeholder mirroring devnet4 until divergence lands."""

from typing import ClassVar

from ..devnet4.containers.block import Block
from ..devnet4.containers.state import State
from ..devnet4.spec import Devnet4Spec
from ..devnet4.store import Store
from ..protocol import ForkProtocol


class Devnet5Spec(Devnet4Spec):
    """
    Devnet5 — placeholder that currently mirrors devnet4 exactly.

    When devnet5 introduces its own container types under
    forks/devnet5/containers/, swap the imports above (and the
    annotations below) to the new classes. Method logic is inherited
    from Devnet4Spec and constructs containers via self.*_class, so
    no method overrides are required for pure container swaps.
    """

    NAME: ClassVar[str] = "devnet5"
    VERSION: ClassVar[int] = 5

    previous: ClassVar[type[ForkProtocol] | None] = Devnet4Spec

    state_class: ClassVar[type[State]] = State
    block_class: ClassVar[type[Block]] = Block
    store_class: ClassVar[type[Store]] = Store
