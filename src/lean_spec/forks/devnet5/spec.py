"""Devnet5 fork — forward-looking placeholder."""

from typing import ClassVar

from ..devnet4.containers.state import State
from ..devnet4.spec import Devnet4Spec
from ..devnet4.store import Store
from ..protocol import SpecStateType, SpecStoreType

# TODO: replace in one spot when devnet5 introduces its own container types.
_Devnet5State: type[SpecStateType] = State
_Devnet5Store: type[SpecStoreType] = Store


class Devnet5Spec(Devnet4Spec):
    """Devnet5 — placeholder that currently mirrors devnet4 exactly."""

    NAME: ClassVar[str] = "devnet5"
    VERSION: ClassVar[int] = 5

    state_class: ClassVar[type[SpecStateType]] = _Devnet5State
    block_class: ClassVar[type] = Devnet4Spec.block_class
    store_class: ClassVar[type[SpecStoreType]] = _Devnet5Store
