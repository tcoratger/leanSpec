"""Lstar fork — identity and construction facade."""

from typing import ClassVar

from lean_spec.forks.lstar.containers import (
    AggregatedAttestation,
    Attestation,
    AttestationData,
    Block,
    Config,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    Validator,
)
from lean_spec.forks.lstar.containers.block.block import BlockSignatures
from lean_spec.forks.lstar.containers.state import State
from lean_spec.forks.lstar.containers.validator import Validators

from ..protocol import ForkProtocol, SpecStateType
from .store import Store


class LstarSpec(ForkProtocol):
    """Lstar fork."""

    NAME: ClassVar[str] = "lstar"
    VERSION: ClassVar[int] = 4
    GOSSIP_DIGEST: ClassVar[str] = "12345678"

    previous: ClassVar[type[ForkProtocol] | None] = None

    state_class: type[State] = State
    block_class: type[Block] = Block
    signed_block_class: type[SignedBlock] = SignedBlock
    block_signatures_class: type[BlockSignatures] = BlockSignatures
    store_class: type[Store] = Store

    attestation_data_class: type[AttestationData] = AttestationData
    attestation_class: type[Attestation] = Attestation
    signed_attestation_class: type[SignedAttestation] = SignedAttestation
    aggregated_attestation_class: type[AggregatedAttestation] = AggregatedAttestation
    signed_aggregated_attestation_class: type[SignedAggregatedAttestation] = (
        SignedAggregatedAttestation
    )

    validator_class: type[Validator] = Validator
    validators_class: type[Validators] = Validators

    config_class: type[Config] = Config

    def upgrade_state(self, state: SpecStateType) -> State:
        """
        Lstar is the root fork: there is no predecessor, so no migration.

        Returns the input state unchanged.
        """
        assert isinstance(state, State)
        return state
