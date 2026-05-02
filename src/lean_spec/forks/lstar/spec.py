"""Lstar fork — identity and construction facade."""

from collections.abc import Iterable
from collections.abc import Set as AbstractSet
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
from lean_spec.subspecs.chain.clock import Interval
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.types import Bytes32, Slot, ValidatorIndex

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

    # State transition surface
    #
    # The methods below mirror the existing State / Store / SignedBlock methods
    # one-for-one. Stage 4A only adds the spec-class API surface; the bodies are
    # pure delegators to the container methods. Stage 4C will move the bodies in.

    def state_transition(
        self,
        state: State,
        block: Block,
        valid_signatures: bool = True,
    ) -> State:
        """Apply the full state transition function and return the post-state."""
        return state.state_transition(block, valid_signatures)

    def process_slots(self, state: State, target_slot: Slot) -> State:
        """Advance the state through empty slots up to ``target_slot``."""
        return state.process_slots(target_slot)

    def process_block(self, state: State, block: Block) -> State:
        """Apply full block processing (header + body) to the state."""
        return state.process_block(block)

    def process_block_header(self, state: State, block: Block) -> State:
        """Apply block-header processing only."""
        return state.process_block_header(block)

    def process_attestations(
        self,
        state: State,
        attestations: Iterable[AggregatedAttestation],
    ) -> State:
        """Apply aggregated attestations and update justification/finalization."""
        return state.process_attestations(attestations)

    def build_block(
        self,
        state: State,
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Bytes32,
        known_block_roots: AbstractSet[Bytes32],
        aggregated_payloads: dict[AttestationData, set[AggregatedSignatureProof]] | None = None,
    ) -> tuple[Block, State, list[AggregatedAttestation], list[AggregatedSignatureProof]]:
        """Build a valid block on top of ``state``."""
        return state.build_block(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots=known_block_roots,
            aggregated_payloads=aggregated_payloads,
        )

    # Block signature verification

    def verify_signatures(
        self,
        signed_block: SignedBlock,
        validators: Validators,
        scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME,
    ) -> bool:
        """Verify all XMSS signatures in ``signed_block`` against ``validators``."""
        return signed_block.verify_signatures(validators, scheme)

    # Forkchoice surface

    def on_block(
        self,
        store: Store,
        signed_block: SignedBlock,
        scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME,
    ) -> Store:
        """Process a new block and update the forkchoice store."""
        return store.on_block(signed_block, scheme)

    def on_tick(
        self,
        store: Store,
        target_interval: Interval,
        has_proposal: bool,
        is_aggregator: bool = False,
    ) -> tuple[Store, list[SignedAggregatedAttestation]]:
        """Advance the forkchoice store time to ``target_interval``."""
        return store.on_tick(target_interval, has_proposal, is_aggregator)

    def on_gossip_attestation(
        self,
        store: Store,
        signed_attestation: SignedAttestation,
        scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME,
        is_aggregator: bool = False,
    ) -> Store:
        """Process a single-validator attestation received via gossip."""
        return store.on_gossip_attestation(signed_attestation, scheme, is_aggregator)

    def on_gossip_aggregated_attestation(
        self,
        store: Store,
        signed_attestation: SignedAggregatedAttestation,
    ) -> Store:
        """Process an aggregated attestation received via gossip."""
        return store.on_gossip_aggregated_attestation(signed_attestation)

    def produce_attestation_data(self, store: Store, slot: Slot) -> AttestationData:
        """Produce attestation data for the given slot."""
        return store.produce_attestation_data(slot)

    def produce_block_with_signatures(
        self,
        store: Store,
        slot: Slot,
        validator_index: ValidatorIndex,
    ) -> tuple[Store, Block, list[AggregatedSignatureProof]]:
        """Produce a block plus its aggregated signature proofs for ``slot``."""
        return store.produce_block_with_signatures(slot, validator_index)

    def get_proposal_head(self, store: Store, slot: Slot) -> tuple[Store, Bytes32]:
        """Return the head root that a block proposal at ``slot`` should build on."""
        return store.get_proposal_head(slot)
