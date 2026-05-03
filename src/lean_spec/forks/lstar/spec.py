"""Lstar fork — identity and construction facade."""

from collections.abc import Iterable
from collections.abc import Set as AbstractSet
from typing import ClassVar

from lean_spec.forks.lstar.containers import (
    AggregatedAttestation,
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    BlockHeader,
    Config,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    Validator,
)
from lean_spec.forks.lstar.containers.block.block import BlockSignatures
from lean_spec.forks.lstar.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.forks.lstar.containers.state import State
from lean_spec.forks.lstar.containers.validator import Validators
from lean_spec.subspecs.chain.clock import Interval
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof, AggregationError
from lean_spec.subspecs.xmss.interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.types import Bytes32, Slot, Uint64, ValidatorIndex

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
    block_body_class: type[BlockBody] = BlockBody
    block_header_class: type[BlockHeader] = BlockHeader
    signed_block_class: type[SignedBlock] = SignedBlock
    block_signatures_class: type[BlockSignatures] = BlockSignatures
    aggregated_attestations_class: type[AggregatedAttestations] = AggregatedAttestations
    attestation_signatures_class: type[AttestationSignatures] = AttestationSignatures
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

    def state_transition(
        self,
        state: State,
        block: Block,
        valid_signatures: bool = True,
    ) -> State:
        """Compute the post-state obtained by applying a block to a pre-state."""
        return state.state_transition(block, valid_signatures)

    def process_slots(self, state: State, target_slot: Slot) -> State:
        """Advance the state through empty slots up to a target slot."""
        return state.process_slots(target_slot)

    def process_block(self, state: State, block: Block) -> State:
        """Apply a full block (header and body) to the state."""
        return state.process_block(block)

    def process_block_header(self, state: State, block: Block) -> State:
        """Apply only the header portion of a block to the state."""
        return state.process_block_header(block)

    def process_attestations(
        self,
        state: State,
        attestations: Iterable[AggregatedAttestation],
    ) -> State:
        """Fold attestations into the state and update justification and finalization."""
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
        """Assemble a valid block on top of the given pre-state."""
        return state.build_block(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots=known_block_roots,
            aggregated_payloads=aggregated_payloads,
        )

    def verify_signatures(
        self,
        signed_block: SignedBlock,
        validators: Validators,
        scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME,
    ) -> bool:
        """
        Verify all XMSS signatures in this signed block.

        Checks that:

        - Each body attestation is signed by participating validators
        - The proposer signed the block root with the proposal key

        Args:
            signed_block: The signed block whose signatures are checked.
            validators: Validator registry providing public keys for verification.
            scheme: XMSS signature scheme for verification.

        Returns:
            True if all signatures are valid.

        Raises:
            AssertionError: On verification failure.
        """
        block = signed_block.block
        signatures = signed_block.signature
        aggregated_attestations = block.body.attestations
        attestation_signatures = signatures.attestation_signatures

        # Each attestation in the body must have a corresponding signature entry.
        assert len(aggregated_attestations) == len(attestation_signatures), (
            "Attestation signature groups must align with block body attestations"
        )

        # Attestations and signatures are parallel arrays.
        # - Each attestation says "validators X, Y, Z voted for this data".
        # - Each signature proves those validators actually signed.
        for aggregated_attestation, aggregated_signature in zip(
            aggregated_attestations, attestation_signatures, strict=True
        ):
            # Extract which validators participated in this attestation.
            # The aggregation bits encode validator indices as a bitfield.
            validator_ids = aggregated_attestation.aggregation_bits.to_validator_indices()

            # The signed message is the attestation data root.
            # All validators in this group signed this exact data.
            attestation_data_root = hash_tree_root(aggregated_attestation.data)

            for validator_id in validator_ids:
                num_validators = Uint64(len(validators))
                assert validator_id.is_valid(num_validators), "Validator index out of range"

            # Collect attestation public keys for all participating validators.
            # Order matters: must match the order in the aggregated signature.
            public_keys = [validators[vid].get_attestation_pubkey() for vid in validator_ids]

            try:
                aggregated_signature.verify(
                    public_keys=public_keys,
                    message=attestation_data_root,
                    slot=aggregated_attestation.data.slot,
                )
            except AggregationError as exc:
                raise AssertionError(
                    f"Attestation aggregated signature verification failed: {exc}"
                ) from exc

        # Verify the proposer's signature over the block root.
        #
        # The proposer signs hash_tree_root(block) with their proposal key.
        # This proves the proposer endorsed this specific block.
        proposer_index = block.proposer_index
        assert proposer_index.is_valid(Uint64(len(validators))), "Proposer index out of range"

        proposer = validators[proposer_index]
        block_root = hash_tree_root(block)

        try:
            valid = scheme.verify(
                proposer.get_proposal_pubkey(),
                block.slot,
                block_root,
                signatures.proposer_signature,
            )
        except (ValueError, IndexError):
            valid = False
        assert valid, "Proposer block signature verification failed"

        return True

    def on_block(
        self,
        store: Store,
        signed_block: SignedBlock,
        scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME,
    ) -> Store:
        """Incorporate a newly received block into the forkchoice view."""
        return store.on_block(signed_block, scheme)

    def on_tick(
        self,
        store: Store,
        target_interval: Interval,
        has_proposal: bool,
        is_aggregator: bool = False,
    ) -> tuple[Store, list[SignedAggregatedAttestation]]:
        """Advance forkchoice time to a target interval and emit any due aggregates."""
        return store.on_tick(target_interval, has_proposal, is_aggregator)

    def on_gossip_attestation(
        self,
        store: Store,
        signed_attestation: SignedAttestation,
        scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME,
        is_aggregator: bool = False,
    ) -> Store:
        """Incorporate a single-validator attestation received from the network."""
        return store.on_gossip_attestation(signed_attestation, scheme, is_aggregator)

    def on_gossip_aggregated_attestation(
        self,
        store: Store,
        signed_attestation: SignedAggregatedAttestation,
    ) -> Store:
        """Incorporate an aggregated attestation received from the network."""
        return store.on_gossip_aggregated_attestation(signed_attestation)

    def produce_attestation_data(self, store: Store, slot: Slot) -> AttestationData:
        """Build the attestation payload that a validator should sign at this slot."""
        return store.produce_attestation_data(slot)

    def produce_block_with_signatures(
        self,
        store: Store,
        slot: Slot,
        validator_index: ValidatorIndex,
    ) -> tuple[Store, Block, list[AggregatedSignatureProof]]:
        """Produce a proposal block together with the aggregated signature proofs it needs."""
        return store.produce_block_with_signatures(slot, validator_index)

    def get_proposal_head(self, store: Store, slot: Slot) -> tuple[Store, Bytes32]:
        """Resolve the head root that a proposal at this slot should extend."""
        return store.get_proposal_head(slot)
