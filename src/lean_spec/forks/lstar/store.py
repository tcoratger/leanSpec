"""
Forkchoice store for tracking chain state and attestations.

The Store tracks all information required for the LMD GHOST forkchoice algorithm.
"""

__all__ = ["AttestationSignatureEntry", "Store"]

from typing import NamedTuple

from lean_spec.forks.lstar.containers import (
    AttestationData,
    Block,
    Config,
    SignedAttestation,
    SignedBlock,
)
from lean_spec.forks.lstar.containers.attestation.attestation import SignedAggregatedAttestation
from lean_spec.forks.lstar.containers.block import BlockLookup
from lean_spec.subspecs.chain.clock import Interval
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.types import (
    Bytes32,
    Checkpoint,
    Slot,
    ValidatorIndex,
)
from lean_spec.types.base import StrictBaseModel

from .containers.state import State

_LAZY_SPEC: object = None


def _spec() -> object:
    """Return the lstar fork spec; deferred import breaks the spec ↔ store cycle."""
    global _LAZY_SPEC
    if _LAZY_SPEC is None:
        from lean_spec.forks.lstar.spec import LstarSpec

        _LAZY_SPEC = LstarSpec()
    return _LAZY_SPEC


class AttestationSignatureEntry(NamedTuple):
    """
    Single validator's XMSS signature for an attestation.

    Used as an element in the attestation_signatures map: one entry per validator
    that attested to the same AttestationData.
    """

    validator_id: ValidatorIndex
    signature: Signature


class Store(StrictBaseModel):
    """
    Forkchoice store tracking chain state and validator attestations.

    This is the "local view" that a node uses to run LMD GHOST. It contains:

    - which blocks and states are known,
    - which checkpoints are justified and finalized,
    - which block is currently considered the head,
    - and, for each validator, their latest attestation that should influence fork choice.

    The `Store` is updated whenever:
    - a new block is processed,
    - an attestation is received (via a block or gossip),
    - an interval tick occurs (activating new attestations),
    - or when the head is recomputed.
    """

    time: Interval
    """Current time in intervals since genesis."""

    config: Config
    """Chain configuration parameters."""

    head: Bytes32
    """
    Root of the current canonical chain head block.

    This is the result of running the fork choice algorithm on the current contents of the `Store`.
    """

    safe_target: Bytes32
    """
    Root of the current safe target for attestation.

    This can be used by higher-level logic to restrict which blocks are
    considered safe to attest to, based on additional safety conditions.
    """

    latest_justified: Checkpoint
    """
    Highest slot justified checkpoint known to the store.

    LMD GHOST starts from this checkpoint when computing the head.

    Only descendants of this checkpoint are considered viable.
    """

    latest_finalized: Checkpoint
    """
    Highest slot finalized checkpoint known to the store.

    Everything strictly before this checkpoint can be considered immutable.

    Fork choice will never revert finalized history.
    """

    blocks: BlockLookup = {}
    """
    Mapping from block root to Block objects.

    This is the set of blocks that the node currently knows about.

    Every block that might participate in fork choice must appear here.
    """

    states: dict[Bytes32, State] = {}
    """
    Mapping from block root to State objects.

    For each known block, we keep its post-state.

    These states carry justified and finalized checkpoints that we use to update the
    `Store`'s latest justified and latest finalized checkpoints.
    """

    validator_id: ValidatorIndex | None
    """Index of the validator running this store instance."""

    attestation_signatures: dict[AttestationData, set[AttestationSignatureEntry]] = {}
    """
    Per-validator XMSS signatures learned from committee attesters.

    Keyed by AttestationData.
    """

    latest_new_aggregated_payloads: dict[AttestationData, set[AggregatedSignatureProof]] = {}
    """
    Aggregated signature proofs pending processing.

    These payloads are "new" and do not yet contribute to fork choice.
    They migrate to known payloads via interval ticks.
    Populated from blocks or gossip aggregated attestations.
    """

    latest_known_aggregated_payloads: dict[AttestationData, set[AggregatedSignatureProof]] = {}
    """
    Aggregated signature proofs that have been processed.

    These payloads are "known" and contribute to fork choice weights.
    Used for recursive signature aggregation when building blocks.
    """

    @classmethod
    def from_anchor(
        cls,
        state: State,
        anchor_block: Block,
        validator_id: ValidatorIndex | None,
    ) -> "Store":
        """Initialize a forkchoice store from an anchor state and block."""
        return _spec().create_store(state, anchor_block, validator_id)  # type: ignore[attr-defined]

    def prune_stale_attestation_data(self) -> "Store":
        """Remove attestation data that can no longer influence fork choice."""
        return _spec().prune_stale_attestation_data(self)  # type: ignore[attr-defined]

    def validate_attestation(self, attestation_data: AttestationData) -> None:
        """Validate incoming attestation before processing."""
        _spec().validate_attestation(self, attestation_data)  # type: ignore[attr-defined]

    def on_gossip_attestation(
        self,
        signed_attestation: SignedAttestation,
        scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME,
        is_aggregator: bool = False,
    ) -> "Store":
        """Process a signed attestation received via gossip network."""
        return _spec().on_gossip_attestation(  # type: ignore[attr-defined]
            self, signed_attestation, scheme, is_aggregator
        )

    def on_gossip_aggregated_attestation(
        self, signed_attestation: SignedAggregatedAttestation
    ) -> "Store":
        """Process a signed aggregated attestation received via gossip."""
        return _spec().on_gossip_aggregated_attestation(  # type: ignore[attr-defined]
            self, signed_attestation
        )

    def on_block(
        self,
        signed_block: SignedBlock,
        scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME,
    ) -> "Store":
        """Process a new block and update the forkchoice state."""
        return _spec().on_block(self, signed_block, scheme)  # type: ignore[attr-defined]

    def extract_attestations_from_aggregated_payloads(
        self, aggregated_payloads: dict[AttestationData, set[AggregatedSignatureProof]]
    ) -> dict[ValidatorIndex, AttestationData]:
        """Extract attestations from aggregated payloads."""
        return _spec().extract_attestations_from_aggregated_payloads(  # type: ignore[attr-defined]
            self, aggregated_payloads
        )

    def compute_block_weights(self) -> dict[Bytes32, int]:
        """Compute attestation-based weight for each block above the finalized slot."""
        return _spec().compute_block_weights(self)  # type: ignore[attr-defined]

    def update_head(self) -> "Store":
        """Compute updated store with new canonical head."""
        return _spec().update_head(self)  # type: ignore[attr-defined]

    def accept_new_attestations(self) -> "Store":
        """Process pending aggregated payloads and update forkchoice head."""
        return _spec().accept_new_attestations(self)  # type: ignore[attr-defined]

    def update_safe_target(self) -> "Store":
        """Compute the deepest block that has 2/3+ supermajority attestation weight."""
        return _spec().update_safe_target(self)  # type: ignore[attr-defined]

    def aggregate(self) -> tuple["Store", list[SignedAggregatedAttestation]]:
        """Turn raw validator votes into compact aggregated attestations."""
        return _spec().aggregate(self)  # type: ignore[attr-defined]

    def tick_interval(
        self, has_proposal: bool, is_aggregator: bool = False
    ) -> tuple["Store", list[SignedAggregatedAttestation]]:
        """Advance store time by one interval and perform interval-specific actions."""
        return _spec().tick_interval(self, has_proposal, is_aggregator)  # type: ignore[attr-defined]

    def on_tick(
        self, target_interval: Interval, has_proposal: bool, is_aggregator: bool = False
    ) -> tuple["Store", list[SignedAggregatedAttestation]]:
        """Advance forkchoice store time to given interval count."""
        return _spec().on_tick(  # type: ignore[attr-defined]
            self, target_interval, has_proposal, is_aggregator
        )

    def get_proposal_head(self, slot: Slot) -> tuple["Store", Bytes32]:
        """Get the head for block proposal at given slot."""
        return _spec().get_proposal_head(self, slot)  # type: ignore[attr-defined]

    def get_attestation_target(self) -> Checkpoint:
        """Calculate target checkpoint for validator attestations."""
        return _spec().get_attestation_target(self)  # type: ignore[attr-defined]

    def produce_attestation_data(self, slot: Slot) -> AttestationData:
        """Produce attestation data for the given slot."""
        return _spec().produce_attestation_data(self, slot)  # type: ignore[attr-defined]

    def produce_block_with_signatures(
        self,
        slot: Slot,
        validator_index: ValidatorIndex,
    ) -> tuple["Store", Block, list[AggregatedSignatureProof]]:
        """Produce a block and its aggregated signature proofs for the target slot."""
        return _spec().produce_block_with_signatures(  # type: ignore[attr-defined]
            self, slot, validator_index
        )
