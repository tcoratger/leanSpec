"""Fork-choice store: the node's local view of the chain."""

from typing import NamedTuple

from pydantic import Field

from lean_spec.base import StrictBaseModel
from lean_spec.spec.crypto.xmss.containers import Signature
from lean_spec.spec.forks.lstar.containers.aggregation import SingleMessageAggregate
from lean_spec.spec.forks.lstar.containers.checkpoint import AttestationData, Checkpoint
from lean_spec.spec.forks.lstar.containers.genesis import GenesisConfig
from lean_spec.spec.forks.lstar.containers.identifiers import ValidatorIndex
from lean_spec.spec.forks.lstar.containers.interval import Interval
from lean_spec.spec.ssz import Bytes32, Container


class AttestationSignatureEntry(NamedTuple):
    """One validator paired with its signature for an attestation."""

    validator_index: ValidatorIndex
    """Index of the validator that produced the signature."""

    signature: Signature
    """Signature over the attestation."""


class Store[StateT: Container, BlockT: Container](StrictBaseModel):
    """A node's local view of the chain for running fork choice."""

    time: Interval
    """Current time in intervals since genesis."""

    config: GenesisConfig
    """Chain configuration parameters."""

    head: Bytes32
    """Root of the head block that fork choice currently selects."""

    safe_target: Bytes32
    """Root of the block a validator is currently safe to attest to."""

    latest_justified: Checkpoint
    """Highest-slot justified checkpoint observed so far."""

    latest_finalized: Checkpoint
    """Highest-slot finalized checkpoint observed so far."""

    blocks: dict[Bytes32, BlockT] = Field(default_factory=dict)
    """
    Known blocks indexed by their root.

    Every block eligible to participate in fork choice appears here.
    """

    states: dict[Bytes32, StateT] = Field(default_factory=dict)
    """Post-state of each known block, indexed by block root."""

    validator_index: ValidatorIndex | None
    """Index of the validator that owns this view, or none for an observer."""

    attestation_signatures: dict[AttestationData, set[AttestationSignatureEntry]] = Field(
        default_factory=dict
    )
    """
    Per-validator signatures observed, grouped by the vote they sign.

    This pool only shrinks when finalization advances.
    Pruning drops every vote whose head sits at or below the finalized slot.
    Between two finalizations the set of distinct vote keys can keep growing.

    A staked validator holds one key entry per distinct vote it signs.
    The vote's head may be any block descending from the finalized block.
    During a long non-finalizing window the number of such blocks is unbounded.
    Each new head a validator signs adds a fresh key here.
    The signature is verified before insertion, so the writer pays that cost first.
    The growth is a resource bound, not a safety break.

    The spec sets no cap on this pool.
    A hard cap would change attestation acceptance and could diverge from the reference.
    Bounding memory during a non-finalizing window is a node-implementation responsibility.
    A node may cap retained keys, evict by age, or apply its own admission policy.
    """

    latest_new_aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] = Field(
        default_factory=dict
    )
    """Pending single-message proofs awaiting promotion, grouped by the vote they support."""

    latest_known_aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] = Field(
        default_factory=dict
    )
    """Single-message proofs counted toward fork choice, grouped by the vote they support."""
