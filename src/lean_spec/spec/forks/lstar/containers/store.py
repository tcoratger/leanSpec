"""Fork-choice store: the node's LMD-GHOST local view of the chain."""

from typing import NamedTuple

from pydantic import Field

from lean_spec.base import StrictBaseModel
from lean_spec.spec.crypto.xmss.containers import Signature
from lean_spec.spec.forks.lstar.containers.aggregation import SingleMessageAggregate
from lean_spec.spec.forks.lstar.containers.checkpoint import AttestationData, Checkpoint
from lean_spec.spec.forks.lstar.containers.identifiers import ValidatorIndex
from lean_spec.spec.forks.lstar.containers.interval import Interval
from lean_spec.spec.forks.lstar.containers.validator import GenesisConfig
from lean_spec.spec.ssz import Bytes32, Container


class AttestationSignatureEntry(NamedTuple):
    """
    Single validator's XMSS signature for an attestation.

    Used as an element in the attestation_signatures map: one entry per validator
    that attested to the same AttestationData.
    """

    validator_index: ValidatorIndex
    signature: Signature


class Store[StateT: Container, BlockT: Container](StrictBaseModel):
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

    config: GenesisConfig
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

    blocks: dict[Bytes32, BlockT] = Field(default_factory=dict)
    """
    Mapping from block root to Block objects.

    This is the set of blocks that the node currently knows about.

    Every block that might participate in fork choice must appear here.
    """

    states: dict[Bytes32, StateT] = Field(default_factory=dict)
    """
    Mapping from block root to State objects.

    For each known block, we keep its post-state.

    These states carry justified and finalized checkpoints that we use to update the
    `Store`'s latest justified and latest finalized checkpoints.
    """

    validator_index: ValidatorIndex | None
    """Index of the validator running this store instance."""

    attestation_signatures: dict[AttestationData, set[AttestationSignatureEntry]] = Field(
        default_factory=dict
    )
    """
    Per-validator XMSS signatures learned from committee attesters.

    Keyed by AttestationData.
    """

    latest_new_aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] = Field(
        default_factory=dict
    )
    """
    Aggregated signature proofs pending processing.

    These payloads are "new" and do not yet contribute to fork choice.
    They migrate to known payloads via interval ticks.
    Populated from gossip aggregated attestations.
    Block import does not feed individual proofs into this map directly.
    The block-level proof is a merged multi-message aggregate blob verified as a whole.
    On gossip-block import, any validator deconstructs that multi-message aggregate into
    per-message proofs, writes them back here, and gossips the aggregate.
    """

    latest_known_aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] = Field(
        default_factory=dict
    )
    """
    Aggregated signature proofs that have been processed.

    These payloads are "known" and contribute to fork choice weights.
    Used for recursive signature aggregation when building blocks.
    """
