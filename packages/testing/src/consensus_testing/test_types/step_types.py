"""Step types for fork choice tests: author-facing inputs and emitted results."""

from typing import Annotated, Any, Literal

from pydantic import Field, field_serializer, model_validator

from consensus_testing.test_fixtures.base import ExpectedRejection
from consensus_testing.test_types.attestation_specs import (
    AggregatedAttestationSpec,
    GossipAttestationSpec,
)
from consensus_testing.test_types.block_spec import BlockSpec
from consensus_testing.test_types.store_checks import StoreChecks
from consensus_testing.test_types.store_snapshot import StoreSnapshot
from lean_spec.base import CamelModel
from lean_spec.spec.forks import RejectionReason
from lean_spec.spec.forks.lstar.containers import (
    Block,
    SignedAggregatedAttestation,
    SignedAttestation,
)


class BaseForkChoiceStep(CamelModel):
    """Base class for fork choice event steps."""

    model_config = CamelModel.model_config | {"frozen": True}

    valid: bool = True
    """Whether this step is expected to succeed."""

    expected_rejection: ExpectedRejection | None = None
    """Expected rejection when invalid, never serialized into the emitted contract."""

    checks: StoreChecks | None = None
    """Store state checks to validate after this step, limited to fields explicitly set."""

    @model_validator(mode="after")
    def validate_rejection_is_declared(self) -> "BaseForkChoiceStep":
        """
        Require a declared rejection on every step expected to fail.

        A vector saying only "reject this" lets a client reject for the wrong reason and pass.
        """
        if not self.valid and self.expected_rejection is None:
            raise ValueError("steps with valid=False must declare their expected_rejection")
        return self


class TickStep(BaseForkChoiceStep):
    """Advance store time to a unix timestamp or interval count, triggering interval actions."""

    step_type: Literal["tick"] = "tick"
    """Discriminator field for serialization."""

    time: int | None = None
    """Optional unix timestamp to advance to."""

    interval: int | None = None
    """Optional exact interval count to advance to."""

    has_proposal: bool = False
    """Whether interval 0 of the target slot should see a proposal."""

    @model_validator(mode="after")
    def validate_target(self) -> "TickStep":
        """Require exactly one time target representation."""
        if (self.time is None) == (self.interval is None):
            raise ValueError("TickStep requires exactly one of time or interval")
        return self


class BlockStep(BaseForkChoiceStep):
    """Process a block through the store, updating the block tree and possibly the head."""

    step_type: Literal["block"] = "block"
    """Discriminator field for serialization."""

    block: BlockSpec
    """Block specification with required slot and optional overrides, filled during generation."""

    tick_to_slot: bool = True
    """Whether to advance the store clock to the block's slot before import.

    Set False to pin how clients treat a block ahead of their local time.
    """


class AttestationStep(BaseForkChoiceStep):
    """
    Process a gossip attestation, updating validator attestation tracking.

    Attestations inside blocks are processed with the block, not here.
    """

    step_type: Literal["attestation"] = "attestation"
    """Discriminator field for serialization."""

    attestation: GossipAttestationSpec
    """Gossip attestation specification, with data and signature filled during generation."""

    is_aggregator: bool = False
    """Whether the node holds the aggregator role for this attestation.

    Only aggregator nodes store gossip signatures in the raw signature pool.
    """


class GossipAggregatedAttestationStep(BaseForkChoiceStep):
    """Aggregated attestation processing step."""

    step_type: Literal["gossipAggregatedAttestation"] = "gossipAggregatedAttestation"
    """Discriminator field for serialization."""

    attestation: AggregatedAttestationSpec
    """Specification for the aggregated gossip attestation."""


ForkChoiceStep = Annotated[
    TickStep | BlockStep | AttestationStep | GossipAggregatedAttestationStep,
    Field(discriminator="step_type"),
]


class BaseFilledStep(CamelModel):
    """Base class for emitted fork choice steps, carrying the shared generation outputs."""

    model_config = CamelModel.model_config | {"frozen": True}

    valid: bool
    """Whether this step succeeded."""

    rejection_reason: RejectionReason | None = None
    """Language-neutral reason the input was rejected, the field clients assert against."""

    checks: StoreChecks | None = None
    """Store state checks the step was validated against."""

    store_snapshot: StoreSnapshot
    """Canonical store observables after this step, populated even for rejected steps.

    Pins the no-op on rejection so a client cannot corrupt state on a rejected input.
    """


class FilledTickStep(BaseFilledStep):
    """Emitted time advancement step."""

    step_type: Literal["tick"] = "tick"
    """Discriminator field for serialization."""

    time: int | None = None
    """Optional unix timestamp advanced to."""

    interval: int | None = None
    """Optional exact interval count advanced to."""

    has_proposal: bool
    """Whether interval 0 of the target slot saw a proposal."""


class FilledBlockStep(BaseFilledStep):
    """Emitted block processing step carrying the complete built block."""

    step_type: Literal["block"] = "block"
    """Discriminator field for serialization."""

    tick_to_slot: bool
    """Whether the store clock advanced to the block's slot before import."""

    block: Block
    """The filled Block, processed through the spec."""

    block_root_label: str | None = Field(default=None, exclude=True)
    """Authored label for this block, merged into the block payload."""

    @field_serializer("block", when_used="json")
    def serialize_block(self, filled_block: Block) -> dict[str, Any]:
        """
        Serialize the block, merging the authored label into its payload.

        The label rides inside the block object so consumers resolve forks without a side table.
        """
        serialized_block = filled_block.to_json()
        if self.block_root_label:
            serialized_block["blockRootLabel"] = self.block_root_label
        return serialized_block


class FilledAttestationStep(BaseFilledStep):
    """Emitted gossip attestation step carrying the signed attestation."""

    step_type: Literal["attestation"] = "attestation"
    """Discriminator field for serialization."""

    attestation: SignedAttestation
    """The filled SignedAttestation, processed through the spec."""

    is_aggregator: bool
    """Whether the node held the aggregator role for this attestation."""


class FilledGossipAggregatedAttestationStep(BaseFilledStep):
    """Emitted aggregated attestation step carrying the signed aggregate."""

    step_type: Literal["gossipAggregatedAttestation"] = "gossipAggregatedAttestation"
    """Discriminator field for serialization."""

    attestation: SignedAggregatedAttestation
    """The filled SignedAggregatedAttestation, processed through the spec."""


FilledForkChoiceStep = Annotated[
    FilledTickStep
    | FilledBlockStep
    | FilledAttestationStep
    | FilledGossipAggregatedAttestationStep,
    Field(discriminator="step_type"),
]
