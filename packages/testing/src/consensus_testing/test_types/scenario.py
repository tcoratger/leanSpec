"""Fluent builder for authoring fork choice step sequences."""

from collections.abc import Iterable, Sequence
from typing import Self

from consensus_testing.test_types.attestation_specs import AggregatedAttestationSpec
from consensus_testing.test_types.block_spec import BlockSpec
from consensus_testing.test_types.step_types import (
    BlockStep,
    ForkChoiceStep,
    GossipAggregatedAttestationStep,
    TickStep,
)
from consensus_testing.test_types.store_checks import StoreChecks
from lean_spec.spec.forks import Slot, ValidatorIndex


class ForkChoiceScenario:
    """
    Builds a fork choice step sequence through chained calls.

    Each call appends one step and returns the scenario.
    The explicit step list stays available through steps().
    """

    def __init__(self) -> None:
        """Start an empty scenario."""
        self._steps: list[ForkChoiceStep] = []

    def block(
        self,
        slot: int,
        *,
        label: str | None = None,
        parent_label: str | None = None,
        attestations: list[AggregatedAttestationSpec] | None = None,
        tick_to_slot: bool = True,
    ) -> Self:
        """
        Append a block-processing step.

        Args:
            slot: Slot the block is built for.
            label: Optional label so later blocks can name this one as parent.
            parent_label: Optional parent block label, for building forks.
            attestations: Optional in-block aggregated attestations.
            tick_to_slot: Whether to advance the store clock to the block slot.
        """
        self._steps.append(
            BlockStep(
                block=BlockSpec(
                    slot=Slot(slot),
                    label=label,
                    parent_label=parent_label,
                    attestations=attestations,
                ),
                tick_to_slot=tick_to_slot,
            )
        )
        return self

    def tick(self, interval: int, *, has_proposal: bool = False) -> Self:
        """
        Append a time-advancement step that targets an exact interval count.

        Args:
            interval: Interval count since genesis to advance the store to.
            has_proposal: Whether interval 0 of the target slot sees a proposal.
        """
        self._steps.append(TickStep(interval=interval, has_proposal=has_proposal))
        return self

    def tick_to_unix_time(self, time: int, *, has_proposal: bool = False) -> Self:
        """
        Append a time-advancement step that targets a unix timestamp.

        Args:
            time: Unix timestamp in seconds to advance the store to.
            has_proposal: Whether interval 0 of the target slot sees a proposal.
        """
        self._steps.append(TickStep(time=time, has_proposal=has_proposal))
        return self

    def attest(
        self,
        by: Iterable[int],
        slot: int,
        target_label: str,
        target_slot: int,
        *,
        source_label: str | None = None,
        source_slot: int | None = None,
    ) -> Self:
        """
        Append a gossip aggregated-attestation step.

        Args:
            by: Validator indices contributing to the aggregate.
            slot: Slot the attestation is made at.
            target_label: Label of the block the attestation targets.
            target_slot: Slot of the target block.
            source_label: Optional label of the source block, for an explicit source.
            source_slot: Optional source checkpoint slot, paired with source_label.
        """
        self._steps.append(
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(index) for index in by],
                    slot=Slot(slot),
                    target_slot=Slot(target_slot),
                    target_root_label=target_label,
                    source_root_label=source_label,
                    source_slot=Slot(source_slot) if source_slot is not None else None,
                )
            )
        )
        return self

    def expect(self, **store_check_fields: object) -> Self:
        """
        Attach store-state checks to the most recently appended step.

        Field names are the StoreChecks fields, so a scenario asserts the
        same observables the explicit form does.

        Raises:
            ValueError: When no step has been appended yet.
        """
        if not self._steps:
            raise ValueError("expect() needs a preceding step to attach checks to")
        self._steps[-1] = self._steps[-1].model_copy(
            update={"checks": StoreChecks(**store_check_fields)}
        )
        return self

    def chain(self, slots: Iterable[int]) -> Self:
        """
        Append one labeled block per slot, labeled block_{slot}.

        Args:
            slots: Slots to build a linear chain through, in order.
        """
        for slot in slots:
            self.block(slot, label=f"block_{slot}")
        return self

    def steps(self) -> Sequence[ForkChoiceStep]:
        """Return the accumulated steps."""
        return self._steps
