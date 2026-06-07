"""Tests for the lstar State container."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from lean_spec.spec.forks import Checkpoint, Slot
from lean_spec.spec.forks.lstar.config import HISTORICAL_ROOTS_LIMIT, VALIDATOR_REGISTRY_LIMIT
from lean_spec.spec.forks.lstar.containers.state import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    State,
)
from lean_spec.spec.ssz import Boolean, Bytes32
from lean_spec.spec.ssz.exceptions import SSZValueError
from tests.lean_spec.helpers import make_genesis_state


class TestJustifiedSlotsIsSlotJustified:
    """Justification lookups against the tracked slot bitfield."""

    def test_target_at_finalized_boundary_is_implicitly_justified(self) -> None:
        """A target equal to the finalized boundary is justified without consulting bits."""
        justified_slots = JustifiedSlots(data=[])
        assert justified_slots.is_slot_justified(Slot(4), Slot(4)) == Boolean(True)

    def test_target_before_finalized_boundary_is_implicitly_justified(self) -> None:
        """A target below the finalized boundary is justified without consulting bits."""
        justified_slots = JustifiedSlots(data=[])
        assert justified_slots.is_slot_justified(Slot(4), Slot(1)) == Boolean(True)

    def test_target_after_finalized_with_bit_set_true(self) -> None:
        """A future target whose tracked bit is set reads back as justified."""
        justified_slots = JustifiedSlots(data=[Boolean(True), Boolean(False)])
        assert justified_slots.is_slot_justified(Slot(0), Slot(1)) == Boolean(True)

    def test_target_after_finalized_with_bit_set_false(self) -> None:
        """A future target whose tracked bit is clear reads back as not justified."""
        justified_slots = JustifiedSlots(data=[Boolean(True), Boolean(False)])
        assert justified_slots.is_slot_justified(Slot(0), Slot(2)) == Boolean(False)

    def test_nonzero_finalized_anchor_offsets_the_relative_index(self) -> None:
        """A non-zero finalized anchor shifts which tracked bit a future slot maps to."""
        # Finalized boundary 3 maps slot 4 to index 0 and slot 6 to index 2.
        justified_slots = JustifiedSlots(data=[Boolean(False), Boolean(True), Boolean(True)])
        assert justified_slots.is_slot_justified(Slot(3), Slot(4)) == Boolean(False)
        assert justified_slots.is_slot_justified(Slot(3), Slot(5)) == Boolean(True)
        assert justified_slots.is_slot_justified(Slot(3), Slot(6)) == Boolean(True)

    def test_target_beyond_tracked_length_raises_with_boundary_and_length(self) -> None:
        """A future target past the tracked range raises naming the boundary and length."""
        justified_slots = JustifiedSlots(data=[Boolean(True)])
        with pytest.raises(
            IndexError,
            match=r"Slot 5 is outside the tracked range "
            r"\(finalized_boundary=0, tracked_length=1\)",
        ):
            justified_slots.is_slot_justified(Slot(0), Slot(5))

    def test_target_beyond_tracked_length_with_nonzero_anchor_reports_anchor(self) -> None:
        """The out-of-range error reports the non-zero finalized anchor and the length."""
        justified_slots = JustifiedSlots(data=[Boolean(True), Boolean(False)])
        with pytest.raises(
            IndexError,
            match=r"Slot 7 is outside the tracked range "
            r"\(finalized_boundary=2, tracked_length=2\)",
        ):
            justified_slots.is_slot_justified(Slot(2), Slot(7))

    def test_empty_bitfield_future_target_raises(self) -> None:
        """An empty bitfield cannot answer any future slot and raises."""
        justified_slots = JustifiedSlots(data=[])
        with pytest.raises(
            IndexError,
            match=r"Slot 1 is outside the tracked range "
            r"\(finalized_boundary=0, tracked_length=0\)",
        ):
            justified_slots.is_slot_justified(Slot(0), Slot(1))


class TestJustifiedSlotsExtendToSlot:
    """Capacity growth that keeps the tracked slot bitfield addressable."""

    def test_finalized_target_returns_same_instance_unchanged(self) -> None:
        """A target at or below the finalized boundary needs no growth and is returned as is."""
        justified_slots = JustifiedSlots(data=[Boolean(True)])
        assert justified_slots.extend_to_slot(Slot(5), Slot(2)) is justified_slots

    def test_exact_boundary_capacity_returns_same_instance(self) -> None:
        """A target that fits the last existing index exactly triggers no growth."""
        # Finalized 0, target 2 maps to index 1, which the two stored bits already cover.
        justified_slots = JustifiedSlots(data=[Boolean(True), Boolean(False)])
        assert justified_slots.extend_to_slot(Slot(0), Slot(2)) is justified_slots

    def test_surplus_capacity_returns_same_instance(self) -> None:
        """A target well within the existing capacity triggers no growth."""
        justified_slots = JustifiedSlots(data=[Boolean(True), Boolean(False), Boolean(True)])
        assert justified_slots.extend_to_slot(Slot(0), Slot(1)) is justified_slots

    def test_growth_by_one_appends_single_false_and_preserves_bits(self) -> None:
        """Growing by one index appends one False bit and keeps the existing bits."""
        justified_slots = JustifiedSlots(data=[Boolean(True)])
        extended_slots = justified_slots.extend_to_slot(Slot(0), Slot(2))
        assert extended_slots == JustifiedSlots(data=[Boolean(True), Boolean(False)])

    def test_growth_by_several_appends_only_false_bits(self) -> None:
        """Growing by several indices appends only False bits and keeps the existing bits."""
        justified_slots = JustifiedSlots(data=[Boolean(True)])
        extended_slots = justified_slots.extend_to_slot(Slot(0), Slot(4))
        assert extended_slots == JustifiedSlots(
            data=[Boolean(True), Boolean(False), Boolean(False), Boolean(False)]
        )

    def test_growth_from_empty_bitfield(self) -> None:
        """Growing an empty bitfield yields all False up to the required index."""
        justified_slots = JustifiedSlots(data=[])
        extended_slots = justified_slots.extend_to_slot(Slot(0), Slot(3))
        assert extended_slots == JustifiedSlots(
            data=[Boolean(False), Boolean(False), Boolean(False)]
        )

    def test_growth_with_nonzero_finalized_anchor(self) -> None:
        """A non-zero anchor offsets the required index when computing the gap to fill."""
        # Finalized 2, target 5 maps to index 2, so two False bits are appended.
        justified_slots = JustifiedSlots(data=[Boolean(True)])
        extended_slots = justified_slots.extend_to_slot(Slot(2), Slot(5))
        assert extended_slots == JustifiedSlots(
            data=[Boolean(True), Boolean(False), Boolean(False)]
        )

    def test_extended_slots_are_queryable_as_not_justified(self) -> None:
        """Slots filled by growth report as not justified until their bit is set."""
        justified_slots = JustifiedSlots(data=[Boolean(True)])
        extended_slots = justified_slots.extend_to_slot(Slot(0), Slot(3))
        assert extended_slots.is_slot_justified(Slot(0), Slot(1)) == Boolean(True)
        assert extended_slots.is_slot_justified(Slot(0), Slot(3)) == Boolean(False)


class TestSlotBitfieldLimits:
    """Construction and limit enforcement for the slot-tracking SSZ types."""

    @pytest.mark.parametrize(
        "slot_tracking_type",
        [HistoricalBlockHashes, JustificationRoots],
        ids=["historical_block_hashes", "justification_roots"],
    )
    def test_root_lists_share_historical_roots_limit(
        self, slot_tracking_type: type[HistoricalBlockHashes] | type[JustificationRoots]
    ) -> None:
        """Both root lists cap their length at the historical roots limit."""
        assert slot_tracking_type.LIMIT == int(HISTORICAL_ROOTS_LIMIT)

    def test_justified_slots_limit_is_historical_roots_limit(self) -> None:
        """The justified-slot bitfield caps at the historical roots limit."""
        assert JustifiedSlots.LIMIT == int(HISTORICAL_ROOTS_LIMIT)

    def test_justification_validators_limit_is_product_of_both_limits(self) -> None:
        """The flattened validator vote bitfield caps at roots times registry size."""
        assert JustificationValidators.LIMIT == int(HISTORICAL_ROOTS_LIMIT) * int(
            VALIDATOR_REGISTRY_LIMIT
        )

    @pytest.mark.parametrize(
        "slot_tracking_type",
        [HistoricalBlockHashes, JustificationRoots],
        ids=["historical_block_hashes", "justification_roots"],
    )
    def test_root_lists_construct_empty(
        self, slot_tracking_type: type[HistoricalBlockHashes] | type[JustificationRoots]
    ) -> None:
        """Both root lists construct as empty collections."""
        assert list(slot_tracking_type(data=[]).data) == []

    @pytest.mark.parametrize(
        "slot_tracking_type",
        [HistoricalBlockHashes, JustificationRoots],
        ids=["historical_block_hashes", "justification_roots"],
    )
    def test_root_lists_construct_populated(
        self, slot_tracking_type: type[HistoricalBlockHashes] | type[JustificationRoots]
    ) -> None:
        """Both root lists hold the exact roots they were built from."""
        roots = [Bytes32(bytes([7]) * 32), Bytes32(bytes([9]) * 32)]
        assert list(slot_tracking_type(data=roots).data) == roots

    @pytest.mark.parametrize(
        "bitfield_type",
        [JustifiedSlots, JustificationValidators],
        ids=["justified_slots", "justification_validators"],
    )
    def test_bitfields_construct_empty(
        self, bitfield_type: type[JustifiedSlots] | type[JustificationValidators]
    ) -> None:
        """Both bitfields construct as empty collections."""
        assert list(bitfield_type(data=[]).data) == []

    @pytest.mark.parametrize(
        "bitfield_type",
        [JustifiedSlots, JustificationValidators],
        ids=["justified_slots", "justification_validators"],
    )
    def test_bitfields_construct_populated(
        self, bitfield_type: type[JustifiedSlots] | type[JustificationValidators]
    ) -> None:
        """Both bitfields coerce their inputs into the booleans they were built from."""
        assert list(bitfield_type(data=[True, False, True]).data) == [
            Boolean(True),
            Boolean(False),
            Boolean(True),
        ]

    def test_justified_slots_exceeding_limit_raises(self) -> None:
        """A justified-slot bitfield longer than its limit is rejected."""
        with pytest.raises(SSZValueError, match=r"exceeds limit"):
            JustifiedSlots(data=[Boolean(False)] * (int(HISTORICAL_ROOTS_LIMIT) + 1))

    def test_justified_slots_at_limit_constructs(self) -> None:
        """A justified-slot bitfield exactly at its limit constructs successfully."""
        at_limit_slots = JustifiedSlots(data=[Boolean(False)] * int(HISTORICAL_ROOTS_LIMIT))
        assert len(at_limit_slots.data) == int(HISTORICAL_ROOTS_LIMIT)


class TestStateGenesis:
    """Field values present in a freshly generated genesis state."""

    def test_genesis_slot_is_zero(self) -> None:
        """Genesis starts at slot zero."""
        assert make_genesis_state(num_validators=1).slot == Slot(0)

    def test_genesis_history_collections_are_empty(self) -> None:
        """Genesis carries no historical hashes, justified slots, or justification tracking."""
        genesis_state = make_genesis_state(num_validators=4)
        assert genesis_state.historical_block_hashes == HistoricalBlockHashes(data=[])
        assert genesis_state.justified_slots == JustifiedSlots(data=[])
        assert genesis_state.justifications_roots == JustificationRoots(data=[])
        assert genesis_state.justifications_validators == JustificationValidators(data=[])

    def test_genesis_checkpoints_anchor_at_zero(self) -> None:
        """Genesis justified and finalized checkpoints both point at the zero anchor."""
        genesis_state = make_genesis_state(num_validators=2)
        genesis_anchor_checkpoint = Checkpoint(root=Bytes32.zero(), slot=Slot(0))
        assert genesis_state.latest_justified == genesis_anchor_checkpoint
        assert genesis_state.latest_finalized == genesis_anchor_checkpoint

    @pytest.mark.parametrize("num_validators", [1, 3, 16], ids=["one", "three", "sixteen"])
    def test_genesis_validator_registry_length_matches_request(self, num_validators: int) -> None:
        """The genesis validator registry length matches the requested validator count."""
        assert len(make_genesis_state(num_validators=num_validators).validators.data) == (
            num_validators
        )

    def test_genesis_config_records_genesis_time(self) -> None:
        """The genesis configuration records the supplied genesis time."""
        assert int(make_genesis_state(num_validators=1, genesis_time=42).config.genesis_time) == 42


class TestStateSerialization:
    """SSZ wire-format round-tripping for the State container."""

    def test_genesis_state_roundtrips_through_ssz_bytes(self) -> None:
        """Encoding genesis to SSZ bytes and decoding back reproduces the same state."""
        genesis_state = make_genesis_state(num_validators=3)
        assert State.decode_bytes(genesis_state.encode_bytes()) == genesis_state


class TestStateImmutability:
    """Frozen-model semantics forbid post-construction mutation."""

    def test_assigning_slot_raises(self) -> None:
        """Assigning a new slot on a constructed state raises."""
        genesis_state = make_genesis_state(num_validators=1)
        with pytest.raises(ValidationError, match="frozen"):
            genesis_state.slot = Slot(1)
