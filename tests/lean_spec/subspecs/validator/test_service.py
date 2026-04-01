"""Tests for Validator Service."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from consensus_testing.keys import XmssKeyManager, create_dummy_signature

from lean_spec.subspecs.chain.clock import SlotClock
from lean_spec.subspecs.containers import (
    AttestationData,
    Block,
    SignedAttestation,
    SignedBlock,
    ValidatorIndex,
    ValidatorIndices,
)
from lean_spec.subspecs.containers.attestation import AggregationBits
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.block_cache import BlockCache
from lean_spec.subspecs.sync.peer_manager import PeerManager
from lean_spec.subspecs.sync.service import SyncService
from lean_spec.subspecs.validator import ValidatorRegistry, ValidatorService
from lean_spec.subspecs.validator.registry import ValidatorEntry
from lean_spec.subspecs.xmss import TARGET_SIGNATURE_SCHEME
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import TEST_VALIDATOR_ID, MockNetworkRequester, make_store

# Patch target for the XMSS scheme reference inside service.py.
_SCHEME = "lean_spec.subspecs.validator.service.TARGET_SIGNATURE_SCHEME"

# Structurally valid but cryptographically meaningless signature for unit tests.


def _make_entry(index: int = 0) -> ValidatorEntry:
    """Return a ValidatorEntry with distinct named mock keys."""
    return ValidatorEntry(
        index=ValidatorIndex(index),
        attestation_secret_key=MagicMock(name=f"att_{index}"),
        proposal_secret_key=MagicMock(name=f"prop_{index}"),
    )


def _registry(*indices: int) -> ValidatorRegistry:
    """Build a ValidatorRegistry with mock keys for the given indices."""
    reg = ValidatorRegistry()
    for i in indices:
        mk = MagicMock(name=f"key_{i}")
        reg.add(
            ValidatorEntry(
                index=ValidatorIndex(i),
                attestation_secret_key=mk,
                proposal_secret_key=mk,
            )
        )
    return reg


def _mock_store(
    *,
    slot_for_block: Slot | None = None,
    head_state: MagicMock | None = None,
    validator_id: ValidatorIndex | None = None,
) -> MagicMock:
    """
    Return a MagicMock store for unit tests.

    head_state=None causes attestation/block production to return early,
    which is useful when the test only targets earlier code paths.
    """
    store = MagicMock(
        head=MagicMock(name="head_root"),
        validator_id=validator_id,
        blocks=({"b": MagicMock(slot=slot_for_block)} if slot_for_block is not None else {}),
        states=MagicMock(),
    )
    store.states.get.return_value = head_state
    store.update_head.return_value = store
    store.on_gossip_attestation.return_value = store
    store.produce_attestation_data.return_value = MagicMock(spec=AttestationData)
    return store


def _monotonic_clock(*, slot: Slot | None = None, interval: Uint64 | None = None) -> MagicMock:
    """
    Clock whose total_intervals() increments on every call.

    Use when the test drives the loop by calling service.stop() inside a mock,
    because a monotonically increasing counter means already_handled never fires
    accidentally (the loop always moves forward).
    """
    if slot is None:
        slot = Slot(0)
    if interval is None:
        interval = Uint64(0)

    clock = MagicMock(spec=SlotClock)
    _n: list[int] = [0]

    def _total() -> int:
        _n[0] += 1
        return _n[0]

    clock.total_intervals.side_effect = _total
    clock.current_slot.return_value = slot
    clock.current_interval.return_value = interval
    clock.sleep_until_next_interval = AsyncMock()
    return clock


def _fixed_clock(*, slot: Slot | None = None, interval: Uint64 | None = None) -> MagicMock:
    """
    Clock whose total_intervals() always returns the same value (1).

    Use when the test needs already_handled to fire on the second iteration,
    which triggers sleep_until_next_interval — useful for duplicate-prevention
    and slot-pruning tests where we stop via the sleep mock.
    """
    slot = slot or Slot(0)
    interval = interval or Uint64(0)
    clock = MagicMock(spec=SlotClock)
    clock.total_intervals.return_value = 1
    clock.current_slot.return_value = slot
    clock.current_interval.return_value = interval
    clock.sleep_until_next_interval = AsyncMock()
    return clock


@pytest.fixture
def sync_service(base_store: Store) -> SyncService:
    """Sync service backed by the shared base store."""
    return SyncService(
        store=base_store,
        peer_manager=PeerManager(),
        block_cache=BlockCache(),
        clock=SlotClock(genesis_time=Uint64(0)),
        network=MockNetworkRequester(),
    )


@pytest.fixture
def mock_registry() -> ValidatorRegistry:
    """Registry with mock keys for validators 0 and 1."""
    return _registry(0, 1)


class TestSignBlock:
    """
    Unit tests for block signing.

    The XMSS signing logic is patched throughout so these tests cover only
    field population and key-type selection, not advancement logic.
    """

    def _setup(self, sync_service: SyncService, *, slot: int = 1) -> tuple[ValidatorService, Block]:
        entry = _make_entry(0)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        block = Block(
            slot=Slot(slot),
            proposer_index=ValidatorIndex(0),
            parent_root=sync_service.store.head,
            state_root=sync_service.store.head,
            body=sync_service.store.blocks[sync_service.store.head].body,
        )
        return service, block

    def test_wraps_the_input_block(self, sync_service: SyncService) -> None:
        """The returned signed block contains the exact block object that was passed in."""
        service, block = self._setup(sync_service)

        with patch.object(
            ValidatorService,
            "_sign_with_key",
            lambda self, e, slot, msg, kf: (e, create_dummy_signature()),
        ):
            result = service._sign_block(block, ValidatorIndex(0), [])

        assert result.block is block

    def test_proposer_signature_comes_from_signing_logic(self, sync_service: SyncService) -> None:
        """The proposer signature field is the exact signature returned by the signing logic."""
        service, block = self._setup(sync_service)

        with patch.object(
            ValidatorService,
            "_sign_with_key",
            lambda self, e, slot, msg, kf: (e, create_dummy_signature()),
        ):
            result = service._sign_block(block, ValidatorIndex(0), [])

        assert result.signature.proposer_signature == create_dummy_signature()

    def test_uses_proposal_key_and_block_root(self, sync_service: SyncService) -> None:
        """Block signing uses the proposal key field and the block root as message."""
        service, block = self._setup(sync_service, slot=2)
        captured: list[tuple] = []

        def capture(self, e, slot, message, key_field):
            captured.append((slot, message, key_field))
            return (e, create_dummy_signature())

        with patch.object(ValidatorService, "_sign_with_key", capture):
            service._sign_block(block, ValidatorIndex(0), [])

        assert len(captured) == 1
        slot, message, key_field = captured[0]
        assert slot == Slot(2)
        assert message == hash_tree_root(block)
        assert key_field == "proposal_secret_key"

    def test_attestation_signatures_included(self, sync_service: SyncService) -> None:
        """Aggregated attestation proofs passed in are present in the returned signature."""
        service, block = self._setup(sync_service)
        agg_proof = MagicMock(spec=AggregatedSignatureProof)

        with patch.object(
            ValidatorService,
            "_sign_with_key",
            lambda self, e, slot, msg, kf: (e, create_dummy_signature()),
        ):
            result = service._sign_block(block, ValidatorIndex(0), [agg_proof])

        assert agg_proof in list(result.signature.attestation_signatures)

    def test_missing_validator_raises_value_error(self, sync_service: SyncService) -> None:
        """Signing a block with an unregistered validator index raises ValueError."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )
        block = Block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(42),
            parent_root=sync_service.store.head,
            state_root=sync_service.store.head,
            body=sync_service.store.blocks[sync_service.store.head].body,
        )

        with pytest.raises(ValueError, match="No secret key for validator 42"):
            service._sign_block(block, ValidatorIndex(42), [])


class TestSignAttestation:
    """
    Unit tests for attestation signing.

    The XMSS signing logic is patched so tests cover only field population
    and key-type selection.
    """

    def _setup(
        self, sync_service: SyncService, index: int = 0
    ) -> tuple[ValidatorService, AttestationData]:
        entry = _make_entry(index)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        att_data = sync_service.store.produce_attestation_data(Slot(1))
        return service, att_data

    def test_fields_populated_correctly(self, sync_service: SyncService) -> None:
        """The signed attestation contains the correct validator ID, data, and signature."""
        service, att_data = self._setup(sync_service, index=3)

        with patch.object(
            ValidatorService,
            "_sign_with_key",
            lambda self, e, slot, msg, kf: (e, create_dummy_signature()),
        ):
            result = service._sign_attestation(att_data, ValidatorIndex(3))

        assert result.validator_id == ValidatorIndex(3)
        assert result.data is att_data
        assert result.signature == create_dummy_signature()

    def test_uses_attestation_key_not_proposal_key(self, sync_service: SyncService) -> None:
        """Attestation signing selects the attestation key, never the proposal key."""
        service, att_data = self._setup(sync_service)
        captured: list[str] = []

        def capture(self, e, slot, message, key_field):
            captured.append(key_field)
            return (e, create_dummy_signature())

        with patch.object(ValidatorService, "_sign_with_key", capture):
            service._sign_attestation(att_data, ValidatorIndex(0))

        assert captured == ["attestation_secret_key"]

    def test_missing_validator_raises_value_error(self, sync_service: SyncService) -> None:
        """Signing an attestation with an unregistered validator index raises ValueError."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )
        att_data = sync_service.store.produce_attestation_data(Slot(1))

        with pytest.raises(ValueError, match="No secret key for validator 99"):
            service._sign_attestation(att_data, ValidatorIndex(99))


class TestSignWithKey:
    """Unit tests for the XMSS key advancement and signing logic."""

    def _setup(
        self, sync_service: SyncService, index: int = 0
    ) -> tuple[ValidatorService, ValidatorRegistry, ValidatorEntry, object, object]:
        entry = _make_entry(index)
        att_key = entry.attestation_secret_key
        prop_key = entry.proposal_secret_key
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        return service, registry, entry, att_key, prop_key

    def test_no_advancement_when_slot_already_prepared(self, sync_service: SyncService) -> None:
        """No key advancement when the slot is already within the prepared interval."""
        service, _, entry, att_key, _ = self._setup(sync_service)
        mock_sig = MagicMock(name="sig")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.return_value = [3]  # slot 3 already covered
            scheme.sign.return_value = mock_sig

            service._sign_with_key(entry, Slot(3), MagicMock(), "attestation_secret_key")

        scheme.advance_preparation.assert_not_called()
        scheme.sign.assert_called_once_with(att_key, Slot(3), scheme.sign.call_args[0][2])

    def test_key_advanced_once_until_slot_in_interval(self, sync_service: SyncService) -> None:
        """Key advances exactly once when one step covers the target slot."""
        service, _, entry, att_key, _ = self._setup(sync_service)
        advanced = MagicMock(name="advanced_key")
        mock_sig = MagicMock(name="sig")

        with patch(_SCHEME) as scheme:
            # Original key: slot 5 not ready.  Advanced key: slot 5 ready.
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is att_key else [5]
            scheme.advance_preparation.return_value = advanced
            scheme.sign.return_value = mock_sig

            service._sign_with_key(entry, Slot(5), MagicMock(), "attestation_secret_key")

        scheme.advance_preparation.assert_called_once_with(att_key)
        scheme.sign.assert_called_once_with(advanced, Slot(5), scheme.sign.call_args[0][2])

    def test_key_advanced_multiple_times_until_prepared(self, sync_service: SyncService) -> None:
        """Key advancement loops until the target slot falls within the interval."""
        service, _, entry, att_key, _ = self._setup(sync_service)
        key_v1 = MagicMock(name="key_v1")
        key_v2 = MagicMock(name="key_v2")
        key_v3 = MagicMock(name="key_v3")  # Only v3 covers slot 7
        mock_sig = MagicMock(name="sig")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [7] if key is key_v3 else []
            scheme.advance_preparation.side_effect = [key_v1, key_v2, key_v3]
            scheme.sign.return_value = mock_sig

            service._sign_with_key(entry, Slot(7), MagicMock(), "attestation_secret_key")

        assert scheme.advance_preparation.call_count == 3
        scheme.sign.assert_called_once_with(key_v3, Slot(7), scheme.sign.call_args[0][2])

    def test_updated_entry_persisted_in_registry(self, sync_service: SyncService) -> None:
        """After signing, the registry holds an entry with the advanced key."""
        service, registry, entry, att_key, prop_key = self._setup(sync_service)
        advanced = MagicMock(name="advanced_att")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is att_key else [4]
            scheme.advance_preparation.return_value = advanced
            scheme.sign.return_value = MagicMock()

            service._sign_with_key(entry, Slot(4), MagicMock(), "attestation_secret_key")

        stored = registry.get(ValidatorIndex(0))
        assert stored is not None
        assert stored.attestation_secret_key is advanced

    def test_attestation_key_updated_proposal_key_unchanged(
        self, sync_service: SyncService
    ) -> None:
        """Signing with the attestation key updates only that key; proposal key is untouched."""
        service, registry, entry, att_key, prop_key = self._setup(sync_service)
        advanced_att = MagicMock(name="new_att")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is att_key else [1]
            scheme.advance_preparation.return_value = advanced_att
            scheme.sign.return_value = MagicMock()

            service._sign_with_key(entry, Slot(1), MagicMock(), "attestation_secret_key")

        stored = registry.get(ValidatorIndex(0))
        assert stored is not None
        assert stored.attestation_secret_key is advanced_att
        assert stored.proposal_secret_key is prop_key  # untouched

    def test_proposal_key_updated_attestation_key_unchanged(
        self, sync_service: SyncService
    ) -> None:
        """Signing with the proposal key updates only that key; attestation key is untouched."""
        service, registry, entry, att_key, prop_key = self._setup(sync_service)
        advanced_prop = MagicMock(name="new_prop")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is prop_key else [1]
            scheme.advance_preparation.return_value = advanced_prop
            scheme.sign.return_value = MagicMock()

            service._sign_with_key(entry, Slot(1), MagicMock(), "proposal_secret_key")

        stored = registry.get(ValidatorIndex(0))
        assert stored is not None
        assert stored.proposal_secret_key is advanced_prop
        assert stored.attestation_secret_key is att_key  # untouched

    def test_returns_updated_entry_and_signature(self, sync_service: SyncService) -> None:
        """Return value is (updated ValidatorEntry, Signature) — both fields correct."""
        service, _, entry, att_key, _ = self._setup(sync_service)
        advanced = MagicMock(name="adv")
        mock_sig = MagicMock(name="ret_sig")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is att_key else [2]
            scheme.advance_preparation.return_value = advanced
            scheme.sign.return_value = mock_sig

            ret_entry, ret_sig = service._sign_with_key(
                entry, Slot(2), MagicMock(), "attestation_secret_key"
            )

        assert ret_sig is mock_sig
        assert ret_entry.attestation_secret_key is advanced


class TestValidatorServiceBasic:
    """Basic tests for lifecycle properties."""

    def test_service_starts_stopped(
        self,
        sync_service: SyncService,
        mock_registry: ValidatorRegistry,
    ) -> None:
        """A new service is not running and has zero counters."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=mock_registry,
        )

        assert not service.is_running
        assert service.blocks_produced == 0
        assert service.attestations_produced == 0

    def test_stop_sets_running_to_false(
        self,
        sync_service: SyncService,
        mock_registry: ValidatorRegistry,
    ) -> None:
        """Stopping the service sets the running flag to False."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=mock_registry,
        )

        service._running = True
        service.stop()
        assert not service.is_running


class TestMaybeProduceBlock:
    """Unit tests for block production edge cases."""

    async def test_zero_validators_in_state_returns_early(self, sync_service: SyncService) -> None:
        """When head state has zero validators, no ZeroDivisionError — returns early."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=_registry(0),
        )
        mock_head_state = MagicMock()
        mock_head_state.validators = []
        sync_service.store = _mock_store(head_state=mock_head_state)

        blocks: list[SignedBlock] = []

        async def capture(block: SignedBlock) -> None:
            blocks.append(block)

        service.on_block = capture
        await service._maybe_produce_block(Slot(0))

        assert blocks == []

    async def test_no_head_state_returns_early(self, sync_service: SyncService) -> None:
        """When no head state is available, no block is produced and no error is raised."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=_registry(0),
        )
        sync_service.store = _mock_store(head_state=None)

        blocks: list[SignedBlock] = []

        async def capture(block: SignedBlock) -> None:
            blocks.append(block)

        service.on_block = capture
        await service._maybe_produce_block(Slot(0))

        assert blocks == []

    async def test_assertion_error_is_logged_and_skipped(
        self, sync_service: SyncService, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Store AssertionError during block production is caught; no block emitted."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=_registry(0),
        )

        mock_head_state = MagicMock()
        mock_head_state.validators = [MagicMock()]  # 1 validator
        store = _mock_store(head_state=mock_head_state)
        store.produce_block_with_signatures.side_effect = AssertionError("proposer mismatch")
        sync_service.store = store

        blocks: list[SignedBlock] = []

        async def capture(block: SignedBlock) -> None:
            blocks.append(block)

        service.on_block = capture

        with patch.object(ValidatorIndex, "is_proposer_for", return_value=True):
            await service._maybe_produce_block(Slot(0))

        assert blocks == []


class TestValidatorServiceDuties:
    """Tests for duty execution edge cases."""

    async def test_no_block_when_not_proposer(
        self,
        sync_service: SyncService,
    ) -> None:
        """No block produced when we're not the scheduled proposer."""
        blocks_received: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_received.append(block)

        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=_registry(2),
            on_block=capture_block,
        )

        # Validator 2 is proposer for slot 2, not slots 0 or 1
        await service._maybe_produce_block(Slot(0))
        await service._maybe_produce_block(Slot(1))

        assert blocks_received == []

    async def test_empty_registry_skips_attestations(
        self,
        sync_service: SyncService,
    ) -> None:
        """Empty registry produces no attestations."""
        attestations_received: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_received.append(attestation)

        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(Slot(0))

        assert attestations_received == []
        assert service.attestations_produced == 0


class TestProduceAttestationsAdvanced:
    """Unit tests for the block-wait polling loop and local attestation processing."""

    async def test_block_wait_polls_up_to_eight_times_when_no_block_arrives(
        self, sync_service: SyncService
    ) -> None:
        """
        If no block for the target slot ever arrives, the wait loop runs exactly 8 times
        with 0.05-second sleeps, then gives up and continues to attest anyway.
        """
        target_slot = Slot(99)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )

        sleep_durations: list[float] = []

        async def mock_sleep(duration: float) -> None:
            sleep_durations.append(duration)

        with patch("asyncio.sleep", new=mock_sleep):
            await service._produce_attestations(target_slot)

        assert len(sleep_durations) == 8
        assert all(d == pytest.approx(0.05) for d in sleep_durations)

    async def test_block_wait_exits_early_when_block_arrives(
        self, sync_service: SyncService
    ) -> None:
        """The polling loop breaks as soon as it detects a block for the target slot."""
        target_slot = Slot(77)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )

        sync_service.store = _mock_store(head_state=None)
        with_block = _mock_store(slot_for_block=target_slot, head_state=None)

        sleep_calls = [0]

        async def mock_sleep(duration: float) -> None:
            sleep_calls[0] += 1
            if sleep_calls[0] == 3:
                sync_service.store = with_block

        with patch("asyncio.sleep", new=mock_sleep):
            await service._produce_attestations(target_slot)

        assert sleep_calls[0] == 3

    async def test_attestation_processed_locally_before_publish(
        self, sync_service: SyncService
    ) -> None:
        """
        Each produced attestation is passed to the store's gossip handler before
        being published, ensuring the aggregator node counts its own validator's vote.
        """
        target_slot = Slot(1)
        mock_att = MagicMock(spec=SignedAttestation, name="att")

        mock_head_state = MagicMock()
        store = _mock_store(slot_for_block=target_slot, head_state=mock_head_state)
        store.validator_id = None
        sync_service.store = store

        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=_registry(0),
        )

        with patch.object(ValidatorService, "_sign_attestation", lambda self, *a, **kw: mock_att):
            await service._produce_attestations(target_slot)

        store.on_gossip_attestation.assert_called_once_with(
            signed_attestation=mock_att,
            is_aggregator=False,
        )

    async def test_gossip_handler_exception_logged_and_attestation_still_published(
        self, sync_service: SyncService, caplog: pytest.LogCaptureFixture
    ) -> None:
        """
        If local gossip processing raises, the exception is logged and the attestation
        is still published so the network receives it.
        """
        target_slot = Slot(1)
        mock_att = MagicMock(spec=SignedAttestation, name="att")

        mock_head_state = MagicMock()
        store = _mock_store(slot_for_block=target_slot, head_state=mock_head_state)
        store.validator_id = None
        store.on_gossip_attestation.side_effect = RuntimeError("store error")
        sync_service.store = store

        published: list[SignedAttestation] = []

        async def capture_att(att: SignedAttestation) -> None:
            published.append(att)

        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=_registry(0),
            on_attestation=capture_att,
        )

        with (
            caplog.at_level("DEBUG"),
            patch.object(ValidatorService, "_sign_attestation", lambda self, data, vid: mock_att),
        ):
            await service._produce_attestations(target_slot)

        assert published == [mock_att]
        assert "on_gossip_attestation failed" in caplog.text


class TestValidatorServiceRun:
    """Tests for the main run loop."""

    async def test_run_loop_can_be_stopped(
        self,
        sync_service: SyncService,
    ) -> None:
        """The main loop exits when the service is stopped."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )

        call_count = 0

        async def stop_on_second_call(_duration: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                service.stop()

        with patch("asyncio.sleep", new=stop_on_second_call):
            await service.run()

        assert not service.is_running

    async def test_interval_0_triggers_block_production(self, sync_service: SyncService) -> None:
        """At interval 0, the main loop triggers block production for the current slot."""
        clock = _monotonic_clock(slot=Slot(0), interval=Uint64(0))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_registry(0),
        )

        block_slots: list[Slot] = []

        async def mock_produce(self_inner, slot: Slot) -> None:
            block_slots.append(slot)
            service.stop()

        with patch.object(ValidatorService, "_maybe_produce_block", mock_produce):
            await service.run()

        assert block_slots == [Slot(0)]

    async def test_interval_1_triggers_attestation(self, sync_service: SyncService) -> None:
        """At interval >= 1, the main loop triggers attestation production."""
        clock = _monotonic_clock(slot=Slot(0), interval=Uint64(1))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_registry(0),
        )

        attest_slots: list[Slot] = []

        async def mock_attest(self_inner, slot: Slot) -> None:
            attest_slots.append(slot)
            service.stop()

        with patch.object(ValidatorService, "_produce_attestations", mock_attest):
            await service.run()

        assert attest_slots == [Slot(0)]

    async def test_empty_registry_skips_all_duties(self, sync_service: SyncService) -> None:
        """With an empty registry, the loop skips all duties without calling production."""
        clock = _fixed_clock(slot=Slot(0), interval=Uint64(0))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=ValidatorRegistry(),
        )

        sleep_calls = [0]

        async def stop_after_two_sleeps() -> None:
            sleep_calls[0] += 1
            if sleep_calls[0] >= 2:
                service.stop()

        clock.sleep_until_next_interval = AsyncMock(side_effect=stop_after_two_sleeps)

        block_calls: list[Slot] = []
        attest_calls: list[Slot] = []

        with (
            patch.object(
                ValidatorService,
                "_maybe_produce_block",
                AsyncMock(side_effect=lambda self, s: block_calls.append(s)),
            ),
            patch.object(
                ValidatorService,
                "_produce_attestations",
                AsyncMock(side_effect=lambda self, s: attest_calls.append(s)),
            ),
        ):
            await service.run()

        assert block_calls == []
        assert attest_calls == []

    async def test_duplicate_prevention_same_slot_not_attested_twice(
        self, sync_service: SyncService
    ) -> None:
        """A slot already in the attested set does not trigger attestation production again."""
        clock = _fixed_clock(slot=Slot(5), interval=Uint64(1))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_registry(0),
        )
        service._attested_slots = {Slot(5)}  # already attested

        async def stop_on_sleep() -> None:
            service.stop()

        clock.sleep_until_next_interval = AsyncMock(side_effect=stop_on_sleep)

        attest_calls: list[Slot] = []

        async def mock_attest(self_inner, slot: Slot) -> None:
            attest_calls.append(slot)

        with patch.object(ValidatorService, "_produce_attestations", mock_attest):
            await service.run()

        assert attest_calls == []

    async def test_slot_pruning_removes_old_slots(self, sync_service: SyncService) -> None:
        """
        After attesting at slot N, old slots are pruned to bound memory.

        At slot 10: prune_threshold = max(0, 10 - 4) = 6.
        Slots 0-5 (all < 6) must be removed; slot 10 must be present.
        """
        clock = _monotonic_clock(slot=Slot(10), interval=Uint64(1))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_registry(0),
        )
        service._attested_slots = {Slot(i) for i in range(6)}  # slots 0-5

        async def mock_attest(self_inner, slot: Slot) -> None:
            service.stop()

        with patch.object(ValidatorService, "_produce_attestations", mock_attest):
            await service.run()

        for old_slot in range(6):
            assert Slot(old_slot) not in service._attested_slots
        assert Slot(10) in service._attested_slots


class TestProposerGossipAttestation:
    """Tests verifying that all validators (including proposers) produce gossip attestations."""

    @pytest.mark.parametrize(
        ("num_validators", "slot"),
        [
            (2, Slot(0)),  # 2 validators, proposer is validator 0
            (3, Slot(2)),  # 3 validators, proposer is validator 2
        ],
    )
    async def test_all_validators_attest_including_proposer(
        self,
        sync_service: SyncService,
        num_validators: int,
        slot: Slot,
    ) -> None:
        """
        All validators produce gossip attestations, including the proposer.

        With dual keys, the proposer signs the block envelope with the proposal
        key and gossips a separate attestation with the attestation key.
        """
        registry = _registry(*range(num_validators))
        signed_validator_ids: list[ValidatorIndex] = []

        def mock_sign_attestation(
            self: ValidatorService,  # noqa: ARG001
            attestation_data: object,  # noqa: ARG001
            validator_index: ValidatorIndex,
        ) -> SignedAttestation:
            signed_validator_ids.append(validator_index)
            return MagicMock(spec=SignedAttestation, validator_id=validator_index)

        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )

        with patch.object(ValidatorService, "_sign_attestation", mock_sign_attestation):
            await service._produce_attestations(slot)

        expected = {ValidatorIndex(i) for i in range(num_validators)}
        assert set(signed_validator_ids) == expected
        assert service.attestations_produced == num_validators


class TestValidatorServiceIntegration:
    """
    Integration tests using real cryptographic keys and signature verification.

    These tests verify the full signing flow end-to-end without mocking.
    All signatures are cryptographically valid and verifiable.
    """

    @pytest.fixture
    def key_manager(self) -> XmssKeyManager:
        """Key manager with pre-generated test keys."""
        return XmssKeyManager.shared(max_slot=Slot(10))

    @pytest.fixture
    def real_store(self, key_manager: XmssKeyManager) -> Store:
        """Forkchoice store with validators using real public keys."""
        return make_store(num_validators=6, key_manager=key_manager, validator_id=TEST_VALIDATOR_ID)

    @pytest.fixture
    def real_sync_service(self, real_store: Store) -> SyncService:
        """Sync service initialized with the real store."""
        return SyncService(
            store=real_store,
            peer_manager=PeerManager(),
            block_cache=BlockCache(),
            clock=SlotClock(genesis_time=Uint64(0)),
            network=MockNetworkRequester(),
        )

    @pytest.fixture
    def real_registry(self, key_manager: XmssKeyManager) -> ValidatorRegistry:
        """Registry populated with real secret keys from key manager."""
        registry = ValidatorRegistry()
        for i in range(6):
            validator_index = ValidatorIndex(i)
            kp = key_manager[validator_index]
            registry.add(
                ValidatorEntry(
                    index=validator_index,
                    attestation_secret_key=kp.attestation_secret,
                    proposal_secret_key=kp.proposal_secret,
                )
            )
        return registry

    async def test_produce_real_block_with_valid_signature(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Produce a block and verify the proposer signature is cryptographically valid.

        The signature must pass verification using the proposer's public key.
        """
        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_block=capture_block,
        )

        # Slot 1: proposer is validator 1 (1 % 6 == 1)
        await service._maybe_produce_block(Slot(1))

        assert len(blocks_produced) == 1
        signed_block = blocks_produced[0]

        assert signed_block.block.slot == Slot(1)
        assert signed_block.block.proposer_index == ValidatorIndex(1)

        proposer_index = signed_block.block.proposer_index
        block_root = hash_tree_root(signed_block.block)
        proposer_public_key = key_manager[proposer_index].proposal_public

        is_valid = TARGET_SIGNATURE_SCHEME.verify(
            pk=proposer_public_key,
            slot=signed_block.block.slot,
            message=block_root,
            sig=signed_block.signature.proposer_signature,
        )
        assert is_valid, "Proposer signature failed verification"

    async def test_produce_real_attestation_with_valid_signature(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Produce attestations and verify each signature is cryptographically valid.

        All validators produce attestations with valid XMSS signatures.
        """
        attestations_produced: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(Slot(1))

        assert len(attestations_produced) == 6

        for signed_att in attestations_produced:
            validator_id = signed_att.validator_id
            public_key = key_manager[validator_id].attestation_public
            message_bytes = signed_att.data.data_root_bytes()

            is_valid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                slot=signed_att.data.slot,
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert is_valid, f"Attestation signature for validator {validator_id} failed"

    async def test_attestation_data_references_correct_checkpoints(
        self,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify attestation data contains correct head, target, and source checkpoints.

        The attestation must reference:
        - head: the current chain head
        - target: the attestation target based on forkchoice
        - source: the latest justified checkpoint
        """
        attestations_produced: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(Slot(1))

        store = real_sync_service.store
        expected_head_root = store.head
        expected_source = store.latest_justified

        for signed_att in attestations_produced:
            data = signed_att.data
            assert data.head.root == expected_head_root
            assert data.source == expected_source
            assert data.slot == Slot(1)

    async def test_proposer_signature_in_block(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """Verify the proposer's signature over the block root is cryptographically valid."""
        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_block=capture_block,
        )

        await service._maybe_produce_block(Slot(2))

        assert len(blocks_produced) == 1
        signed_block = blocks_produced[0]

        proposer_index = signed_block.block.proposer_index
        block_root = hash_tree_root(signed_block.block)
        public_key = key_manager[proposer_index].proposal_public

        is_valid = TARGET_SIGNATURE_SCHEME.verify(
            pk=public_key,
            slot=signed_block.block.slot,
            message=block_root,
            sig=signed_block.signature.proposer_signature,
        )
        assert is_valid

    async def test_block_includes_pending_attestations(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify attestations from the pool are included in produced blocks.

        When the store has pending attestations, the proposer should aggregate
        and include them in the block body.
        """
        store = real_sync_service.store
        attestation_data = store.produce_attestation_data(Slot(0))
        data_root = attestation_data.data_root_bytes()

        participants = [ValidatorIndex(3), ValidatorIndex(4)]
        public_keys = []
        signatures = []

        for vid in participants:
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signatures.append(sig)
            public_keys.append(key_manager[vid].attestation_public)

        xmss_participants = AggregationBits.from_validator_indices(
            ValidatorIndices(data=participants)
        )
        proof = AggregatedSignatureProof.aggregate(
            xmss_participants=xmss_participants,
            children=[],
            raw_xmss=list(zip(public_keys, signatures, strict=True)),
            message=data_root,
            slot=attestation_data.slot,
        )

        updated_store = store.model_copy(
            update={"latest_known_aggregated_payloads": {attestation_data: {proof}}}
        )
        real_sync_service.store = updated_store

        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_block=capture_block,
        )

        await service._maybe_produce_block(Slot(1))

        assert len(blocks_produced) == 1
        signed_block = blocks_produced[0]

        body_attestations = signed_block.block.body.attestations
        assert len(body_attestations) > 0

        attestation_signatures = signed_block.signature.attestation_signatures
        assert len(attestation_signatures) == len(body_attestations)

    async def test_multiple_slots_produce_different_attestations(
        self,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """Attestations produced at different slots have distinct slot values."""
        attestations_by_slot: dict[Slot, list[SignedAttestation]] = {
            Slot(1): [],
            Slot(2): [],
        }

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_by_slot[attestation.data.slot].append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(Slot(1))
        await service._produce_attestations(Slot(2))

        assert len(attestations_by_slot[Slot(1)]) > 0
        assert len(attestations_by_slot[Slot(2)]) > 0

        for att in attestations_by_slot[Slot(1)]:
            assert att.data.slot == Slot(1)
        for att in attestations_by_slot[Slot(2)]:
            assert att.data.slot == Slot(2)

    async def test_proposer_also_gossips_attestation(
        self,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        The proposer produces a block at interval 0 and a gossip attestation at interval 1.

        Both intervals use independent keys, so there is no OTS conflict.
        """
        blocks_produced: list[SignedBlock] = []
        attestations_produced: list[SignedAttestation] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_block=capture_block,
            on_attestation=capture_attestation,
        )

        slot = Slot(3)
        proposer_index = ValidatorIndex(3)  # 3 % 6 == 3

        await service._maybe_produce_block(slot)
        await service._produce_attestations(slot)

        assert len(blocks_produced) == 1
        assert blocks_produced[0].block.proposer_index == proposer_index

        attestation_validator_ids = {att.validator_id for att in attestations_produced}
        expected_attesters = {ValidatorIndex(i) for i in range(6)}
        assert attestation_validator_ids == expected_attesters

    async def test_block_state_root_is_valid(
        self,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        The produced block has a valid state root matching the post-state hash.
        """
        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_block=capture_block,
        )

        await service._maybe_produce_block(Slot(4))

        assert len(blocks_produced) == 1
        produced_block = blocks_produced[0].block

        assert produced_block.state_root != Bytes32.zero()

        store = real_sync_service.store
        block_hash = hash_tree_root(produced_block)
        assert block_hash in store.blocks
        assert block_hash in store.states

        stored_state = store.states[block_hash]
        computed_state_root = hash_tree_root(stored_state)
        assert produced_block.state_root == computed_state_root

    async def test_signature_uses_correct_slot(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """Signatures verify with the signing slot but fail with any other slot."""
        attestations_produced: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        test_slot = Slot(5)

        await service._produce_attestations(test_slot)

        for signed_att in attestations_produced:
            validator_id = signed_att.validator_id
            public_key = key_manager[validator_id].attestation_public
            message_bytes = signed_att.data.data_root_bytes()

            is_valid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                slot=test_slot,
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert is_valid, f"Slot {test_slot} signature failed for validator {validator_id}"

            wrong_slot = test_slot + Slot(1)
            is_invalid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                slot=wrong_slot,
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert not is_invalid, "Signature should not verify with the wrong slot"
