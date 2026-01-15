"""Tests for ValidatorService."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from lean_spec.subspecs.chain.clock import SlotClock
from lean_spec.subspecs.containers import (
    Block,
    SignedAttestation,
    SignedBlockWithAttestation,
    State,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.sync.backfill_sync import NetworkRequester
from lean_spec.subspecs.sync.block_cache import BlockCache
from lean_spec.subspecs.sync.peer_manager import PeerManager
from lean_spec.subspecs.sync.service import SyncService
from lean_spec.subspecs.validator import ValidatorRegistry, ValidatorService
from lean_spec.subspecs.validator.registry import ValidatorEntry
from lean_spec.types import Uint64


class MockNetworkRequester(NetworkRequester):
    """Mock network requester for testing."""

    async def request_block_by_root(
        self,
        peer_id: str,  # noqa: ARG002
        root: bytes,  # noqa: ARG002
    ) -> SignedBlockWithAttestation | None:
        """Return None - no blocks available."""
        return None


@pytest.fixture
def store(genesis_state: State, genesis_block: Block) -> Store:
    """Forkchoice store initialized with genesis."""
    return Store.get_forkchoice_store(genesis_state, genesis_block)


@pytest.fixture
def sync_service(store: Store) -> SyncService:
    """Sync service with store."""
    return SyncService(
        store=store,
        peer_manager=PeerManager(),
        block_cache=BlockCache(),
        clock=SlotClock(genesis_time=Uint64(0)),
        network=MockNetworkRequester(),
    )


@pytest.fixture
def mock_registry() -> ValidatorRegistry:
    """Registry with mock keys for validators 0 and 1."""
    registry = ValidatorRegistry()
    for i in [0, 1]:
        mock_key = MagicMock()
        registry.add(ValidatorEntry(index=Uint64(i), secret_key=mock_key))
    return registry


class TestValidatorServiceBasic:
    """Basic tests for ValidatorService."""

    def test_service_starts_stopped(
        self,
        sync_service: SyncService,
        mock_registry: ValidatorRegistry,
    ) -> None:
        """Service is not running before start."""
        clock = SlotClock(genesis_time=Uint64(0))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=mock_registry,
        )

        assert not service.is_running
        assert service.blocks_produced == 0
        assert service.attestations_produced == 0

    def test_stop_service(
        self,
        sync_service: SyncService,
        mock_registry: ValidatorRegistry,
    ) -> None:
        """stop() sets running flag to False."""
        clock = SlotClock(genesis_time=Uint64(0))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=mock_registry,
        )

        service._running = True
        service.stop()
        assert not service.is_running


class TestValidatorServiceDuties:
    """Tests for duty execution."""

    def test_no_block_when_not_proposer(
        self,
        sync_service: SyncService,
    ) -> None:
        """No block produced when we're not the proposer."""
        clock = SlotClock(genesis_time=Uint64(0))

        # Registry with validator 2 only
        registry = ValidatorRegistry()
        mock_key = MagicMock()
        registry.add(ValidatorEntry(index=Uint64(2), secret_key=mock_key))

        blocks_received: list[SignedBlockWithAttestation] = []

        async def capture_block(block: SignedBlockWithAttestation) -> None:
            blocks_received.append(block)

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
            on_block=capture_block,
        )

        async def check_no_blocks() -> None:
            # Slot 0 proposer is validator 0, slot 1 is validator 1
            # Validator 2 is proposer for slot 2
            await service._maybe_produce_block(Slot(0))
            await service._maybe_produce_block(Slot(1))

        asyncio.run(check_no_blocks())

        assert len(blocks_received) == 0

    def test_empty_registry_skips_duties(
        self,
        sync_service: SyncService,
    ) -> None:
        """Empty registry skips all duty execution."""
        clock = SlotClock(genesis_time=Uint64(0))
        registry = ValidatorRegistry()

        attestations_received: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_received.append(attestation)

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
            on_attestation=capture_attestation,
        )

        async def produce() -> None:
            await service._produce_attestations(Slot(0))

        asyncio.run(produce())

        assert len(attestations_received) == 0
        assert service.attestations_produced == 0


class TestValidatorServiceRun:
    """Tests for the main run loop."""

    def test_run_loop_can_be_stopped(
        self,
        sync_service: SyncService,
    ) -> None:
        """run() loop exits when stop() is called."""
        clock = SlotClock(genesis_time=Uint64(0))

        # Use empty registry to avoid attestation production
        registry = ValidatorRegistry()

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
        )

        call_count = 0

        async def stop_on_second_call(_duration: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                service.stop()

        async def run_briefly() -> None:
            with patch("asyncio.sleep", new=stop_on_second_call):
                await service.run()

        asyncio.run(run_briefly())
        assert not service.is_running


class TestIntervalSleep:
    """Tests for interval sleep calculation."""

    def test_sleep_until_next_interval_mid_interval(
        self,
        sync_service: SyncService,
    ) -> None:
        """Sleep duration is calculated correctly mid-interval."""
        genesis = Uint64(1000)
        current_time = 1000.5  # 0.5 seconds into first interval

        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: current_time)
        registry = ValidatorRegistry()

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
        )

        captured_duration: float | None = None

        async def capture_sleep(duration: float) -> None:
            nonlocal captured_duration
            captured_duration = duration

        async def check_sleep() -> None:
            with patch("asyncio.sleep", new=capture_sleep):
                await service._sleep_until_next_interval()

        asyncio.run(check_sleep())

        # Should sleep until next interval boundary (1001.0)
        expected = 1001.0 - current_time  # 0.5 seconds
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001

    def test_sleep_before_genesis(
        self,
        sync_service: SyncService,
    ) -> None:
        """Sleeps until genesis when current time is before genesis."""
        genesis = Uint64(1000)
        current_time = 900.0  # 100 seconds before genesis

        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: current_time)
        registry = ValidatorRegistry()

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
        )

        captured_duration: float | None = None

        async def capture_sleep(duration: float) -> None:
            nonlocal captured_duration
            captured_duration = duration

        async def check_sleep() -> None:
            with patch("asyncio.sleep", new=capture_sleep):
                await service._sleep_until_next_interval()

        asyncio.run(check_sleep())

        # Should sleep until genesis
        expected = float(genesis) - current_time  # 100 seconds
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001
