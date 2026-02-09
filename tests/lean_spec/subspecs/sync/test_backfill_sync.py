"""Tests for backfill synchronization module."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.peer.info import PeerInfo
from lean_spec.subspecs.networking.types import ConnectionState
from lean_spec.subspecs.sync.backfill_sync import BackfillSync
from lean_spec.subspecs.sync.block_cache import BlockCache
from lean_spec.subspecs.sync.config import MAX_BACKFILL_DEPTH, MAX_BLOCKS_PER_REQUEST
from lean_spec.subspecs.sync.peer_manager import PeerManager
from lean_spec.types import Bytes32
from tests.lean_spec.helpers import MockNetworkRequester, make_signed_block


@pytest.fixture
def network() -> MockNetworkRequester:
    """Provide mock network."""
    return MockNetworkRequester()


@pytest.fixture
def backfill_system(peer_id: PeerId, network: MockNetworkRequester) -> BackfillSync:
    """Provide a complete BackfillSync with connected peer."""
    manager = PeerManager()
    manager.add_peer(PeerInfo(peer_id=peer_id, state=ConnectionState.CONNECTED))
    return BackfillSync(
        peer_manager=manager,
        block_cache=BlockCache(),
        network=network,
    )


class TestBackfillChainResolution:
    """Tests for resolving chains of missing parents."""

    async def test_fetch_single_missing_block(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
        peer_id: PeerId,
    ) -> None:
        """Fetching a single missing block adds it to cache."""
        block = make_signed_block(
            slot=Slot(10),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        block_root = network.add_block(block)

        await backfill_system.fill_missing([block_root])

        assert block_root in backfill_system.block_cache
        cached = backfill_system.block_cache.get(block_root)
        assert cached is not None
        assert cached.slot == Slot(10)

    async def test_recursive_parent_chain_resolution(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
        peer_id: PeerId,
    ) -> None:
        """Backfill recursively fetches missing parents up the chain."""
        grandparent = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"\x01" * 32),
        )
        grandparent_root = network.add_block(grandparent)

        parent = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(0),
            parent_root=grandparent_root,
            state_root=Bytes32(b"\x02" * 32),
        )
        parent_root = network.add_block(parent)

        child = make_signed_block(
            slot=Slot(3),
            proposer_index=ValidatorIndex(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x03" * 32),
        )
        child_root = network.add_block(child)

        await backfill_system.fill_missing([child_root])

        assert child_root in backfill_system.block_cache
        assert parent_root in backfill_system.block_cache
        assert grandparent_root in backfill_system.block_cache

        child_cached = backfill_system.block_cache.get(child_root)
        parent_cached = backfill_system.block_cache.get(parent_root)
        grandparent_cached = backfill_system.block_cache.get(grandparent_root)

        assert child_cached is not None
        assert parent_cached is not None
        assert grandparent_cached is not None
        assert child_cached.backfill_depth == 1
        assert parent_cached.backfill_depth == 2
        assert grandparent_cached.backfill_depth == 3

    async def test_depth_limit_stops_infinite_recursion(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
    ) -> None:
        """Backfill stops at MAX_BACKFILL_DEPTH to prevent infinite recursion."""
        root = Bytes32(b"\x01" * 32)

        await backfill_system.fill_missing([root], depth=MAX_BACKFILL_DEPTH)

        assert len(network.request_log) == 0
        assert root not in backfill_system.block_cache

    async def test_skips_already_cached_blocks(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
        peer_id: PeerId,
    ) -> None:
        """Blocks already in cache are not re-requested."""
        block = make_signed_block(
            slot=Slot(5),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        block_root = network.add_block(block)

        backfill_system.block_cache.add(block, peer_id)

        await backfill_system.fill_missing([block_root])

        assert len(network.request_log) == 0


class TestBatchingAndPeerManagement:
    """Tests for request batching and peer interaction."""

    async def test_large_request_split_into_batches(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
    ) -> None:
        """Requests larger than MAX_BLOCKS_PER_REQUEST are split."""
        num_roots = MAX_BLOCKS_PER_REQUEST + 5
        roots = [Bytes32(i.to_bytes(32, "big")) for i in range(num_roots)]

        await backfill_system.fill_missing(roots)

        assert len(network.request_log) == 2
        assert len(network.request_log[0][1]) == MAX_BLOCKS_PER_REQUEST
        assert len(network.request_log[1][1]) == 5

    async def test_no_requests_without_available_peer(
        self,
        network: MockNetworkRequester,
    ) -> None:
        """No requests made when no peers are available."""
        manager = PeerManager()
        backfill = BackfillSync(
            peer_manager=manager,
            block_cache=BlockCache(),
            network=network,
        )

        await backfill.fill_missing([Bytes32(b"\x01" * 32)])

        assert len(network.request_log) == 0

    async def test_network_failure_handled_gracefully(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
    ) -> None:
        """Network failures don't crash and pending state is cleaned up."""
        network.should_fail = True
        root = Bytes32(b"\x01" * 32)

        await backfill_system.fill_missing([root])

        assert root not in backfill_system._pending


class TestOrphanHandling:
    """Tests for orphan block management during backfill."""

    async def test_fill_all_orphans_fetches_missing_parents(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
        peer_id: PeerId,
    ) -> None:
        """fill_all_orphans fetches parents for all orphan blocks in cache."""
        parent = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        parent_root = network.add_block(parent)

        child = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x01" * 32),
        )
        child_pending = backfill_system.block_cache.add(child, peer_id)
        backfill_system.block_cache.mark_orphan(child_pending.root)

        assert backfill_system.block_cache.orphan_count == 1

        await backfill_system.fill_all_orphans()

        assert parent_root in backfill_system.block_cache

    async def test_shared_parent_deduplicated(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
        peer_id: PeerId,
    ) -> None:
        """Multiple orphans with same parent only trigger one request for that parent."""
        parent = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        parent_root = network.add_block(parent)

        child1 = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x01" * 32),
        )
        child2 = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(1),
            parent_root=parent_root,
            state_root=Bytes32(b"\x02" * 32),
        )

        pending1 = backfill_system.block_cache.add(child1, peer_id)
        pending2 = backfill_system.block_cache.add(child2, peer_id)
        backfill_system.block_cache.mark_orphan(pending1.root)
        backfill_system.block_cache.mark_orphan(pending2.root)

        await backfill_system.fill_all_orphans()

        all_requested_roots = [root for _, roots in network.request_log for root in roots]
        assert all_requested_roots.count(parent_root) == 1

        assert parent_root in network.request_log[0][1]

        assert parent_root in backfill_system.block_cache
