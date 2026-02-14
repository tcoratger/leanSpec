"""
Block production and propagation pipeline tests.

Verifies that blocks are produced, propagated via gossip,
and integrated into all nodes' stores.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from .helpers import (
    NodeCluster,
    PipelineDiagnostics,
    assert_peer_connections,
    full_mesh,
)

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.interop


@pytest.mark.timeout(60)
@pytest.mark.num_validators(3)
async def test_block_production_single_slot(node_cluster: NodeCluster) -> None:
    """
    Verify that a block is produced and reaches all nodes within one slot.

    After mesh stabilization and service start, the proposer for slot 1
    should produce a block that propagates to all 3 nodes.
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)
    await assert_peer_connections(node_cluster, min_peers=2, timeout=15)

    # Wait for one slot (4s) plus propagation margin.
    await asyncio.sleep(8)

    for node in node_cluster.nodes:
        diag = PipelineDiagnostics.from_node(node)
        logger.info("Node %d: head_slot=%d blocks=%d", node.index, diag.head_slot, diag.block_count)
        assert diag.head_slot >= 1, (
            f"Node {node.index} stuck at slot {diag.head_slot}, expected >= 1"
        )


@pytest.mark.timeout(60)
@pytest.mark.num_validators(3)
async def test_consecutive_blocks(node_cluster: NodeCluster) -> None:
    """
    Verify blocks at consecutive slots reference correct parents.

    After several slots, each non-genesis block should have a parent_root
    that points to the previous slot's block.
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)
    await assert_peer_connections(node_cluster, min_peers=2, timeout=15)

    # Wait for ~3 slots.
    await asyncio.sleep(16)

    # Check parent chain on node 0.
    store = node_cluster.nodes[0]._store
    head_block = store.blocks[store.head]

    # Walk back from head to genesis, verifying parent chain.
    visited = 0
    current = head_block
    while current.parent_root in store.blocks:
        parent = store.blocks[current.parent_root]
        assert current.slot > parent.slot, (
            f"Block at slot {current.slot} has parent at slot {parent.slot} (not decreasing)"
        )
        current = parent
        visited += 1

    logger.info("Walked %d blocks in parent chain from head slot %d", visited, head_block.slot)
    assert visited >= 2, f"Expected at least 2 blocks in chain, found {visited}"
