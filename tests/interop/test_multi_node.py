"""
Multi-node integration tests for leanSpec consensus.

Tests verify chain finalization and gossip communication
across multiple in-process nodes.
"""

from __future__ import annotations

import asyncio
import logging
import time

import pytest

from .helpers import (
    NodeCluster,
    assert_heads_consistent,
    assert_peer_connections,
    full_mesh,
    mesh_2_2_2,
)

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.interop


@pytest.mark.timeout(120)
@pytest.mark.num_validators(3)
async def test_mesh_finalization(node_cluster: NodeCluster) -> None:
    """
    Three nodes in full mesh should finalize the chain.

    This is the basic multi-node test verifying that:

    - Nodes connect to each other
    - Blocks propagate via gossip
    - Attestations accumulate
    - Chain finalizes with 2/3+ agreement

    Approach (inspired by Ream):
    - Start nodes with mesh topology
    - Let the chain run for a fixed duration
    - Verify ANY finalization occurred (finalized_slot > 0)
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)

    # Wait for peer connections (quick check).
    await assert_peer_connections(node_cluster, min_peers=2, timeout=30)

    # Let the chain run for a fixed duration.
    # Ream uses 70s; increase to 80s to ensure enough slots for finalization.
    run_duration = 80
    poll_interval = 5

    logger.info("Running chain for %d seconds...", run_duration)

    start = time.monotonic()
    while time.monotonic() - start < run_duration:
        # Log detailed progress every poll_interval seconds.
        slots = [node.head_slot for node in node_cluster.nodes]
        finalized = [node.finalized_slot for node in node_cluster.nodes]
        justified = [node.justified_slot for node in node_cluster.nodes]

        # Log attestation counts from each node's store.
        new_atts = [len(node._store.latest_new_attestations) for node in node_cluster.nodes]
        known_atts = [len(node._store.latest_known_attestations) for node in node_cluster.nodes]

        logger.info(
            "Progress: head=%s justified=%s finalized=%s new_atts=%s known_atts=%s",
            slots,
            justified,
            finalized,
            new_atts,
            known_atts,
        )
        await asyncio.sleep(poll_interval)

    # Final state check.
    head_slots = [node.head_slot for node in node_cluster.nodes]
    finalized_slots = [node.finalized_slot for node in node_cluster.nodes]

    logger.info("FINAL: head_slots=%s finalized=%s", head_slots, finalized_slots)

    # Check chain advanced (at least 5 slots like Ream's finalization_lag).
    assert all(slot >= 5 for slot in head_slots), (
        f"Chain did not advance enough. Head slots: {head_slots}"
    )

    # Check ANY finalization occurred (Ream's approach).
    assert any(slot > 0 for slot in finalized_slots), (
        f"NO FINALIZATION. Finalized slots: {finalized_slots}"
    )


@pytest.mark.timeout(120)
@pytest.mark.num_validators(3)
async def test_mesh_2_2_2_finalization(node_cluster: NodeCluster) -> None:
    """
    Ream-compatible mesh topology finalizes chain.

    Nodes 1 and 2 connect to node 0 (hub-and-spoke pattern).
    This topology matches Ream's test_lean_node_finalizes_mesh_2_2_2.
    """
    topology = mesh_2_2_2()
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)

    # Wait for peer connections.
    await assert_peer_connections(node_cluster, min_peers=1, timeout=30)

    # Let the chain run for a fixed duration.
    run_duration = 60
    poll_interval = 5

    logger.info("Running chain for %d seconds (mesh_2_2_2)...", run_duration)

    start = time.monotonic()
    while time.monotonic() - start < run_duration:
        slots = [node.head_slot for node in node_cluster.nodes]
        finalized = [node.finalized_slot for node in node_cluster.nodes]
        logger.info("Progress: head_slots=%s finalized=%s", slots, finalized)
        await asyncio.sleep(poll_interval)

    # Final state check.
    head_slots = [node.head_slot for node in node_cluster.nodes]
    finalized_slots = [node.finalized_slot for node in node_cluster.nodes]

    logger.info("FINAL: head_slots=%s finalized=%s", head_slots, finalized_slots)

    # Check chain advanced.
    assert all(slot >= 5 for slot in head_slots), (
        f"Chain did not advance enough. Head slots: {head_slots}"
    )

    # Check ANY finalization occurred.
    assert any(slot > 0 for slot in finalized_slots), (
        f"NO FINALIZATION. Finalized slots: {finalized_slots}"
    )


@pytest.mark.timeout(60)
@pytest.mark.num_validators(2)
async def test_two_node_connection(node_cluster: NodeCluster) -> None:
    """
    Basic test: two nodes connect and exchange messages.

    Minimal test to verify the connection stack works.
    """
    topology = [(0, 1)]
    validators_per_node = [[0], [1]]

    await node_cluster.start_all(topology, validators_per_node)

    await assert_peer_connections(node_cluster, min_peers=1, timeout=30)

    await asyncio.sleep(5)

    await assert_heads_consistent(node_cluster, max_slot_diff=2)


@pytest.mark.timeout(90)
@pytest.mark.num_validators(3)
async def test_block_gossip_propagation(node_cluster: NodeCluster) -> None:
    """
    Verify blocks propagate to all nodes via gossip.

    One node produces a block, all nodes should receive it.
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)

    await assert_peer_connections(node_cluster, min_peers=2, timeout=30)

    await asyncio.sleep(10)

    head_slots = [node.head_slot for node in node_cluster.nodes]
    logger.info("Head slots after 10s: %s", head_slots)

    assert all(slot > 0 for slot in head_slots), f"Expected progress, got slots: {head_slots}"

    # Use _store to get the live store from sync_service, not the stale node.store snapshot.
    node0_blocks = set(node_cluster.nodes[0]._store.blocks.keys())
    node1_blocks = set(node_cluster.nodes[1]._store.blocks.keys())
    node2_blocks = set(node_cluster.nodes[2]._store.blocks.keys())

    common_blocks = node0_blocks & node1_blocks & node2_blocks
    assert len(common_blocks) > 1, (
        f"Expected shared blocks, got intersection size {len(common_blocks)}"
    )


@pytest.mark.timeout(300)
@pytest.mark.skip(reason="Partition recovery requires disconnect support - future work")
@pytest.mark.num_validators(3)
async def test_partition_recovery(node_cluster: NodeCluster) -> None:
    """
    Network partition recovery: nodes reconnect and resync.

    This test simulates a network partition by disconnecting node 2,
    then reconnecting to verify the chain recovers.
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)
    await assert_peer_connections(node_cluster, min_peers=2, timeout=30)

    await asyncio.sleep(15)

    await assert_heads_consistent(node_cluster, max_slot_diff=2)
