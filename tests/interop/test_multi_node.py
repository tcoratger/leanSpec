"""
Multi-node integration tests for leanSpec consensus.

This module tests the 3SF-mini protocol across multiple in-process nodes.
Each test verifies a different aspect of distributed consensus behavior.

Key concepts tested:

- Gossip propagation: blocks and attestations spread across the network
- Fork choice: nodes converge on the same chain head
- Finalization: 2/3+ validator agreement locks in checkpoints

Configuration for all tests:

- Slot duration: 4 seconds
- Validators per node: 1 (one validator per node)
- Supermajority threshold: 2/3 (2 of 3 validators must attest)

The tests use realistic timing to verify protocol behavior under
network latency and asynchronous message delivery.
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

# Mark all tests in this module as interop tests.
#
# This allows selective test runs via `pytest -m interop`.
pytestmark = pytest.mark.interop


# =============================================================================
# Full Mesh Finalization Test
# =============================================================================


@pytest.mark.timeout(60)
@pytest.mark.num_validators(3)
async def test_mesh_finalization(node_cluster: NodeCluster) -> None:
    """
    Verify chain finalization in a fully connected network.

    This is the primary finalization test for 3SF-mini consensus.
    It validates the complete consensus lifecycle:

    - Peer discovery and connection establishment
    - Block production and gossip propagation
    - Attestation aggregation across validators
    - Checkpoint justification (2/3+ votes)
    - Checkpoint finalization (justified child of justified parent)

    Network topology: Full mesh (every node connected to every other).
    This maximizes connectivity and minimizes propagation latency.

    Timing rationale:

    - 60s timeout: allows ~15 slots at 4s each, plenty for finalization
    - 30s run duration: ~7-8 slots, enough for 2 epochs of justification
    - 15s peer timeout: sufficient for TCP handshake + noise protocol

    The Ream project uses similar parameters for compatibility testing.
    """
    # Build the network topology.
    #
    # Full mesh with 3 nodes creates 3 bidirectional connections:
    # - Node 0 <-> Node 1
    # - Node 0 <-> Node 2
    # - Node 1 <-> Node 2
    topology = full_mesh(3)

    # Assign exactly one validator to each node.
    #
    # Validator indices match node indices for clarity.
    # With 3 validators total, each controls 1/3 of voting power.
    validators_per_node = [[0], [1], [2]]

    # Start all nodes with the configured topology.
    #
    # Each node begins:
    #
    # - Listening on a unique port
    # - Connecting to peers per topology
    # - Running the block production loop
    # - Subscribing to gossip topics
    await node_cluster.start_all(topology, validators_per_node)

    # Wait for peer connections before proceeding.
    #
    # Each node needs at least 2 peers (the other two nodes).
    # This ensures gossip will reach all nodes.
    # The 15s timeout handles slow handshakes.
    await assert_peer_connections(node_cluster, min_peers=2, timeout=15)

    # Let the chain run for a fixed duration.
    #
    # Timing calculation:
    #
    # - Slot duration: 4 seconds
    # - Slots in 30s: ~7-8 slots
    # - Finalization requires: 2 consecutive justified epochs
    # - With 3 validators: justification needs 2/3 = 2 attestations per slot
    #
    # This duration allows enough time for validators to:
    #
    # 1. Produce blocks (one per slot, round-robin)
    # 2. Broadcast attestations (all validators each slot)
    # 3. Accumulate justification (2+ matching attestations)
    # 4. Finalize (justified epoch becomes finalized)
    run_duration = 30
    poll_interval = 5

    logger.info("Running chain for %d seconds...", run_duration)

    # Poll the chain state periodically.
    #
    # This provides visibility into consensus progress during the test.
    # The logged metrics help debug failures.
    start = time.monotonic()
    while time.monotonic() - start < run_duration:
        # Collect current state from each node.
        #
        # Head slot: the highest slot block each node has seen.
        # Finalized slot: the most recent finalized checkpoint slot.
        # Justified slot: the most recent justified checkpoint slot.
        slots = [node.head_slot for node in node_cluster.nodes]
        finalized = [node.finalized_slot for node in node_cluster.nodes]
        justified = [node.justified_slot for node in node_cluster.nodes]

        # Track attestation counts for debugging.
        #
        # New attestations: received but not yet processed by fork choice.
        # Known attestations: already incorporated into the store.
        #
        # These counts reveal if gossip is working:
        #
        # - High new_atts, low known_atts = processing bottleneck
        # - Low counts everywhere = gossip not propagating
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

    # Capture final state for assertions.
    head_slots = [node.head_slot for node in node_cluster.nodes]
    finalized_slots = [node.finalized_slot for node in node_cluster.nodes]

    logger.info("FINAL: head_slots=%s finalized=%s", head_slots, finalized_slots)

    # Verify the chain advanced sufficiently.
    #
    # Minimum 5 slots ensures:
    #
    # - Block production is working (at least 5 blocks created)
    # - Gossip is propagating (all nodes see the same progress)
    # - No single node is stuck or partitioned
    assert all(slot >= 5 for slot in head_slots), (
        f"Chain did not advance enough. Head slots: {head_slots}"
    )

    # Verify heads are consistent across nodes.
    #
    # In a healthy network, all nodes should converge to similar head slots.
    # A difference > 2 slots indicates gossip or fork choice issues.
    head_diff = max(head_slots) - min(head_slots)
    assert head_diff <= 2, f"Head slots diverged too much. Slots: {head_slots}, diff: {head_diff}"

    # Verify ALL nodes finalized.
    #
    # With 30s runtime (~7-8 slots) and working gossip, every node
    # should have finalized at least one checkpoint.
    assert all(slot > 0 for slot in finalized_slots), (
        f"Not all nodes finalized. Finalized slots: {finalized_slots}"
    )

    # Verify finalized checkpoints are consistent.
    #
    # All nodes must agree on the finalized checkpoint.
    # Finalization is irreversible - divergent finalization would be catastrophic.
    assert len(set(finalized_slots)) == 1, (
        f"Finalized slots inconsistent across nodes: {finalized_slots}"
    )


# =============================================================================
# Hub-and-Spoke Topology Test
# =============================================================================


@pytest.mark.timeout(60)
@pytest.mark.num_validators(3)
async def test_mesh_2_2_2_finalization(node_cluster: NodeCluster) -> None:
    """
    Verify finalization with hub-and-spoke topology.

    This tests consensus under restricted connectivity:

    - Node 0 is the hub (receives all connections)
    - Nodes 1 and 2 are spokes (only connect to hub)
    - Spokes cannot communicate directly

    Topology diagram::

        Node 1 ---> Node 0 <--- Node 2

    This is harder than full mesh because:

    - Messages between spokes must route through the hub
    - Hub failure would partition the network
    - Gossip takes two hops instead of one

    The test verifies that even with indirect connectivity,
    the protocol achieves finalization. This matches the
    Ream project's `test_lean_node_finalizes_mesh_2_2_2` test.
    """
    # Build hub-and-spoke topology.
    #
    # Returns [(1, 0), (2, 0)]: nodes 1 and 2 dial node 0.
    # Node 0 acts as the central hub.
    topology = mesh_2_2_2()

    # Same validator assignment as full mesh test.
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)

    # Lower peer requirement than full mesh.
    #
    # Hub (node 0) has 2 peers; spokes have 1 peer each.
    # Using min_peers=1 ensures spokes pass the check.
    await assert_peer_connections(node_cluster, min_peers=1, timeout=15)

    # Same timing as full mesh test.
    #
    # Hub-and-spoke may be slightly slower due to extra gossip hops,
    # but 30s provides sufficient margin.
    run_duration = 30
    poll_interval = 5

    logger.info("Running chain for %d seconds (mesh_2_2_2)...", run_duration)

    # Poll chain progress.
    start = time.monotonic()
    while time.monotonic() - start < run_duration:
        slots = [node.head_slot for node in node_cluster.nodes]
        finalized = [node.finalized_slot for node in node_cluster.nodes]
        logger.info("Progress: head_slots=%s finalized=%s", slots, finalized)
        await asyncio.sleep(poll_interval)

    # Final state capture.
    head_slots = [node.head_slot for node in node_cluster.nodes]
    finalized_slots = [node.finalized_slot for node in node_cluster.nodes]

    logger.info("FINAL: head_slots=%s finalized=%s", head_slots, finalized_slots)

    # Same assertions as full mesh.
    #
    # Despite reduced connectivity (messages route through hub),
    # the protocol should still achieve full consensus.

    # Chain must advance sufficiently.
    assert all(slot >= 5 for slot in head_slots), (
        f"Chain did not advance enough. Head slots: {head_slots}"
    )

    # Heads must be consistent across nodes.
    #
    # Hub-and-spoke adds latency but should not cause divergence.
    head_diff = max(head_slots) - min(head_slots)
    assert head_diff <= 2, f"Head slots diverged too much. Slots: {head_slots}, diff: {head_diff}"

    # ALL nodes must finalize.
    assert all(slot > 0 for slot in finalized_slots), (
        f"Not all nodes finalized. Finalized slots: {finalized_slots}"
    )

    # Finalized checkpoints must be identical.
    #
    # Even with indirect connectivity, finalization must be consistent.
    assert len(set(finalized_slots)) == 1, (
        f"Finalized slots inconsistent across nodes: {finalized_slots}"
    )


# =============================================================================
# Basic Connection Test
# =============================================================================


@pytest.mark.timeout(30)
@pytest.mark.num_validators(2)
async def test_two_node_connection(node_cluster: NodeCluster) -> None:
    """
    Verify two nodes can connect and sync their views.

    This is the minimal multi-node test. It validates:

    - TCP connection establishment
    - Noise protocol handshake
    - Gossipsub topic subscription
    - Basic message exchange

    Not testing finalization here. With only 2 validators,
    both must agree for supermajority (100% required).
    This test focuses on connectivity, not consensus.

    Timing rationale:

    - 30s timeout: generous for simple connection test
    - 3s sleep: allows ~1 slot of chain activity
    - max_slot_diff=2: permits minor propagation delays
    """
    # Simplest possible topology: one connection.
    #
    # Node 0 dials node 1.
    topology = [(0, 1)]

    # One validator per node.
    validators_per_node = [[0], [1]]

    await node_cluster.start_all(topology, validators_per_node)

    # Each node should have exactly 1 peer.
    await assert_peer_connections(node_cluster, min_peers=1, timeout=15)

    # Brief pause for chain activity.
    #
    # At 4s slots, 3s is less than one full slot.
    # This tests that even partial slot activity syncs.
    await asyncio.sleep(3)

    # Verify nodes have consistent chain views.
    #
    # max_slot_diff=2 allows:
    #
    # - One node slightly ahead due to block production timing
    # - Minor propagation delays
    # - Clock skew between nodes
    #
    # Larger divergence would indicate gossip failure.
    await assert_heads_consistent(node_cluster, max_slot_diff=2)


# =============================================================================
# Block Gossip Propagation Test
# =============================================================================


@pytest.mark.timeout(45)
@pytest.mark.num_validators(3)
async def test_block_gossip_propagation(node_cluster: NodeCluster) -> None:
    """
    Verify blocks propagate to all nodes via gossip.

    This tests the gossipsub layer specifically:

    - Block producers broadcast to the beacon_block topic
    - Subscribers receive and validate blocks
    - Valid blocks are added to the local store

    Unlike finalization tests, this focuses on block propagation only.
    Attestations and checkpoints are not the primary concern here.
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)

    # Full connectivity required for reliable propagation.
    await assert_peer_connections(node_cluster, min_peers=2, timeout=15)

    # Wait for approximately 2 slots of chain activity.
    #
    # At 4s per slot, 8s allows:
    #
    # - Slot 0: genesis
    # - Slot 1: first block produced
    # - Slot 2: second block produced (possibly)
    #
    # This gives gossip time to deliver blocks to all nodes.
    await asyncio.sleep(8)

    head_slots = [node.head_slot for node in node_cluster.nodes]
    logger.info("Head slots after 10s: %s", head_slots)

    # Verify all nodes have progressed beyond genesis.
    #
    # slot > 0 means at least one block was received.
    assert all(slot > 0 for slot in head_slots), f"Expected progress, got slots: {head_slots}"

    # Check block overlap across node stores.
    #
    # Access the live store via _store (not the snapshot).
    # The store.blocks dictionary maps block roots to block objects.
    node0_blocks = set(node_cluster.nodes[0]._store.blocks.keys())
    node1_blocks = set(node_cluster.nodes[1]._store.blocks.keys())
    node2_blocks = set(node_cluster.nodes[2]._store.blocks.keys())

    # Compute blocks present on all nodes.
    #
    # The intersection contains blocks that successfully propagated.
    # This includes at least the genesis block (always shared).
    common_blocks = node0_blocks & node1_blocks & node2_blocks

    # More than 1 common block proves gossip works.
    #
    # - 1 block = only genesis (trivially shared)
    # - 2+ blocks = produced blocks propagated via gossip
    assert len(common_blocks) > 1, (
        f"Expected shared blocks, got intersection size {len(common_blocks)}"
    )


# =============================================================================
# Network Partition Recovery Test (Future Work)
# =============================================================================


@pytest.mark.timeout(300)
@pytest.mark.skip(reason="Partition recovery requires disconnect support - future work")
@pytest.mark.num_validators(3)
async def test_partition_recovery(node_cluster: NodeCluster) -> None:
    """
    Verify chain recovery after network partition heals.

    This test would validate Byzantine fault tolerance:

    - Network splits into partitions
    - Partitions make independent progress
    - Partitions reconnect
    - Chain converges to a single consistent view

    Currently skipped because the test infrastructure does not yet
    support programmatic peer disconnection. The test framework
    needs enhancements to:

    - Disconnect specific peers
    - Reconnect after delay
    - Track partition membership

    When implemented, this test will use:

    - 5 minute timeout (300s) for partition and recovery
    - 15s initial run for pre-partition baseline
    - Variable partition duration
    - Post-recovery consistency checks
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)
    await assert_peer_connections(node_cluster, min_peers=2, timeout=30)

    # Pre-partition baseline.
    await asyncio.sleep(15)

    # Consistency check before partition.
    await assert_heads_consistent(node_cluster, max_slot_diff=2)

    # TODO: Implement partition simulation.
    # - Disconnect node 2 from nodes 0 and 1
    # - Let partitions run independently
    # - Reconnect and verify convergence
