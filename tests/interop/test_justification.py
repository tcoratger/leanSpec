"""
Justification and finalization pipeline tests.

Verifies the full consensus lifecycle from block production through
checkpoint justification and finalization.
"""

from __future__ import annotations

import asyncio
import logging
import time

import pytest

from .helpers import (
    NodeCluster,
    PipelineDiagnostics,
    assert_all_finalized_to,
    assert_heads_consistent,
    assert_peer_connections,
    assert_same_finalized_checkpoint,
    full_mesh,
    mesh_2_2_2,
)

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.interop


@pytest.mark.timeout(120)
@pytest.mark.num_validators(3)
async def test_first_justification(node_cluster: NodeCluster) -> None:
    """
    Verify that the first justification event occurs.

    Justification requires 2/3+ attestation weight on a target checkpoint.
    With 3 validators, 2 must attest to the same target. This test waits
    for the justified_slot to advance beyond genesis on any node.
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)
    await assert_peer_connections(node_cluster, min_peers=2, timeout=15)

    start = time.monotonic()
    timeout = 90.0

    while time.monotonic() - start < timeout:
        justified_slots = [n.justified_slot for n in node_cluster.nodes]

        if any(js > 0 for js in justified_slots):
            logger.info("First justification achieved: %s", justified_slots)
            return

        # Log pipeline state periodically for diagnostics.
        if int(time.monotonic() - start) % 10 == 0:
            for node in node_cluster.nodes:
                diag = PipelineDiagnostics.from_node(node)
                logger.info(
                    "Node %d: head=%d safe=%d just=%d fin=%d",
                    node.index,
                    diag.head_slot,
                    diag.safe_target_slot,
                    diag.justified_slot,
                    diag.finalized_slot,
                )

        await asyncio.sleep(2.0)

    diags = [PipelineDiagnostics.from_node(n) for n in node_cluster.nodes]
    for i, d in enumerate(diags):
        logger.error(
            "Node %d: head=%d safe=%d fin=%d just=%d gsigs=%d nagg=%d kagg=%d",
            i,
            d.head_slot,
            d.safe_target_slot,
            d.finalized_slot,
            d.justified_slot,
            d.gossip_signatures_count,
            d.new_aggregated_count,
            d.known_aggregated_count,
        )
    raise AssertionError(f"No justification after {timeout}s: {[d.justified_slot for d in diags]}")


@pytest.mark.timeout(150)
@pytest.mark.num_validators(3)
async def test_finalization_full_mesh(node_cluster: NodeCluster) -> None:
    """
    Verify chain finalization in a fully connected network.

    Tests the complete consensus lifecycle:

    - Block production and gossip propagation
    - Attestation aggregation across validators
    - Checkpoint justification (2/3+ votes)
    - Checkpoint finalization (justified child of justified parent)

    Network topology: Full mesh (every node connected to every other).
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)
    await assert_peer_connections(node_cluster, min_peers=2, timeout=15)
    await assert_heads_consistent(node_cluster, max_slot_diff=2, timeout=30)

    await assert_all_finalized_to(node_cluster, target_slot=1, timeout=90)
    await assert_heads_consistent(node_cluster, max_slot_diff=2, timeout=15)
    await assert_same_finalized_checkpoint(node_cluster.nodes, timeout=15)


@pytest.mark.timeout(150)
@pytest.mark.num_validators(3)
async def test_finalization_hub_spoke(node_cluster: NodeCluster) -> None:
    """
    Verify finalization with hub-and-spoke topology.

    Node 0 is the hub; nodes 1 and 2 are spokes that only connect to the hub.
    Messages between spokes must route through the hub.
    """
    topology = mesh_2_2_2()
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)
    await assert_peer_connections(node_cluster, min_peers=1, timeout=15)
    await assert_heads_consistent(node_cluster, max_slot_diff=2, timeout=30)

    await assert_all_finalized_to(node_cluster, target_slot=1, timeout=90)
    await assert_heads_consistent(node_cluster, max_slot_diff=2, timeout=15)
    await assert_same_finalized_checkpoint(node_cluster.nodes, timeout=15)
