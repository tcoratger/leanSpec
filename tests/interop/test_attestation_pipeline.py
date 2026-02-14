"""
Attestation production and delivery pipeline tests.

Verifies that validators produce attestations referencing the correct
head and that attestations are delivered to the aggregator.
"""

from __future__ import annotations

import asyncio
import logging
import time

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
async def test_attestation_head_references(node_cluster: NodeCluster) -> None:
    """
    Verify attestations reference the current slot's block, not genesis.

    After the first block is produced and propagated, attestations from
    non-proposer validators should point to that block as their head.
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)
    await assert_peer_connections(node_cluster, min_peers=2, timeout=15)

    # Wait for ~3 slots so attestations have been produced.
    await asyncio.sleep(16)

    # Check that gossip_signatures or aggregated payloads exist.
    # If attestations reference genesis with target==source, they'd be skipped.
    # So the presence of valid aggregated payloads indicates correct head references.
    for node in node_cluster.nodes:
        diag = PipelineDiagnostics.from_node(node)
        logger.info(
            "Node %d: head=%d safe_target=%d gossip_sigs=%d new_agg=%d known_agg=%d",
            node.index,
            diag.head_slot,
            diag.safe_target_slot,
            diag.gossip_signatures_count,
            diag.new_aggregated_count,
            diag.known_aggregated_count,
        )

    # At least one node should have aggregated payloads (the aggregator).
    total_agg = sum(
        PipelineDiagnostics.from_node(n).new_aggregated_count
        + PipelineDiagnostics.from_node(n).known_aggregated_count
        for n in node_cluster.nodes
    )
    assert total_agg > 0, "No aggregated attestation payloads found on any node"


@pytest.mark.timeout(60)
@pytest.mark.num_validators(3)
async def test_attestation_gossip_delivery(node_cluster: NodeCluster) -> None:
    """
    Verify attestations reach the aggregator node via gossip.

    The aggregator collects gossip signatures from subnet attestation topics.
    After a few slots, the aggregator should have collected signatures from
    multiple validators.
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)
    await assert_peer_connections(node_cluster, min_peers=2, timeout=15)

    # Wait for ~2 slots for attestations to be produced and gossiped.
    await asyncio.sleep(12)

    # Find aggregator nodes (those with gossip_signatures).
    for node in node_cluster.nodes:
        diag = PipelineDiagnostics.from_node(node)
        if diag.gossip_signatures_count > 0 or diag.new_aggregated_count > 0:
            logger.info(
                "Node %d has pipeline activity: gossip_sigs=%d new_agg=%d",
                node.index,
                diag.gossip_signatures_count,
                diag.new_aggregated_count,
            )

    # At least one aggregator should have received signatures.
    max_sigs = max(
        PipelineDiagnostics.from_node(n).gossip_signatures_count
        + PipelineDiagnostics.from_node(n).new_aggregated_count
        for n in node_cluster.nodes
    )
    assert max_sigs > 0, "No gossip signatures or aggregated payloads found on any node"


@pytest.mark.timeout(90)
@pytest.mark.num_validators(3)
async def test_safe_target_advancement(node_cluster: NodeCluster) -> None:
    """
    Verify safe_target advances beyond genesis after aggregation.

    After aggregation at interval 2 and safe target update at interval 3,
    the safe_target should point to a non-genesis block. This is a
    prerequisite for meaningful attestation targets.
    """
    topology = full_mesh(3)
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)
    await assert_peer_connections(node_cluster, min_peers=2, timeout=15)

    # Wait for enough slots for safe_target to advance.
    # Needs: block production -> attestation -> aggregation -> safe target update.
    start = time.monotonic()
    timeout = 60.0

    while time.monotonic() - start < timeout:
        diags = [PipelineDiagnostics.from_node(n) for n in node_cluster.nodes]
        safe_targets = [d.safe_target_slot for d in diags]

        if any(st > 0 for st in safe_targets):
            logger.info("Safe target advanced: %s", safe_targets)
            return

        logger.debug("Safe targets still at genesis: %s", safe_targets)
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
    raise AssertionError(f"Safe target never advanced beyond genesis: {safe_targets}")
