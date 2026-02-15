"""End-to-end consensus lifecycle test."""

from __future__ import annotations

import asyncio
import logging
import time

import pytest

from .helpers import (
    NodeCluster,
    PipelineDiagnostics,
    assert_all_finalized_to,
    assert_checkpoint_monotonicity,
    assert_head_descends_from,
    assert_heads_consistent,
    assert_peer_connections,
    assert_same_finalized_checkpoint,
    full_mesh,
)

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.interop

NUM_VALIDATORS = 3
"""Number of validators in the test cluster.

Three is the smallest committee where 2/3 supermajority is meaningful.
Two out of three validators must agree to justify a checkpoint.
With all three attesting, justification occurs after one epoch.

Round-robin proposer assignment cycles through all validators:

- slot 1 -> validator 1  (1 % 3)
- slot 2 -> validator 2  (2 % 3)
- slot 3 -> validator 0  (3 % 3)
"""


MIN_ATTESTATION_ACTIVITY = 3
"""
Minimum attestation pipeline activity across all nodes after one slot.

Each validator produces one attestation per slot.
After 4 seconds (one slot), all 3 must have entered the pipeline.
Activity counts gossip signatures, new aggregated, and known aggregated.
"""


@pytest.mark.timeout(240)
@pytest.mark.num_validators(3)
async def test_consensus_lifecycle(node_cluster: NodeCluster) -> None:
    """
    Validate the full consensus lifecycle in a 3-node cluster.

    Each phase depends on the previous one succeeding.
    Failure at any phase logs pipeline diagnostics for debugging.
    The 240-second timeout covers all seven phases end-to-end.

    Checkpoint snapshots from every phase feed into a final
    monotonicity check. Justified and finalized slots must never
    decrease across phases on any node.
    """
    # Every node connects to every other node.
    # With 3 nodes this creates 3 bidirectional links: 0-1, 0-2, 1-2.
    topology = full_mesh(NUM_VALIDATORS)

    # One validator per node. Isolating validators ensures each node
    # proposes independently and attestations travel over the network.
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)

    # Collect diagnostic snapshots after each phase.
    # Used at the end to verify checkpoint monotonicity across phases.
    checkpoint_history: list[list[PipelineDiagnostics]] = []

    # Phase 1: Connectivity
    #
    # In a full mesh of 3 nodes, each node has exactly 2 peers.
    # QUIC connections establish in under a second, so 5s is generous.
    # This phase gates all subsequent phases that rely on gossip.
    logger.info("Phase 1: Connectivity")
    await assert_peer_connections(node_cluster, min_peers=2, timeout=5)
    diags = node_cluster.log_diagnostics("connectivity")
    checkpoint_history.append(diags)

    # Phase 2: Block production
    #
    # Wait for all nodes to advance past genesis.
    # Once slot 1 is reached, verify three properties:
    #
    # 1. Gossip completeness - blocks propagate to all peers
    # 2. Parent chain integrity - slot numbers strictly increase
    # 3. Proposer assignment - round-robin matches slot % 3
    logger.info("Phase 2: Block production")
    reached = await node_cluster.wait_for_slot(target_slot=1, timeout=25)
    diags = node_cluster.log_diagnostics("block-production")
    checkpoint_history.append(diags)
    assert reached, f"Block production stalled: head slots {[d.head_slot for d in diags]}"

    # Gossip completeness: every block should reach every node.
    #
    # Tolerate at most 1 missing block per node.
    # A block produced at the boundary of the check window
    # may still be propagating through the mesh.
    block_sets = [set(node._store.blocks.keys()) for node in node_cluster.nodes]
    all_blocks = block_sets[0] | block_sets[1] | block_sets[2]
    for i, bs in enumerate(block_sets):
        missing = all_blocks - bs
        assert len(missing) <= 1, (
            f"Node {i} missing {len(missing)} blocks: has {len(bs)}/{len(all_blocks)}"
        )

    # Parent chain integrity: walk backward from head to genesis.
    #
    # Each block must reference a parent with a strictly lower slot.
    # A violation here indicates a fork or misordered import.
    for node in node_cluster.nodes:
        store = node._store
        head_block = store.blocks[store.head]
        visited = 0
        current = head_block
        while current.parent_root in store.blocks:
            parent = store.blocks[current.parent_root]
            assert current.slot > parent.slot, (
                f"Node {node.index}: block at slot {current.slot} has parent at slot {parent.slot}"
            )
            current = parent
            visited += 1

        logger.info(
            "Node %d parent chain: %d blocks from head slot %d",
            node.index,
            visited,
            int(head_block.slot),
        )

    # Proposer assignment: round-robin rotation.
    #
    # For every non-genesis block, proposer_index must equal slot % 3.
    # This confirms the validator schedule is correctly applied.
    store = node_cluster.nodes[0]._store
    for _root, block in store.blocks.items():
        if int(block.slot) == 0:
            continue
        expected_proposer = int(block.slot) % NUM_VALIDATORS
        assert int(block.proposer_index) == expected_proposer, (
            f"Block at slot {block.slot} has proposer "
            f"{block.proposer_index}, expected {expected_proposer}"
        )

    # Phase 3: Attestation pipeline
    #
    # Validators produce attestations once per slot (every 4 seconds).
    # After sleeping one full slot, the pipeline should contain entries
    # from all three validators: gossip signatures, new aggregated
    # payloads, or already-known aggregated payloads.
    logger.info("Phase 3: Attestation pipeline")
    await asyncio.sleep(4)
    diags = node_cluster.log_diagnostics("attestation")
    checkpoint_history.append(diags)

    # Cluster-wide check: total activity must reach the threshold.
    # Three validators each produce one attestation, so the sum of
    # all pipeline stages across all nodes must be at least 3.
    total_activity = sum(
        d.gossip_signatures_count + d.new_aggregated_count + d.known_aggregated_count for d in diags
    )
    assert total_activity >= MIN_ATTESTATION_ACTIVITY, (
        f"Expected >= {MIN_ATTESTATION_ACTIVITY} attestation pipeline "
        f"entries across all nodes, got {total_activity}"
    )

    # Per-node check: every node must have seen at least one entry.
    # A node with zero activity indicates a gossip or subscription failure.
    for i, d in enumerate(diags):
        node_activity = (
            d.gossip_signatures_count + d.new_aggregated_count + d.known_aggregated_count
        )
        assert node_activity >= 1, (
            f"Node {i}: zero attestation pipeline activity "
            f"(gsigs={d.gossip_signatures_count}, "
            f"nagg={d.new_aggregated_count}, "
            f"kagg={d.known_aggregated_count})"
        )

    # Phase 4: Safe target advancement
    #
    # A block becomes "safe" when it accumulates enough attestations.
    # The safe target is the highest block considered safe by the node.
    # With 100% participation (3/3 validators), the safe target
    # should advance past genesis within a few slots.
    logger.info("Phase 4: Safe target")
    start = time.monotonic()
    timeout = 30.0
    safe_targets: list[int] = []

    # Poll every 2 seconds until all nodes report safe_target >= 1.
    while time.monotonic() - start < timeout:
        safe_targets = [n.diagnostics().safe_target_slot for n in node_cluster.nodes]
        if all(st >= 1 for st in safe_targets):
            break
        await asyncio.sleep(2.0)

    diags = node_cluster.log_diagnostics("safe-target")
    checkpoint_history.append(diags)

    # Re-read after diagnostics to avoid stale-snapshot race.
    # The 2-second poll sleep lets gossip update the store between
    # the last snapshot and the assertion.
    safe_targets = [n.diagnostics().safe_target_slot for n in node_cluster.nodes]

    # Per-node assertion to identify which node stalled.
    for i, st in enumerate(safe_targets):
        assert st >= 1, f"Node {i}: safe_target_slot={st}, expected >= 1"

    # Phase 5: Justification
    #
    # A checkpoint is justified when it receives 2/3+ vote weight.
    # With all 3 validators attesting (100% > 66% threshold),
    # justified_slot should advance past genesis within one epoch.
    logger.info("Phase 5: Justification")
    start = time.monotonic()
    timeout = 30.0
    justified_slots: list[int] = []

    # Poll every 2 seconds until all nodes justify past genesis.
    while time.monotonic() - start < timeout:
        justified_slots = [n.justified_slot for n in node_cluster.nodes]
        if all(js >= 1 for js in justified_slots):
            break
        await asyncio.sleep(2.0)

    diags = node_cluster.log_diagnostics("justification")
    checkpoint_history.append(diags)

    # Re-read after diagnostics to avoid stale-snapshot race.
    justified_slots = [n.justified_slot for n in node_cluster.nodes]

    # Per-node assertion to identify which node failed to justify.
    for i, js in enumerate(justified_slots):
        assert js >= 1, f"Node {i}: justified_slot={js}, expected >= 1"

    # Phase 6: Finalization
    #
    # Finalization occurs when a justified checkpoint is followed by
    # another justified checkpoint. Once finalized, a block is permanent.
    # This phase verifies finalization itself and four safety invariants:
    #
    # 1. Head consistency across nodes
    # 2. Checkpoint agreement (same finalized root)
    # 3. Justified >= finalized (monotonicity invariant)
    # 4. Fork choice ancestry (head descends from checkpoints)
    logger.info("Phase 6: Finalization")
    await assert_all_finalized_to(node_cluster, target_slot=1, timeout=60)
    diags = node_cluster.log_diagnostics("finalization")
    checkpoint_history.append(diags)

    # Head consistency: all nodes must be within 2 slots of each other.
    # Larger drift would indicate a partition or stalled gossip.
    await assert_heads_consistent(node_cluster, max_slot_diff=2, timeout=15)

    # Checkpoint agreement: all nodes must share the same finalized root.
    # Disagreement here would be a consensus-breaking bug.
    await assert_same_finalized_checkpoint(node_cluster, timeout=15)

    # Per-node finalization check to identify which node lagged.
    for node in node_cluster.nodes:
        assert node.finalized_slot >= 1, (
            f"Node {node.index}: finalized_slot={node.finalized_slot}, expected >= 1"
        )

    # Consensus invariant: justified slot must never fall behind finalized.
    # Finalization is derived from justification, so this must hold.
    for node in node_cluster.nodes:
        s = node._store
        j_slot = int(s.latest_justified.slot)
        f_slot = int(s.latest_finalized.slot)
        assert j_slot >= f_slot, (
            f"Node {node.index}: justified_slot={j_slot} < finalized_slot={f_slot}"
        )

    # Fork choice ancestry: the head must descend from both checkpoints.
    # The fork choice algorithm walks forward from the checkpoint root.
    # If the head is not a descendant, the algorithm is broken.
    assert_head_descends_from(node_cluster, "finalized")
    assert_head_descends_from(node_cluster, "justified")

    # Finalized chain consistency: compare the entire finalized prefix.
    #
    # Walk backward from the finalized tip to genesis on node 0.
    # Then verify every other node has the same blocks at the same roots.
    # This catches subtle disagreements that tip-only checks miss.
    finalized_root = node_cluster.nodes[0]._store.latest_finalized.root
    chain_roots: list[tuple[int, bytes]] = []
    store0 = node_cluster.nodes[0]._store
    current_root = finalized_root
    while current_root in store0.blocks:
        block = store0.blocks[current_root]
        chain_roots.append((int(block.slot), current_root))
        if int(block.slot) == 0:
            break
        current_root = block.parent_root

    for node in node_cluster.nodes[1:]:
        s = node._store
        for slot, root in chain_roots:
            assert root in s.blocks, f"Node {node.index} missing finalized block at slot {slot}"

    logger.info(
        "Finalized chain: %d blocks verified across all nodes",
        len(chain_roots),
    )

    # Phase 7: Sustained finalization
    #
    # Finalization must continue beyond a single round.
    # Reaching finalized slot >= 2 proves the protocol survives
    # proposer rotation: at least 2 different validators had their
    # blocks finalized, confirming end-to-end round-robin operation.
    logger.info("Phase 7: Sustained finalization")
    await assert_all_finalized_to(node_cluster, target_slot=2, timeout=60)
    diags = node_cluster.log_diagnostics("sustained-finalization")
    checkpoint_history.append(diags)

    # Per-node finalization check: each node must have finalized to >= 2.
    for node in node_cluster.nodes:
        assert node.finalized_slot >= 2, (
            f"Node {node.index}: finalized_slot={node.finalized_slot}, expected >= 2"
        )

    # Checkpoint agreement must still hold after deeper finalization.
    await assert_same_finalized_checkpoint(node_cluster, timeout=15)

    # Re-verify fork choice ancestry after the chain grew.
    assert_head_descends_from(node_cluster, "finalized")

    # Proposer diversity:
    #
    # With finalized_slot >= 2, at least slots 1 and 2 are finalized.
    #
    # Round-robin gives:
    # - slot 1 to validator 1 (1 % 3),
    # - slot 2 to validator 2 (2 % 3).
    #
    # Both must appear in the proposer set.
    store = node_cluster.nodes[0]._store
    finalized_proposers: set[int] = set()
    for _root, block in store.blocks.items():
        if 0 < int(block.slot) <= int(store.latest_finalized.slot):
            finalized_proposers.add(int(block.proposer_index))

    assert len(finalized_proposers) >= 2, (
        f"Expected >= 2 distinct proposers in finalized chain, got {finalized_proposers}"
    )
    # Exact proposer identity: round-robin guarantees these specific validators.
    assert 1 in finalized_proposers, (
        f"Validator 1 (proposer of slot 1) missing from finalized proposers: {finalized_proposers}"
    )
    assert 2 in finalized_proposers, (
        f"Validator 2 (proposer of slot 2) missing from finalized proposers: {finalized_proposers}"
    )

    # Block body content: blocks after slot 1 should carry attestations.
    #
    # Proposers include pending attestations in the block body.
    # If no blocks after slot 1 contain attestations, the pipeline
    # from attestation production to block inclusion is broken.
    blocks_with_attestations = 0
    checked_blocks = 0
    for _root, block in store.blocks.items():
        slot = int(block.slot)
        if slot <= 1:
            continue
        checked_blocks += 1
        att_count = len(block.body.attestations)
        if att_count > 0:
            blocks_with_attestations += 1
        logger.info("Slot %d: %d attestations in block body", slot, att_count)

    # At least one block after slot 1 must exist and contain attestations.
    assert checked_blocks >= 1, "No blocks after slot 1 found in store"
    assert blocks_with_attestations >= 1, (
        f"No blocks after slot 1 contain attestations (checked {checked_blocks} blocks)"
    )

    # Final cross-phase invariant: checkpoint slots must never decrease.
    #
    # Justified and finalized slots are monotonically increasing.
    # A regression in any phase would indicate a fork choice or
    # state transition bug.
    assert_checkpoint_monotonicity(checkpoint_history)

    logger.info("All 7 phases passed.")
