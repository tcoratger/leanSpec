"""
Prometheus metric definitions aligned with leanMetrics spec.

Names, types, and buckets match https://github.com/leanEthereum/leanMetrics/blob/main/metrics.md
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from prometheus_client import (
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

if TYPE_CHECKING:
    from prometheus_client import CollectorRegistry

# Histogram buckets from leanMetrics spec
FORK_CHOICE_BLOCK_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 1, 1.25, 1.5, 2, 4)
ATTESTATION_VALIDATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 1)
STATE_TRANSITION_BUCKETS = (0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 4)
REORG_DEPTH_BUCKETS = (1, 2, 3, 5, 7, 10, 20, 30, 50, 100)

# Node info (set once at start). None until init_metrics() runs.
lean_node_info: Gauge | None = None
lean_node_start_time_seconds: Gauge | None = None

# Fork choice
lean_head_slot: Gauge | None = None
lean_current_slot: Gauge | None = None
lean_safe_target_slot: Gauge | None = None
lean_fork_choice_block_processing_time_seconds: Histogram | None = None
lean_attestations_valid_total: Counter | None = None
lean_attestations_invalid_total: Counter | None = None
lean_attestation_validation_time_seconds: Histogram | None = None
lean_fork_choice_reorgs_total: Counter | None = None
lean_fork_choice_reorg_depth: Histogram | None = None

# State transition
lean_latest_justified_slot: Gauge | None = None
lean_latest_finalized_slot: Gauge | None = None
lean_state_transition_time_seconds: Histogram | None = None

# Validator
lean_validators_count: Gauge | None = None

# Network
lean_connected_peers: Gauge | None = None

_initialized = False


def init_metrics(
    name: str = "leanspec-node",
    version: str = "0.0.1",
    registry: CollectorRegistry | None = None,
) -> None:
    """
    Create and register all lean metrics.

    Call once at node startup. Idempotent; subsequent calls no-op.

    Args:
        name: Node name label for lean_node_info.
        version: Node version label for lean_node_info.
        registry: Prometheus registry to use. Defaults to global REGISTRY.
    """
    global _initialized
    if _initialized:
        return
    reg = registry or REGISTRY

    # Node info (leanMetrics: Node Info Metrics)
    global lean_node_info, lean_node_start_time_seconds
    lean_node_info = Gauge(
        "lean_node_info",
        "Node information (always 1).",
        ["name", "version"],
        registry=reg,
    )
    lean_node_info.labels(name=name, version=version).set(1)
    lean_node_start_time_seconds = Gauge(
        "lean_node_start_time_seconds",
        "Start timestamp.",
        registry=reg,
    )
    lean_node_start_time_seconds.set(time.time())

    # Fork choice (leanMetrics: Fork-Choice Metrics)
    global lean_head_slot, lean_current_slot, lean_safe_target_slot
    global lean_fork_choice_block_processing_time_seconds
    global lean_attestations_valid_total, lean_attestations_invalid_total
    global lean_attestation_validation_time_seconds
    global lean_fork_choice_reorgs_total, lean_fork_choice_reorg_depth
    lean_head_slot = Gauge(
        "lean_head_slot",
        "Latest slot of the lean chain.",
        registry=reg,
    )
    lean_current_slot = Gauge(
        "lean_current_slot",
        "Current slot of the lean chain.",
        registry=reg,
    )
    lean_safe_target_slot = Gauge(
        "lean_safe_target_slot",
        "Safe target slot.",
        registry=reg,
    )
    lean_fork_choice_block_processing_time_seconds = Histogram(
        "lean_fork_choice_block_processing_time_seconds",
        "Time taken to process block in fork choice.",
        buckets=FORK_CHOICE_BLOCK_BUCKETS,
        registry=reg,
    )
    lean_attestations_valid_total = Counter(
        "lean_attestations_valid_total",
        "Total number of valid attestations.",
        ["source"],
        registry=reg,
    )
    lean_attestations_invalid_total = Counter(
        "lean_attestations_invalid_total",
        "Total number of invalid attestations.",
        ["source"],
        registry=reg,
    )
    lean_attestation_validation_time_seconds = Histogram(
        "lean_attestation_validation_time_seconds",
        "Time taken to validate attestation.",
        buckets=ATTESTATION_VALIDATION_BUCKETS,
        registry=reg,
    )
    lean_fork_choice_reorgs_total = Counter(
        "lean_fork_choice_reorgs_total",
        "Total number of fork choice reorgs.",
        registry=reg,
    )
    lean_fork_choice_reorg_depth = Histogram(
        "lean_fork_choice_reorg_depth",
        "Depth of fork choice reorgs (in blocks).",
        buckets=REORG_DEPTH_BUCKETS,
        registry=reg,
    )

    # State transition (leanMetrics: State Transition Metrics)
    global lean_latest_justified_slot, lean_latest_finalized_slot
    global lean_state_transition_time_seconds
    lean_latest_justified_slot = Gauge(
        "lean_latest_justified_slot",
        "Latest justified slot.",
        registry=reg,
    )
    lean_latest_finalized_slot = Gauge(
        "lean_latest_finalized_slot",
        "Latest finalized slot.",
        registry=reg,
    )
    lean_state_transition_time_seconds = Histogram(
        "lean_state_transition_time_seconds",
        "Time to process state transition.",
        buckets=STATE_TRANSITION_BUCKETS,
        registry=reg,
    )

    # Validator (leanMetrics: Validator Metrics)
    global lean_validators_count
    lean_validators_count = Gauge(
        "lean_validators_count",
        "Number of validators managed by a node.",
        registry=reg,
    )
    lean_validators_count.set(0)

    # Network (leanMetrics: Network Metrics)
    global lean_connected_peers
    lean_connected_peers = Gauge(
        "lean_connected_peers",
        "Number of connected peers.",
        registry=reg,
    )
    lean_connected_peers.set(0)

    _initialized = True


def get_metrics_output(registry: CollectorRegistry | None = None) -> bytes:
    """
    Return Prometheus text exposition format for scraping.

    Args:
        registry: Registry to export. Defaults to global REGISTRY.

    Returns:
        UTF-8 bytes suitable for HTTP response body.
    """
    reg = registry or REGISTRY
    return generate_latest(reg)
