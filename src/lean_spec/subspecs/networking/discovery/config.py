"""
Discovery v5 Configuration
==========================

Configuration parameters for the Discovery v5 protocol.
"""

from typing_extensions import Final

from lean_spec.types import StrictBaseModel

# =============================================================================
# Protocol Constants
# =============================================================================

K_BUCKET_SIZE: Final = 16
"""Number of nodes per k-bucket in the routing table."""

ALPHA: Final = 3
"""Concurrency parameter for lookups."""

BUCKET_COUNT: Final = 256
"""Number of k-buckets (log2 of ID space)."""

REQUEST_TIMEOUT_SECS: Final = 1.0
"""Timeout for individual requests in seconds."""

LOOKUP_PARALLELISM: Final = 3
"""Number of parallel queries during lookup."""

MAX_NODES_RESPONSE: Final = 16
"""Maximum nodes returned in a single NODES response."""

BOND_EXPIRY_SECS: Final = 86400
"""Time before a bonded node must be re-validated (24 hours)."""


class DiscoveryConfig(StrictBaseModel):
    """
    Configuration for the Discovery v5 protocol.

    Attributes:
        k_bucket_size: Number of nodes per k-bucket.
        alpha: Concurrency parameter for lookups.
        request_timeout_secs: Timeout for requests.
        lookup_parallelism: Parallel queries during lookup.
        max_nodes_response: Max nodes in NODES response.
        bond_expiry_secs: Bond expiration time.
    """

    k_bucket_size: int = K_BUCKET_SIZE
    alpha: int = ALPHA
    request_timeout_secs: float = REQUEST_TIMEOUT_SECS
    lookup_parallelism: int = LOOKUP_PARALLELISM
    max_nodes_response: int = MAX_NODES_RESPONSE
    bond_expiry_secs: int = BOND_EXPIRY_SECS
