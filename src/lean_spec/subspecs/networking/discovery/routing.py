"""
Discovery v5 Routing Table
==========================

This module specifies the Kademlia-style routing table used in Discovery v5.
The routing table stores known nodes organized by their distance from the
local node.
"""

from dataclasses import dataclass, field
from typing import Iterator, Optional

from .config import BUCKET_COUNT, K_BUCKET_SIZE


def xor_distance(a: bytes, b: bytes) -> int:
    """
    Compute the XOR distance between two node IDs.

    The XOR distance is the standard metric in Kademlia networks.
    It satisfies the triangle inequality and defines a metric space.

    Args:
        a: First node ID (32 bytes).
        b: Second node ID (32 bytes).

    Returns:
        Integer representing the XOR distance.
    """
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


def log2_distance(a: bytes, b: bytes) -> int:
    """
    Compute the log2 of the XOR distance (bucket index).

    This determines which k-bucket a node belongs to.
    Returns 0 if the IDs are identical.

    Args:
        a: First node ID (32 bytes).
        b: Second node ID (32 bytes).

    Returns:
        The log2 distance (0-256).
    """
    distance = xor_distance(a, b)
    if distance == 0:
        return 0
    return distance.bit_length()


@dataclass
class NodeEntry:
    """
    An entry in the routing table for a discovered node.

    Attributes:
        node_id: The 32-byte node identifier.
        enr_seq: Last known ENR sequence number.
        last_seen: Timestamp of last successful contact.
        endpoint: Network endpoint (ip:port).
    """

    node_id: bytes
    enr_seq: int = 0
    last_seen: float = 0.0
    endpoint: Optional[str] = None


@dataclass
class KBucket:
    """
    A k-bucket holding up to k node entries.

    K-buckets organize nodes by their distance from the local node.
    Each bucket holds nodes at a specific log2 distance range.

    Properties
    ----------

    - Fixed capacity of K_BUCKET_SIZE nodes
    - Least-recently seen nodes are at the front
    - Most-recently seen nodes are at the back

    Eviction Policy
    ---------------

    When the bucket is full and a new node is discovered:
    1. Ping the least-recently seen node (front)
    2. If it responds, move it to the back and discard the new node
    3. If it doesn't respond, evict it and add the new node

    Attributes:
        nodes: List of node entries in this bucket.
    """

    nodes: list[NodeEntry] = field(default_factory=list)

    @property
    def is_full(self) -> bool:
        """Check if the bucket is at capacity."""
        return len(self.nodes) >= K_BUCKET_SIZE

    @property
    def is_empty(self) -> bool:
        """Check if the bucket has no nodes."""
        return len(self.nodes) == 0

    def __len__(self) -> int:
        """Return the number of nodes in this bucket."""
        return len(self.nodes)

    def __iter__(self) -> Iterator[NodeEntry]:
        """Iterate over nodes in the bucket."""
        return iter(self.nodes)

    def contains(self, node_id: bytes) -> bool:
        """Check if a node ID is in this bucket."""
        return any(entry.node_id == node_id for entry in self.nodes)

    def get(self, node_id: bytes) -> Optional[NodeEntry]:
        """Get a node entry by ID, or None if not found."""
        for entry in self.nodes:
            if entry.node_id == node_id:
                return entry
        return None

    def add(self, entry: NodeEntry) -> bool:
        """
        Add a node to the bucket.

        If the node already exists, it is moved to the back (most recent).
        If the bucket is full, the node is not added.

        Args:
            entry: The node entry to add.

        Returns:
            True if the node was added or updated, False if bucket is full.
        """
        # If node exists, move to back
        for i, existing in enumerate(self.nodes):
            if existing.node_id == entry.node_id:
                self.nodes.pop(i)
                self.nodes.append(entry)
                return True

        # If bucket is full, cannot add
        if self.is_full:
            return False

        # Add new node
        self.nodes.append(entry)
        return True

    def remove(self, node_id: bytes) -> bool:
        """
        Remove a node from the bucket.

        Args:
            node_id: The node ID to remove.

        Returns:
            True if the node was removed, False if not found.
        """
        for i, entry in enumerate(self.nodes):
            if entry.node_id == node_id:
                self.nodes.pop(i)
                return True
        return False

    def head(self) -> Optional[NodeEntry]:
        """Get the least-recently seen node (front of list)."""
        return self.nodes[0] if self.nodes else None

    def tail(self) -> Optional[NodeEntry]:
        """Get the most-recently seen node (back of list)."""
        return self.nodes[-1] if self.nodes else None


@dataclass
class RoutingTable:
    """
    Kademlia routing table for Discovery v5.

    The routing table organizes discovered nodes into k-buckets based
    on their XOR distance from the local node ID.

    Structure
    ---------

    - 256 k-buckets (one for each possible log2 distance)
    - Each bucket holds up to K_BUCKET_SIZE nodes
    - Bucket i contains nodes with log2(distance) == i + 1

    Attributes:
        local_id: This node's ID.
        buckets: Array of k-buckets indexed by distance.
    """

    local_id: bytes
    buckets: list[KBucket] = field(default_factory=lambda: [KBucket() for _ in range(BUCKET_COUNT)])

    def bucket_index(self, node_id: bytes) -> int:
        """
        Get the bucket index for a node ID.

        Args:
            node_id: The node ID to find the bucket for.

        Returns:
            Bucket index (0-255).
        """
        distance = log2_distance(self.local_id, node_id)
        # Bucket 0 is for distance 1, bucket 255 is for distance 256
        return max(0, distance - 1)

    def get_bucket(self, node_id: bytes) -> KBucket:
        """Get the k-bucket for a specific node ID."""
        return self.buckets[self.bucket_index(node_id)]

    def add(self, entry: NodeEntry) -> bool:
        """
        Add a node to the appropriate bucket.

        Args:
            entry: The node entry to add.

        Returns:
            True if added/updated, False if bucket is full.
        """
        if entry.node_id == self.local_id:
            return False  # Don't add ourselves
        bucket = self.get_bucket(entry.node_id)
        return bucket.add(entry)

    def remove(self, node_id: bytes) -> bool:
        """Remove a node from the routing table."""
        bucket = self.get_bucket(node_id)
        return bucket.remove(node_id)

    def get(self, node_id: bytes) -> Optional[NodeEntry]:
        """Get a node entry by ID."""
        bucket = self.get_bucket(node_id)
        return bucket.get(node_id)

    def contains(self, node_id: bytes) -> bool:
        """Check if a node ID is in the routing table."""
        return self.get(node_id) is not None

    def node_count(self) -> int:
        """Count total nodes in the routing table."""
        return sum(len(bucket) for bucket in self.buckets)

    def closest_nodes(self, target: bytes, count: int) -> list[NodeEntry]:
        """
        Find the closest nodes to a target ID.

        Args:
            target: Target node ID to find nodes near.
            count: Maximum number of nodes to return.

        Returns:
            List of nodes sorted by distance to target.
        """
        all_nodes = [entry for bucket in self.buckets for entry in bucket]
        all_nodes.sort(key=lambda e: xor_distance(e.node_id, target))
        return all_nodes[:count]
