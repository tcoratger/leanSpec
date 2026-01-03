"""Tests for Discovery v5 protocol specification."""

import pytest

from lean_spec.subspecs.networking.discovery import (
    DiscoveryConfig,
    FindNode,
    KBucket,
    Nodes,
    Ping,
    Pong,
    RoutingTable,
    TalkReq,
    TalkResp,
)
from lean_spec.subspecs.networking.discovery.routing import (
    NodeEntry,
    log2_distance,
    xor_distance,
)


class TestDiscoveryConfig:
    """Tests for DiscoveryConfig."""

    def test_default_config(self) -> None:
        """Default config has expected values."""
        config = DiscoveryConfig()

        assert config.k_bucket_size == 16
        assert config.alpha == 3
        assert config.request_timeout_secs == 1.0
        assert config.max_nodes_response == 16

    def test_custom_config(self) -> None:
        """Custom config values are accepted."""
        config = DiscoveryConfig(
            k_bucket_size=8,
            alpha=5,
            request_timeout_secs=2.0,
        )
        assert config.k_bucket_size == 8
        assert config.alpha == 5


class TestDiscoveryMessages:
    """Tests for Discovery v5 message types."""

    def test_ping_creation(self) -> None:
        """Ping message can be created."""
        ping = Ping(
            request_id=b"\x01\x02\x03\x04",
            enr_seq=42,
        )
        assert ping.request_id == b"\x01\x02\x03\x04"
        assert ping.enr_seq == 42

    def test_pong_creation(self) -> None:
        """Pong message can be created."""
        pong = Pong(
            request_id=b"\x01\x02\x03\x04",
            enr_seq=42,
            recipient_ip=b"\xc0\xa8\x01\x01",
            recipient_port=9000,
        )
        assert pong.enr_seq == 42
        assert pong.recipient_port == 9000

    def test_findnode_creation(self) -> None:
        """FindNode message can be created."""
        findnode = FindNode(
            request_id=b"\x01\x02\x03\x04",
            distances=[0, 1, 256],
        )
        assert 0 in findnode.distances
        assert 256 in findnode.distances

    def test_nodes_creation(self) -> None:
        """Nodes message can be created."""
        nodes = Nodes(
            request_id=b"\x01\x02\x03\x04",
            total=3,
            enrs=[b"enr1", b"enr2"],
        )
        assert nodes.total == 3
        assert len(nodes.enrs) == 2

    def test_talkreq_creation(self) -> None:
        """TalkReq message can be created."""
        req = TalkReq(
            request_id=b"\x01\x02\x03\x04",
            protocol=b"eth2",
            request=b"payload",
        )
        assert req.protocol == b"eth2"

    def test_talkresp_creation(self) -> None:
        """TalkResp message can be created."""
        resp = TalkResp(
            request_id=b"\x01\x02\x03\x04",
            response=b"response_payload",
        )
        assert resp.response == b"response_payload"


class TestXorDistance:
    """Tests for XOR distance calculation."""

    def test_zero_distance(self) -> None:
        """Identical IDs have zero distance."""
        node_id = b"\x00" * 32
        assert xor_distance(node_id, node_id) == 0

    def test_max_distance(self) -> None:
        """Complementary IDs have maximum distance."""
        a = b"\x00" * 32
        b = b"\xff" * 32
        assert xor_distance(a, b) == (2**256 - 1)

    def test_distance_symmetry(self) -> None:
        """XOR distance is symmetric."""
        a = b"\x12" * 32
        b = b"\x34" * 32
        assert xor_distance(a, b) == xor_distance(b, a)

    def test_log2_distance_zero(self) -> None:
        """log2_distance of identical IDs is 0."""
        node_id = b"\x00" * 32
        assert log2_distance(node_id, node_id) == 0

    def test_log2_distance_values(self) -> None:
        """log2_distance returns bit position of highest differing bit."""
        a = b"\x00" * 32
        b = b"\x00" * 31 + b"\x01"  # Differs in last bit
        assert log2_distance(a, b) == 1

        c = b"\x00" * 31 + b"\x80"  # Differs in 8th bit from end
        assert log2_distance(a, c) == 8


class TestKBucket:
    """Tests for K-bucket implementation."""

    def test_empty_bucket(self) -> None:
        """New bucket is empty."""
        bucket = KBucket()
        assert bucket.is_empty
        assert not bucket.is_full
        assert len(bucket) == 0

    def test_add_node(self) -> None:
        """Nodes can be added to bucket."""
        bucket = KBucket()
        entry = NodeEntry(node_id=b"\x01" * 32)

        assert bucket.add(entry)
        assert len(bucket) == 1
        assert bucket.contains(b"\x01" * 32)

    def test_bucket_capacity(self) -> None:
        """Bucket respects K_BUCKET_SIZE capacity."""
        bucket = KBucket()

        # Fill bucket to capacity (default 16)
        for i in range(16):
            entry = NodeEntry(node_id=bytes([i]) + b"\x00" * 31)
            assert bucket.add(entry)

        assert bucket.is_full
        assert len(bucket) == 16

        # Cannot add more
        extra = NodeEntry(node_id=b"\xff" * 32)
        assert not bucket.add(extra)

    def test_update_existing_node(self) -> None:
        """Adding existing node moves it to back."""
        bucket = KBucket()

        entry1 = NodeEntry(node_id=b"\x01" * 32, enr_seq=1)
        entry2 = NodeEntry(node_id=b"\x02" * 32, enr_seq=1)
        bucket.add(entry1)
        bucket.add(entry2)

        # Update entry1
        updated = NodeEntry(node_id=b"\x01" * 32, enr_seq=2)
        bucket.add(updated)

        # entry1 should now be at back (most recent)
        tail = bucket.tail()
        assert tail is not None
        assert tail.node_id == b"\x01" * 32

    def test_remove_node(self) -> None:
        """Nodes can be removed from bucket."""
        bucket = KBucket()
        entry = NodeEntry(node_id=b"\x01" * 32)
        bucket.add(entry)

        assert bucket.remove(b"\x01" * 32)
        assert not bucket.contains(b"\x01" * 32)
        assert bucket.is_empty

    def test_get_node(self) -> None:
        """get() retrieves node entry by ID."""
        bucket = KBucket()
        entry = NodeEntry(node_id=b"\x01" * 32, enr_seq=42)
        bucket.add(entry)

        retrieved = bucket.get(b"\x01" * 32)
        assert retrieved is not None
        assert retrieved.enr_seq == 42

        assert bucket.get(b"\x02" * 32) is None


class TestRoutingTable:
    """Tests for routing table implementation."""

    def test_empty_routing_table(self) -> None:
        """New routing table is empty."""
        local_id = b"\x00" * 32
        table = RoutingTable(local_id=local_id)

        assert table.node_count() == 0

    def test_add_node_to_correct_bucket(self) -> None:
        """Nodes are added to correct bucket by distance."""
        local_id = b"\x00" * 32
        table = RoutingTable(local_id=local_id)

        # Add a node
        entry = NodeEntry(node_id=b"\x00" * 31 + b"\x01")
        table.add(entry)

        assert table.node_count() == 1
        assert table.contains(b"\x00" * 31 + b"\x01")

    def test_cannot_add_self(self) -> None:
        """Cannot add local node to routing table."""
        local_id = b"\xab" * 32
        table = RoutingTable(local_id=local_id)

        entry = NodeEntry(node_id=local_id)
        assert not table.add(entry)

    def test_closest_nodes(self) -> None:
        """closest_nodes() returns nodes sorted by distance."""
        local_id = b"\x00" * 32
        table = RoutingTable(local_id=local_id)

        # Add nodes at different distances
        for i in range(1, 5):
            entry = NodeEntry(node_id=bytes([i]) + b"\x00" * 31)
            table.add(entry)

        target = b"\x01" + b"\x00" * 31
        closest = table.closest_nodes(target, count=2)

        assert len(closest) == 2
        # First should be the target itself (distance 0)
        assert closest[0].node_id == target

    def test_routing_table_iteration(self) -> None:
        """Can iterate over all nodes in routing table."""
        local_id = b"\x00" * 32
        table = RoutingTable(local_id=local_id)

        for i in range(5):
            entry = NodeEntry(node_id=bytes([i + 1]) + b"\x00" * 31)
            table.add(entry)

        assert table.node_count() == 5
