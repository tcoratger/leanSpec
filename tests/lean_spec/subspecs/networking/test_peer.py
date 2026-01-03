"""Tests for peer management specification."""

import pytest

from lean_spec.subspecs.networking.peer import PeerInfo, PeerManager, PeerManagerConfig
from lean_spec.subspecs.networking.types import PeerState
from lean_spec.types import Uint64


class TestPeerInfo:
    """Tests for PeerInfo structure."""

    def test_create_peer_info(self) -> None:
        """PeerInfo can be created with peer ID."""
        info = PeerInfo(peer_id="16Uiu2HAk...")
        assert info.peer_id == "16Uiu2HAk..."
        assert info.state == PeerState.DISCONNECTED

    def test_is_connected_states(self) -> None:
        """is_connected() returns True for connected states."""
        info = PeerInfo(peer_id="test")

        info.state = PeerState.DISCONNECTED
        assert not info.is_connected()

        info.state = PeerState.CONNECTING
        assert not info.is_connected()

        info.state = PeerState.CONNECTED
        assert info.is_connected()

        info.state = PeerState.HANDSHAKING
        assert info.is_connected()

        info.state = PeerState.ACTIVE
        assert info.is_connected()

    def test_is_active(self) -> None:
        """is_active() returns True only for ACTIVE state."""
        info = PeerInfo(peer_id="test")

        info.state = PeerState.CONNECTED
        assert not info.is_active()

        info.state = PeerState.ACTIVE
        assert info.is_active()

    def test_subnet_subscription(self) -> None:
        """Subnet subscription checking works correctly."""
        info = PeerInfo(peer_id="test")

        # Subscribe to subnets 0 and 7 (bits in first byte)
        info.attnets = b"\x81" + b"\x00" * 7  # 0x81 = 10000001

        assert info.is_subscribed_to_subnet(0)
        assert info.is_subscribed_to_subnet(7)
        assert not info.is_subscribed_to_subnet(1)
        assert not info.is_subscribed_to_subnet(63)

    def test_subscribed_subnets_list(self) -> None:
        """subscribed_subnets() returns correct list."""
        info = PeerInfo(peer_id="test")
        info.attnets = b"\x05" + b"\x00" * 7  # 0x05 = 00000101 = subnets 0 and 2

        subnets = info.subscribed_subnets()
        assert subnets == [0, 2]

    def test_update_from_status(self) -> None:
        """update_from_status() updates chain info."""
        info = PeerInfo(peer_id="test")

        info.update_from_status(finalized_epoch=Uint64(100), head_slot=Uint64(3200))

        assert info.finalized_epoch == Uint64(100)
        assert info.head_slot == Uint64(3200)

    def test_update_from_metadata(self) -> None:
        """update_from_metadata() updates if seq is higher."""
        info = PeerInfo(peer_id="test")
        info.metadata_seq = Uint64(5)

        # Lower seq should not update
        info.update_from_metadata(seq=Uint64(3), attnets=b"\xff" * 8, syncnets=b"\x01")
        assert info.attnets == b"\x00" * 8  # Unchanged

        # Higher seq should update
        info.update_from_metadata(seq=Uint64(10), attnets=b"\xff" * 8, syncnets=b"\x01")
        assert info.metadata_seq == Uint64(10)
        assert info.attnets == b"\xff" * 8


class TestPeerManagerConfig:
    """Tests for PeerManagerConfig."""

    def test_default_config(self) -> None:
        """Default config has sensible values."""
        config = PeerManagerConfig()

        assert config.target_peer_count == 50
        assert config.max_peer_count == 100
        assert config.min_peer_count == 10
        assert config.outbound_ratio == 0.5

    def test_custom_config(self) -> None:
        """Custom config values are accepted."""
        config = PeerManagerConfig(
            target_peer_count=25,
            max_peer_count=50,
        )
        assert config.target_peer_count == 25


class TestPeerManager:
    """Tests for PeerManager."""

    def test_create_manager(self) -> None:
        """PeerManager can be created with config."""
        config = PeerManagerConfig()
        manager = PeerManager(config=config)

        assert len(manager) == 0

    def test_get_or_create_peer(self) -> None:
        """get_or_create() creates new peer if not exists."""
        manager = PeerManager(config=PeerManagerConfig())

        peer = manager.get_or_create("peer1")
        assert peer.peer_id == "peer1"
        assert "peer1" in manager

        # Second call returns same peer
        peer2 = manager.get_or_create("peer1")
        assert peer is peer2

    def test_remove_peer(self) -> None:
        """remove() removes peer from manager."""
        manager = PeerManager(config=PeerManagerConfig())
        manager.get_or_create("peer1")

        removed = manager.remove("peer1")
        assert removed is not None
        assert "peer1" not in manager

    def test_connection_state_transitions(self) -> None:
        """State transitions update peer state correctly."""
        manager = PeerManager(config=PeerManagerConfig())

        # Connecting
        assert manager.on_connecting("peer1")
        peer = manager.get("peer1")
        assert peer is not None
        assert peer.state == PeerState.CONNECTING

        # Connected
        manager.on_connected("peer1")
        assert peer.state == PeerState.CONNECTED

        # Handshaking
        manager.on_handshake_start("peer1")
        assert peer.state == PeerState.HANDSHAKING

        # Active
        manager.on_handshake_complete("peer1")
        assert peer.state == PeerState.ACTIVE

        # Disconnecting
        manager.on_disconnecting("peer1")
        assert peer.state == PeerState.DISCONNECTING

        # Disconnected
        manager.on_disconnected("peer1")
        assert peer.state == PeerState.DISCONNECTED
        assert peer.disconnect_count == 1

    def test_connected_peers(self) -> None:
        """connected_peers() returns only connected peers."""
        manager = PeerManager(config=PeerManagerConfig())

        manager.on_connecting("peer1")
        manager.on_connected("peer1")
        manager.on_handshake_complete("peer1")

        manager.on_connecting("peer2")
        manager.on_connected("peer2")

        manager.get_or_create("peer3")  # Disconnected

        connected = manager.connected_peers()
        active = manager.active_peers()

        assert len(connected) == 2
        assert len(active) == 1

    def test_capacity_check(self) -> None:
        """is_at_capacity() respects max_peer_count."""
        config = PeerManagerConfig(max_peer_count=2)
        manager = PeerManager(config=config)

        manager.on_connecting("peer1")
        manager.on_connected("peer1")
        assert not manager.is_at_capacity()

        manager.on_connecting("peer2")
        manager.on_connected("peer2")
        assert manager.is_at_capacity()

        # Cannot connect more when at capacity
        assert not manager.on_connecting("peer3")

    def test_score_update(self) -> None:
        """update_score() modifies peer score."""
        manager = PeerManager(config=PeerManagerConfig())
        manager.get_or_create("peer1")

        manager.update_score("peer1", 10.0)
        peer = manager.get("peer1")
        assert peer is not None
        assert peer.score == 10.0

        manager.update_score("peer1", -5.0)
        assert peer.score == 5.0

    def test_ban_peer(self) -> None:
        """ban() adds peer to banned list."""
        manager = PeerManager(config=PeerManagerConfig())
        manager.get_or_create("peer1")

        manager.ban("peer1")

        assert manager.is_banned("peer1")
        assert not manager.on_connecting("peer1")  # Cannot connect when banned

    def test_unban_peer(self) -> None:
        """unban() removes peer from banned list."""
        manager = PeerManager(config=PeerManagerConfig())
        manager.ban("peer1")

        manager.unban("peer1")

        assert not manager.is_banned("peer1")

    def test_peers_on_subnet(self) -> None:
        """peers_on_subnet() returns peers subscribed to subnet."""
        manager = PeerManager(config=PeerManagerConfig())

        # Create active peer subscribed to subnet 5
        manager.on_connecting("peer1")
        manager.on_connected("peer1")
        manager.on_handshake_complete("peer1")
        peer1 = manager.get("peer1")
        assert peer1 is not None
        peer1.attnets = b"\x20" + b"\x00" * 7  # Bit 5 set

        # Create active peer not on subnet 5
        manager.on_connecting("peer2")
        manager.on_connected("peer2")
        manager.on_handshake_complete("peer2")

        subnet_peers = manager.peers_on_subnet(5)
        assert len(subnet_peers) == 1
        assert subnet_peers[0].peer_id == "peer1"

    def test_best_peers_for_sync(self) -> None:
        """best_peers_for_sync() returns peers sorted by chain progress."""
        manager = PeerManager(config=PeerManagerConfig())

        # Create peers with different chain progress
        for i, (epoch, slot) in enumerate([(100, 3200), (50, 1600), (100, 3300)]):
            peer_id = f"peer{i}"
            manager.on_connecting(peer_id)
            manager.on_connected(peer_id)
            manager.on_handshake_complete(peer_id)
            peer = manager.get(peer_id)
            assert peer is not None
            peer.finalized_epoch = Uint64(epoch)
            peer.head_slot = Uint64(slot)

        best = manager.best_peers_for_sync(2)
        assert len(best) == 2
        # peer2 should be first (epoch 100, slot 3300)
        assert best[0].peer_id == "peer2"
