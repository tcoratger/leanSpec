"""Tests for minimal peer module."""

from lean_spec.subspecs.networking.peer import Direction, PeerInfo
from lean_spec.subspecs.networking.types import ConnectionState, GoodbyeReason


class TestConnectionState:
    """Tests for ConnectionState enum."""

    def test_state_values(self) -> None:
        """ConnectionState has the 4 expected states."""
        assert ConnectionState.DISCONNECTED == 1
        assert ConnectionState.CONNECTING == 2
        assert ConnectionState.CONNECTED == 3
        assert ConnectionState.DISCONNECTING == 4


class TestGoodbyeReason:
    """Tests for GoodbyeReason codes."""

    def test_official_codes(self) -> None:
        """Official spec codes have correct values."""
        assert GoodbyeReason.CLIENT_SHUTDOWN == 1
        assert GoodbyeReason.IRRELEVANT_NETWORK == 2
        assert GoodbyeReason.FAULT_OR_ERROR == 3


class TestDirection:
    """Tests for Direction enum."""

    def test_direction_values(self) -> None:
        """Direction has inbound and outbound."""
        assert Direction.INBOUND == 1
        assert Direction.OUTBOUND == 2


class TestPeerInfo:
    """Tests for PeerInfo dataclass."""

    def test_create_peer_info(self) -> None:
        """PeerInfo can be created with peer ID."""
        peer = PeerInfo(peer_id="16Uiu2HAk...")
        assert peer.peer_id == "16Uiu2HAk..."
        assert peer.state == ConnectionState.DISCONNECTED
        assert peer.direction == Direction.OUTBOUND
        assert peer.address is None

    def test_create_with_all_fields(self) -> None:
        """PeerInfo can be created with all fields."""
        peer = PeerInfo(
            peer_id="16Uiu2HAk...",
            state=ConnectionState.CONNECTED,
            direction=Direction.INBOUND,
            address="/ip4/192.168.1.1/tcp/9000",
        )
        assert peer.state == ConnectionState.CONNECTED
        assert peer.direction == Direction.INBOUND
        assert peer.address == "/ip4/192.168.1.1/tcp/9000"

    def test_is_connected(self) -> None:
        """is_connected() returns True only when connected."""
        peer = PeerInfo(peer_id="test")

        peer.state = ConnectionState.DISCONNECTED
        assert not peer.is_connected()

        peer.state = ConnectionState.CONNECTING
        assert not peer.is_connected()

        peer.state = ConnectionState.CONNECTED
        assert peer.is_connected()

        peer.state = ConnectionState.DISCONNECTING
        assert not peer.is_connected()

    def test_update_last_seen(self) -> None:
        """update_last_seen() updates timestamp."""
        peer = PeerInfo(peer_id="test")
        original_time = peer.last_seen

        # Small delay to ensure time difference
        import time

        time.sleep(0.01)

        peer.update_last_seen()
        assert peer.last_seen > original_time
