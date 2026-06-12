"""Tests for networking shared types."""

from lean_spec.node.networking.types import ConnectionState, Direction


class TestConnectionState:
    """Tests for ConnectionState enum."""

    def test_state_values(self) -> None:
        """ConnectionState has the 4 expected states."""
        assert ConnectionState.DISCONNECTED == 1
        assert ConnectionState.CONNECTING == 2
        assert ConnectionState.CONNECTED == 3
        assert ConnectionState.DISCONNECTING == 4


class TestDirection:
    """Tests for Direction enum."""

    def test_direction_values(self) -> None:
        """Direction has inbound and outbound."""
        assert Direction.INBOUND == 1
        assert Direction.OUTBOUND == 2
