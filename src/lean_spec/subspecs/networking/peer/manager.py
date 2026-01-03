"""
Peer Manager
============

This module specifies the peer manager that coordinates peer connections,
tracks peer state, and enforces connection limits.
"""

from dataclasses import dataclass, field
from typing import Iterator, Optional

from lean_spec.types import StrictBaseModel

from ..types import PeerId, PeerState
from .info import PeerInfo


class PeerManagerConfig(StrictBaseModel):
    """Configuration for the peer manager."""

    target_peer_count: int = 50
    """Target number of active peers."""

    max_peer_count: int = 100
    """Maximum number of connected peers."""

    min_peer_count: int = 10
    """Minimum peers before aggressive discovery."""

    outbound_ratio: float = 0.5
    """Target ratio of outbound connections."""

    ban_duration_secs: int = 3600
    """Duration to ban misbehaving peers."""

    score_disconnect_threshold: float = -100.0
    """Score below which peers are disconnected."""

    score_ban_threshold: float = -200.0
    """Score below which peers are banned."""


@dataclass
class PeerManager:
    """
    Manages peer connections and state.

    The peer manager is responsible for:
    - Tracking known peers and their state
    - Enforcing connection limits
    - Coordinating with discovery
    - Managing peer scores
    """

    config: PeerManagerConfig
    """Manager configuration."""

    peers: dict[PeerId, PeerInfo] = field(default_factory=dict)
    """All known peers."""

    banned_peers: dict[PeerId, float] = field(default_factory=dict)
    """Banned peers and ban expiry timestamps."""

    def __len__(self) -> int:
        """Return total number of known peers."""
        return len(self.peers)

    def __iter__(self) -> Iterator[PeerInfo]:
        """Iterate over all known peers."""
        return iter(self.peers.values())

    def __contains__(self, peer_id: PeerId) -> bool:
        """Check if a peer is known."""
        return peer_id in self.peers

    def get(self, peer_id: PeerId) -> Optional[PeerInfo]:
        """Get peer info by ID."""
        return self.peers.get(peer_id)

    def get_or_create(self, peer_id: PeerId) -> PeerInfo:
        """Get existing peer or create new entry."""
        if peer_id not in self.peers:
            self.peers[peer_id] = PeerInfo(peer_id=peer_id)
        return self.peers[peer_id]

    def remove(self, peer_id: PeerId) -> Optional[PeerInfo]:
        """Remove a peer from tracking."""
        return self.peers.pop(peer_id, None)

    # =========================================================================
    # Connection State
    # =========================================================================

    def connected_peers(self) -> list[PeerInfo]:
        """Get all connected peers."""
        return [p for p in self.peers.values() if p.is_connected()]

    def active_peers(self) -> list[PeerInfo]:
        """Get all active (handshake complete) peers."""
        return [p for p in self.peers.values() if p.is_active()]

    def connected_count(self) -> int:
        """Count connected peers."""
        return len(self.connected_peers())

    def active_count(self) -> int:
        """Count active peers."""
        return len(self.active_peers())

    def is_at_capacity(self) -> bool:
        """Check if at maximum connection capacity."""
        return self.connected_count() >= self.config.max_peer_count

    def needs_more_peers(self) -> bool:
        """Check if below minimum peer threshold."""
        return self.active_count() < self.config.min_peer_count

    # =========================================================================
    # State Transitions
    # =========================================================================

    def on_connecting(self, peer_id: PeerId) -> bool:
        """
        Handle connection attempt start.

        Returns False if connection should be rejected.
        """
        if self.is_banned(peer_id):
            return False
        if self.is_at_capacity():
            return False

        peer = self.get_or_create(peer_id)
        peer.state = PeerState.CONNECTING
        peer.connection_attempts += 1
        return True

    def on_connected(self, peer_id: PeerId) -> None:
        """Handle transport connection established."""
        peer = self.get_or_create(peer_id)
        peer.state = PeerState.CONNECTED

    def on_handshake_start(self, peer_id: PeerId) -> None:
        """Handle handshake initiation."""
        peer = self.get_or_create(peer_id)
        peer.state = PeerState.HANDSHAKING

    def on_handshake_complete(self, peer_id: PeerId) -> None:
        """Handle successful handshake."""
        peer = self.get_or_create(peer_id)
        peer.state = PeerState.ACTIVE

    def on_disconnecting(self, peer_id: PeerId) -> None:
        """Handle disconnection start."""
        peer = self.get(peer_id)
        if peer:
            peer.state = PeerState.DISCONNECTING

    def on_disconnected(self, peer_id: PeerId) -> None:
        """Handle connection closed."""
        peer = self.get(peer_id)
        if peer:
            peer.state = PeerState.DISCONNECTED
            peer.disconnect_count += 1

    # =========================================================================
    # Scoring and Banning
    # =========================================================================

    def update_score(self, peer_id: PeerId, delta: float) -> None:
        """Update a peer's score by delta."""
        peer = self.get(peer_id)
        if peer:
            peer.score += delta
            self._check_score_thresholds(peer)

    def set_score(self, peer_id: PeerId, score: float) -> None:
        """Set a peer's score directly."""
        peer = self.get(peer_id)
        if peer:
            peer.score = score
            self._check_score_thresholds(peer)

    def _check_score_thresholds(self, peer: PeerInfo) -> None:
        """Check if peer score triggers action."""
        if peer.score < self.config.score_ban_threshold:
            self.ban(peer.peer_id)
        elif peer.score < self.config.score_disconnect_threshold:
            if peer.is_connected():
                peer.state = PeerState.DISCONNECTING

    def ban(self, peer_id: PeerId, duration_secs: Optional[int] = None) -> None:
        """Ban a peer."""
        import time

        duration = duration_secs or self.config.ban_duration_secs
        self.banned_peers[peer_id] = time.time() + duration

        peer = self.get(peer_id)
        if peer and peer.is_connected():
            peer.state = PeerState.DISCONNECTING

    def unban(self, peer_id: PeerId) -> None:
        """Unban a peer."""
        self.banned_peers.pop(peer_id, None)

    def is_banned(self, peer_id: PeerId) -> bool:
        """Check if a peer is banned."""
        import time

        if peer_id not in self.banned_peers:
            return False
        if self.banned_peers[peer_id] < time.time():
            self.unban(peer_id)
            return False
        return True

    # =========================================================================
    # Subnet Queries
    # =========================================================================

    def peers_on_subnet(self, subnet_id: int) -> list[PeerInfo]:
        """Get active peers subscribed to a subnet."""
        return [p for p in self.active_peers() if p.is_subscribed_to_subnet(subnet_id)]

    def best_peers_for_sync(self, count: int) -> list[PeerInfo]:
        """Get the best peers for chain synchronization."""
        active = self.active_peers()
        active.sort(key=lambda p: (p.finalized_epoch, p.head_slot, p.score), reverse=True)
        return active[:count]
