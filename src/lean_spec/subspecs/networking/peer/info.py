"""
Peer Information
================

This module defines the data structures for tracking peer information.
"""

from dataclasses import dataclass, field

from lean_spec.types import Uint64

from ..types import Multiaddr, PeerId, PeerState, SeqNumber


@dataclass
class PeerInfo:
    """Complete information about a known peer."""

    peer_id: PeerId
    """The libp2p peer identifier."""

    state: PeerState = PeerState.DISCONNECTED
    """Current connection state."""

    multiaddrs: list[Multiaddr] = field(default_factory=list)
    """Known network addresses for this peer."""

    enr_seq: SeqNumber = field(default_factory=lambda: Uint64(0))
    """Last known ENR sequence number."""

    metadata_seq: SeqNumber = field(default_factory=lambda: Uint64(0))
    """Last known metadata sequence number."""

    finalized_epoch: Uint64 = field(default_factory=lambda: Uint64(0))
    """Peer's finalized epoch from Status."""

    head_slot: Uint64 = field(default_factory=lambda: Uint64(0))
    """Peer's head slot from Status."""

    score: float = 0.0
    """Behavioral score."""

    last_seen: float = 0.0
    """Timestamp of last successful interaction."""

    connection_attempts: int = 0
    """Number of connection attempts."""

    disconnect_count: int = 0
    """Number of times peer has disconnected."""

    attnets: bytes = b"\x00" * 8
    """Attestation subnet subscriptions."""

    syncnets: bytes = b"\x00"
    """Sync committee subnet subscriptions."""

    def is_connected(self) -> bool:
        """Check if peer is in a connected state."""
        return self.state in (PeerState.CONNECTED, PeerState.HANDSHAKING, PeerState.ACTIVE)

    def is_active(self) -> bool:
        """Check if peer is fully active (handshake complete)."""
        return self.state == PeerState.ACTIVE

    def is_subscribed_to_subnet(self, subnet_id: int) -> bool:
        """Check if peer is subscribed to an attestation subnet."""
        if not 0 <= subnet_id < 64:
            return False
        byte_index = subnet_id // 8
        bit_index = subnet_id % 8
        return bool(self.attnets[byte_index] & (1 << bit_index))

    def subscribed_subnets(self) -> list[int]:
        """Get list of subscribed attestation subnets."""
        return [i for i in range(64) if self.is_subscribed_to_subnet(i)]

    def update_from_status(self, finalized_epoch: Uint64, head_slot: Uint64) -> None:
        """Update peer info from a Status message."""
        self.finalized_epoch = finalized_epoch
        self.head_slot = head_slot

    def update_from_metadata(self, seq: SeqNumber, attnets: bytes, syncnets: bytes) -> None:
        """Update peer info from a Metadata message."""
        if seq > self.metadata_seq:
            self.metadata_seq = seq
            self.attnets = attnets
            self.syncnets = syncnets
