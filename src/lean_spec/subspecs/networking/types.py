"""Networking-related type definitions for the specification."""

from enum import IntEnum, auto

from lean_spec.types import Uint64
from lean_spec.types.byte_arrays import Bytes4, Bytes32

DomainType = Bytes4
"""4-byte domain for message-id isolation in Gossipsub."""

NodeId = Bytes32
"""32-byte node identifier for Discovery v5, derived from ``keccak256(pubkey)``."""

ForkDigest = Bytes4
"""4-byte fork identifier ensuring network isolation between forks."""

SeqNumber = Uint64
"""Sequence number used in ENR records, metadata, and ping messages."""

SubnetId = Uint64
"""Subnet identifier (0-63) for attestation subnet partitioning."""

ProtocolId = str
"""Libp2p protocol identifier."""

PeerId = str
"""Libp2p peer identifier derived from the node's public key."""

Multiaddr = str
"""Multiaddress string, e.g. ``/ip4/192.168.1.1/tcp/9000``."""


class ResponseCode(IntEnum):
    """Response codes for request/response protocol messages."""

    SUCCESS = 0
    """Request processed successfully, response payload follows."""

    INVALID_REQUEST = 1
    """Malformed request or invalid parameters."""

    SERVER_ERROR = 2
    """Internal server error during processing."""

    RESOURCE_UNAVAILABLE = 3
    """Requested data not available (e.g., block not found)."""

    RATE_LIMITED = 4
    """Too many requests, client should back off."""


class DisconnectReason(IntEnum):
    """Reason codes for peer disconnection (sent in Goodbye messages)."""

    CLIENT_SHUTDOWN = 1
    """Node is shutting down normally."""

    IRRELEVANT_NETWORK = 2
    """Peer is on a different fork or network."""

    FAULT_OR_ERROR = 3
    """Generic error detected in peer communication."""

    UNABLE_TO_VERIFY = 128
    """Cannot verify peer's messages (e.g., bad signatures)."""

    TOO_MANY_PEERS = 129
    """Connection limit reached, pruning connections."""

    SCORE_TOO_LOW = 250
    """Peer behavior score dropped below threshold."""

    BANNED = 251
    """Peer has been banned due to malicious behavior."""


class PeerState(IntEnum):
    """Connection state machine for peer connections."""

    DISCONNECTED = auto()
    """No active connection to this peer."""

    CONNECTING = auto()
    """TCP/QUIC connection in progress."""

    CONNECTED = auto()
    """Transport established, awaiting protocol handshake."""

    HANDSHAKING = auto()
    """Exchanging Status messages with peer."""

    ACTIVE = auto()
    """Fully operational, can exchange all protocol messages."""

    DISCONNECTING = auto()
    """Graceful shutdown in progress (Goodbye sent/received)."""


class ValidationResult(IntEnum):
    """Result of validating a gossip message."""

    ACCEPT = auto()
    """Valid message: forward to mesh peers, no score penalty."""

    REJECT = auto()
    """Invalid message: do NOT forward, apply score penalty to sender."""

    IGNORE = auto()
    """Drop silently: do NOT forward, no penalty (e.g., duplicates)."""
