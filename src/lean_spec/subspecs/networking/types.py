"""Networking Types"""

from enum import IntEnum, auto

from lean_spec.types import Uint64
from lean_spec.types.byte_arrays import Bytes1, Bytes4, Bytes32


class DomainType(Bytes1):
    """1-byte domain for message-id isolation in Gossipsub.

    The domain is a single byte prepended to the message hash to compute the gossip message ID.

    - Valid messages use 0x01,
    - Invalid messages use 0x00.
    """


class NodeId(Bytes32):
    """32-byte node identifier for Discovery v5, derived from ``keccak256(pubkey)``."""


class ForkDigest(Bytes4):
    """4-byte fork identifier ensuring network isolation between forks."""


class Version(Bytes4):
    """4-byte fork version number (e.g., 0x01000000 for Phase0)."""


class SeqNumber(Uint64):
    """Sequence number used in ENR records, metadata, and ping messages."""


ProtocolId = str
"""Libp2p protocol identifier, e.g. ``/eth2/beacon_chain/req/status/1/ssz_snappy``."""

Multiaddr = str
"""Multiaddress string, e.g. ``/ip4/192.168.1.1/udp/9000/quic-v1``."""


class Direction(IntEnum):
    """
    Direction of a peer connection.

    Indicates whether:
        - we initiated the connection (outbound) or
        - the peer connected to us (inbound).
    """

    INBOUND = auto()
    """Peer initiated the connection to us."""

    OUTBOUND = auto()
    """We initiated the connection to the peer."""


class ConnectionState(IntEnum):
    """
    Peer connection state machine.

    Tracks the lifecycle of a connection to a peer::

        DISCONNECTED -> CONNECTING -> CONNECTED -> DISCONNECTING -> DISCONNECTED

    These states map directly to libp2p connection events.
    """

    DISCONNECTED = auto()
    """No active connection to this peer."""

    CONNECTING = auto()
    """QUIC connection in progress."""

    CONNECTED = auto()
    """Transport established, can exchange protocol messages."""

    DISCONNECTING = auto()
    """Graceful shutdown in progress (Goodbye sent/received)."""
