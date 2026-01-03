"""
Networking Specification
========================

This module contains the complete networking stack specification for
the Lean Ethereum consensus protocol.

Submodules
----------

**types**: Core type definitions (DomainType, PeerId, ValidationResult, etc.)
**config**: Network configuration constants
**enr**: Ethereum Node Records (EIP-778)
**discovery**: Discovery v5 protocol
**gossipsub**: Publish/subscribe messaging
**reqresp**: Request/response protocols
**peer**: Peer management

Usage
-----

Import commonly used components directly::

    from lean_spec.subspecs.networking import (
        GossipsubMessage,
        GossipsubParameters,
        Status,
        PeerInfo,
    )

Or import from submodules for specific functionality::

    from lean_spec.subspecs.networking.enr import ENR, EnrKey
    from lean_spec.subspecs.networking.discovery import RoutingTable
"""

# Core configuration
from .config import (
    MAX_REQUEST_BLOCKS,
    MESSAGE_DOMAIN_INVALID_SNAPPY,
    MESSAGE_DOMAIN_VALID_SNAPPY,
)

# Discovery
from .discovery import DiscoveryConfig, KBucket, RoutingTable

# ENR
from .enr import ENR, EnrKey, Eth2Data

# Gossipsub
from .gossipsub import (
    GossipsubMessage,
    GossipsubParameters,
    GossipsubTopic,
    MessageId,
    PeerScore,
    PeerScoreParams,
    ScoreThresholds,
)

# Peer management
from .peer import PeerInfo, PeerManager, PeerManagerConfig

# Request/Response
from .reqresp import (
    BLOCKS_BY_ROOT_PROTOCOL_V1,
    GOODBYE_PROTOCOL_V1,
    METADATA_PROTOCOL_V1,
    PING_PROTOCOL_V1,
    STATUS_PROTOCOL_V1,
    BlocksByRootRequest,
    BlocksByRootResponse,
    Goodbye,
    Metadata,
    Ping,
    Status,
)

# Core types
from .types import (
    DisconnectReason,
    DomainType,
    ForkDigest,
    Multiaddr,
    NodeId,
    PeerId,
    PeerState,
    ProtocolId,
    ResponseCode,
    SeqNumber,
    SubnetId,
    ValidationResult,
)

__all__ = [
    # Configuration
    "MAX_REQUEST_BLOCKS",
    "MESSAGE_DOMAIN_INVALID_SNAPPY",
    "MESSAGE_DOMAIN_VALID_SNAPPY",
    # Types
    "DisconnectReason",
    "DomainType",
    "ForkDigest",
    "Multiaddr",
    "NodeId",
    "PeerId",
    "PeerState",
    "ProtocolId",
    "ResponseCode",
    "SeqNumber",
    "SubnetId",
    "ValidationResult",
    # Gossipsub
    "GossipsubMessage",
    "GossipsubParameters",
    "GossipsubTopic",
    "MessageId",
    "PeerScore",
    "PeerScoreParams",
    "ScoreThresholds",
    # Request/Response
    "BLOCKS_BY_ROOT_PROTOCOL_V1",
    "GOODBYE_PROTOCOL_V1",
    "METADATA_PROTOCOL_V1",
    "PING_PROTOCOL_V1",
    "STATUS_PROTOCOL_V1",
    "BlocksByRootRequest",
    "BlocksByRootResponse",
    "Goodbye",
    "Metadata",
    "Ping",
    "Status",
    # ENR
    "ENR",
    "EnrKey",
    "Eth2Data",
    # Discovery
    "DiscoveryConfig",
    "KBucket",
    "RoutingTable",
    # Peer management
    "PeerInfo",
    "PeerManager",
    "PeerManagerConfig",
]
