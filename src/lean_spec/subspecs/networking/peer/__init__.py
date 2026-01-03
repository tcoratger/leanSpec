"""
Peer Management Specification
=============================

This module specifies peer tracking, scoring, and connection management
for the Ethereum networking stack.

Overview
--------

The peer manager maintains information about all known and connected peers:

1. **Discovery**: Peers found via Discovery v5
2. **Connection**: Active libp2p connections
3. **Scoring**: Behavioral scoring for prioritization
4. **Lifecycle**: Connection state machine

Peer Information
----------------

For each peer, we track:
- Identity (PeerId, NodeId, ENR)
- Connection state
- Protocol metadata (Status, Metadata)
- Behavioral score
- Topic subscriptions
"""

from .info import PeerInfo
from .manager import PeerManager, PeerManagerConfig

__all__ = [
    "PeerInfo",
    "PeerManager",
    "PeerManagerConfig",
]
