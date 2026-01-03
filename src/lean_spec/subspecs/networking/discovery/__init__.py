"""
Discovery v5 Protocol Specification
===================================

This module specifies the Discovery v5 protocol used for peer discovery
in Ethereum consensus clients. Discovery v5 is a UDP-based protocol that
enables nodes to find peers on the network.

Protocol Overview
-----------------

Discovery v5 uses a Kademlia-like DHT for node discovery:

1. **Routing Table**: Nodes maintain a k-bucket routing table
2. **Node Lookup**: FINDNODE queries locate nodes near a target
3. **Topic Advertisement**: TALKREQ/TALKRESP for topic-based discovery

Message Types
-------------

- PING/PONG: Liveness checks
- FINDNODE/NODES: Node lookup
- TALKREQ/TALKRESP: Topic advertisement
- REGTOPIC/TICKET/REGCONFIRMATION: Topic registration

References:
----------
- Discovery v5 Specification: https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md
"""

from .config import DiscoveryConfig
from .messages import (
    FindNode,
    Nodes,
    Ping,
    Pong,
    TalkReq,
    TalkResp,
)
from .routing import KBucket, RoutingTable

__all__ = [
    "DiscoveryConfig",
    "FindNode",
    "KBucket",
    "Nodes",
    "Ping",
    "Pong",
    "RoutingTable",
    "TalkReq",
    "TalkResp",
]
