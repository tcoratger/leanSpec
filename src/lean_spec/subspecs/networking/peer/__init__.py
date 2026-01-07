"""
Peer Module
===========

Minimal peer tracking for the Ethereum networking layer.

This module provides the foundation for managing peer connections.
It intentionally contains only the essential types - additional
functionality (scoring, subnet tracking, etc.) can be added as needed.

Exports
-------
PeerInfo
    Core data structure for tracking peer connection state.
Direction
    Enum indicating connection direction (inbound/outbound).
"""

from .info import Direction, PeerInfo

__all__ = [
    "Direction",
    "PeerInfo",
]
