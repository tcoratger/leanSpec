"""Gossipsub Type Definitions"""

from __future__ import annotations

from typing import TypeAlias

from lean_spec.types import Bytes20

MessageId: TypeAlias = Bytes20
"""20-byte message identifier.

Computed from message contents using SHA256::

    SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]

The domain byte distinguishes valid/invalid snappy compression.
"""


PeerId: TypeAlias = str
"""Libp2p peer identifier.

Derived from the peer's public key as a base58-encoded multihash.
Uniquely identifies peers in the P2P network.
"""


TopicId: TypeAlias = str
"""Topic string identifier.

Follows the Ethereum consensus format::

    /{prefix}/{fork_digest}/{topic_name}/{encoding}
"""


Timestamp: TypeAlias = float
"""Unix timestamp in seconds since epoch.

Used for:

- Message arrival times
- Peer activity tracking
- Seen cache expiry
"""
