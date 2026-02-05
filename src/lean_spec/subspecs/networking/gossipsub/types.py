"""Gossipsub Type Definitions"""

from __future__ import annotations

from lean_spec.types import Bytes20

type MessageId = Bytes20
"""20-byte message identifier.

Computed from message contents using SHA256::

    SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]

The domain byte distinguishes valid/invalid snappy compression.
"""


type TopicId = str
"""Topic string identifier.

Follows the Ethereum consensus format::

    /{prefix}/{fork_digest}/{topic_name}/{encoding}
"""


type Timestamp = float
"""Unix timestamp in seconds since epoch.

Used for:

- Message arrival times
- Peer activity tracking
- Seen cache expiry
"""
