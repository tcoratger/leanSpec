"""Networking Configuration Constants."""

from __future__ import annotations

from typing import Final

from .types import DomainType

MAX_REQUEST_BLOCKS: Final[int] = 2**10
"""Maximum number of blocks in a single request (1024)."""

MAX_PAYLOAD_SIZE: Final[int] = 10 * 1024 * 1024
"""Maximum uncompressed payload size in bytes (10 MiB)."""

TTFB_TIMEOUT: Final[float] = 5.0
"""Time-to-first-byte timeout.

Maximum time to wait for the first byte of a response after sending a request.
If no data arrives within this window, the request is considered failed.
"""

RESP_TIMEOUT: Final[float] = 10.0
"""Response timeout.

Maximum total time to receive a complete response. This covers the entire
response, including all chunks for multi-part responses like BlocksByRange.
"""

MESSAGE_DOMAIN_INVALID_SNAPPY: Final[DomainType] = DomainType(b"\x00")
"""1-byte domain for gossip message-id isolation of invalid snappy messages.

Per Ethereum spec, prepended to the message hash when decompression fails.
"""

MESSAGE_DOMAIN_VALID_SNAPPY: Final[DomainType] = DomainType(b"\x01")
"""1-byte domain for gossip message-id isolation of valid snappy messages.

Per Ethereum spec, prepended to the message hash when decompression succeeds.
"""

GOSSIPSUB_PROTOCOL_ID_V11: Final[str] = "/meshsub/1.1.0"
"""Gossipsub v1.1 protocol ID - peer scoring, extended validators.

This is the minimum version required by the Ethereum consensus spec.
"""

GOSSIPSUB_PROTOCOL_ID_V12: Final[str] = "/meshsub/1.2.0"
"""Gossipsub v1.2 protocol ID - IDONTWANT bandwidth optimization."""

GOSSIPSUB_DEFAULT_PROTOCOL_ID: Final[str] = GOSSIPSUB_PROTOCOL_ID_V11
"""
Default protocol ID per Ethereum consensus spec requirements.

The Ethereum consensus P2P spec states:
"Clients MUST support the gossipsub v1 libp2p Protocol including the gossipsub v1.1 extension."
"""

PRUNE_BACKOFF: Final[int] = 60
"""Default PRUNE backoff duration in seconds.

When a peer is pruned from the mesh, they must wait this duration
before attempting to re-graft. This prevents rapid mesh churn.
"""

MAX_ERROR_MESSAGE_SIZE: Final[int] = 256
"""Maximum error message size in bytes per Ethereum P2P spec (ErrorMessage: List[byte, 256])."""
