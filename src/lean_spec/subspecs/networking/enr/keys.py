"""
ENR Key Definitions (EIP-778)
=============================

Standard key names for Ethereum Node Records as defined in EIP-778.
Keys are sorted lexicographically in the record and must be unique.

Pre-defined Keys (EIP-778)
--------------------------

| Key       | Value                                   |
|-----------|----------------------------------------|
| id        | name of identity scheme, e.g. "v4"     |
| secp256k1 | compressed secp256k1 public key, 33 bytes |
| ip        | IPv4 address, 4 bytes                  |
| tcp       | TCP port, big endian integer           |
| udp       | UDP port, big endian integer           |
| ip6       | IPv6 address, 16 bytes                 |
| tcp6      | IPv6-specific TCP port                 |
| udp6      | IPv6-specific UDP port                 |

All keys except `id` are optional. A record without endpoint information
is still valid as long as its signature is valid.

Ethereum Extensions
-------------------

| Key       | Value                                   |
|-----------|----------------------------------------|
| eth2      | Fork digest + next fork info (16 bytes)|
| attnets   | Attestation subnet bitvector (8 bytes) |
| syncnets  | Sync committee subnet bitvector        |

References:
----------
- EIP-778: https://eips.ethereum.org/EIPS/eip-778
"""

from enum import Enum


class EnrKey(str, Enum):
    """
    Standard ENR key identifiers (EIP-778).

    Keys are stored as their string values in the RLP encoding.
    """

    # =========================================================================
    # EIP-778 Standard Keys
    # =========================================================================

    ID = "id"
    """Identity scheme name. REQUIRED. Currently only "v4" is defined."""

    SECP256K1 = "secp256k1"
    """Compressed secp256k1 public key (33 bytes). Required for "v4" scheme."""

    IP = "ip"
    """IPv4 address (4 bytes, network byte order)."""

    TCP = "tcp"
    """TCP port (big-endian integer)."""

    UDP = "udp"
    """UDP port for discovery (big-endian integer)."""

    IP6 = "ip6"
    """IPv6 address (16 bytes, network byte order)."""

    TCP6 = "tcp6"
    """IPv6-specific TCP port. If absent, `tcp` applies to both."""

    UDP6 = "udp6"
    """IPv6-specific UDP port. If absent, `udp` applies to both."""

    # =========================================================================
    # Ethereum Consensus Extensions
    # =========================================================================

    ETH2 = "eth2"
    """Ethereum consensus data: fork_digest(4) + next_fork_version(4) + next_fork_epoch(8)."""

    ATTNETS = "attnets"
    """Attestation subnet subscriptions (8 bytes = 64 bits)."""

    SYNCNETS = "syncnets"
    """Sync committee subnet subscriptions."""

    def __str__(self) -> str:
        """Return the key's string value for ENR encoding."""
        return self.value
