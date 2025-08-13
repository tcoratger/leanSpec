"""Defines the cryptographic constants for the XMSS specification."""

from ..koalabear import Fp

# =================================================================
# Core Scheme Configuration
# =================================================================

MESSAGE_LENGTH: int = 32
"""The length in bytes for all messages to be signed."""

LOG_LIFETIME: int = 32
"""The base-2 logarithm of the scheme's maximum lifetime."""

LIFETIME: int = 1 << LOG_LIFETIME
"""
The maximum number of epochs supported by this configuration.

An individual key pair can be active for a smaller sub-range.
"""

# =================================================================
# Target Sum WOTS Parameters
# =================================================================

DIMENSION: int = 64
"""The total number of hash chains, `v`."""

BASE: int = 8
"""The alphabet size for the digits of the encoded message."""

TARGET_SUM: int = 375
"""The required sum of all codeword chunks for a signature to be valid."""

CHUNK_SIZE: int = 3
"""The number of bits per chunk, calculated as ceil(log2(BASE))."""


# =================================================================
# Hash and Encoding Length Parameters (in field elements)
# =================================================================

PARAMETER_LEN: int = 5
"""
The length of the public parameter `P`.

It isused to specialize the hash function.
"""

HASH_LEN: int = 8
"""The output length of the main tweakable hash function."""

RAND_LEN: int = 7
"""The length of the randomness `rho` used during message encoding."""

TWEAK_LEN: int = 2
"""The length of a domain-separating tweak."""

MSG_LEN: int = 9
"""The length of a message after being encoded into field elements."""

MSG_HASH_LEN: int = 15
"""The output length of the hash function used to digest the message."""

CAPACITY: int = 9
"""The capacity of the Poseidon2 sponge, defining its security level."""


# =================================================================
# Domain Separator Prefixes for Tweaks
# =================================================================

TWEAK_PREFIX_CHAIN = Fp(value=0x00)
"""The unique prefix for tweaks used in Winternitz-style hash chains."""

TWEAK_PREFIX_TREE = Fp(value=0x01)
"""The unique prefix for tweaks used when hashing Merkle tree nodes."""

TWEAK_PREFIX_MESSAGE = Fp(value=0x02)
"""The unique prefix for tweaks used in the initial message hashing step."""
