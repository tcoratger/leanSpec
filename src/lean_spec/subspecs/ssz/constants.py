"""Constants defined in the SSZ specification."""

from lean_spec.types.hash import Bytes32

BYTES_PER_CHUNK: int = 32
"""The number of bytes in a Merkle tree chunk."""

ZERO_HASH: Bytes32 = b"\x00" * BYTES_PER_CHUNK
"""A zero hash, used for padding in the Merkle tree."""
