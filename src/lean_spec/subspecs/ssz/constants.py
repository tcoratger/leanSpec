"""Constants defined in the SSZ specification."""

from __future__ import annotations

from typing import Final

BYTES_PER_CHUNK: Final = 32
"""Number of bytes per Merkle chunk."""

BITS_PER_BYTE: Final = 8
"""Number of bits per byte."""

BITS_PER_CHUNK: Final = BYTES_PER_CHUNK * BITS_PER_BYTE
"""Number of bits per Merkle chunk (256 bits)."""
