"""
Core definition of the KoalaBear prime field Fp.
"""

from typing import Self
from pydantic import BaseModel, Field, field_validator, ConfigDict

# ==============================================================================
# Field Constants
#
# The prime is chosen because the cube map (x -> x^3) is an
# automorphism of the multiplicative group.
# ==============================================================================

# The KoalaBear Prime: P = 2^31 - 2^24 + 1
P: int = 2**31 - 2**24 + 1

# The number of bits in the prime P.
P_BITS: int = 31

# The largest integer n such that 2^n divides (P - 1).
#
# P - 1 = 2^24 * 127
TWO_ADICITY: int = 24

# A pre-computed list of 2^n-th roots of unity.
#
# The element at index `n` is a generator for the multiplicative subgroup of order 2^n.
TWO_ADIC_GENERATORS: list[int] = [
    0x1, 0x7f000000, 0x7e010002, 0x6832fe4a, 0x8dbd69c, 0xa28f031, 0x5c4a5b99, 0x29b75a80,
    0x17668b8a, 0x27ad539b, 0x334d48c7, 0x7744959c, 0x768fc6fa, 0x303964b2, 0x3e687d4d,
    0x45a60e61, 0x6e2f4d7a, 0x163bd499, 0x6c4a8a45, 0x143ef899, 0x514ddcad, 0x484ef19b,
    0x205d63c3, 0x68e7dd49, 0x6ac49f88,
]


# ==============================================================================
# Base Field Fp
#
# This class implements the finite field F_p where p is the KoalaBear prime.
# All arithmetic is performed modulo P.
# ==============================================================================

class Fp(BaseModel):
    """
    An element in the KoalaBear prime field F_p.
    """
    model_config = ConfigDict(frozen=True)

    value: int = Field(
        ge=0,
        lt=P,
        description="Field element value in the range [0, P)"
    )

    @field_validator('value', mode='before')
    @classmethod
    def reduce_modulo_p(cls, v: int) -> int:
        """Reduces an integer input modulo P before validation."""
        return v % P

    def __add__(self, other: Self) -> Self:
        """Field addition."""
        return self.__class__(value=self.value + other.value)

    def __sub__(self, other: Self) -> Self:
        """Field subtraction."""
        return self.__class__(value=self.value - other.value)

    def __neg__(self) -> Self:
        """Field negation."""
        return self.__class__(value=-self.value)

    def __mul__(self, other: Self) -> Self:
        """Field multiplication."""
        return self.__class__(value=self.value * other.value)

    def __pow__(self, exponent: int) -> Self:
        """Field exponentiation."""
        return self.__class__(value=pow(self.value, exponent, P))

    def inverse(self) -> Self:
        """Computes the multiplicative inverse using Fermat's Little Theorem."""
        if self.value == 0:
            raise ZeroDivisionError("Cannot invert the zero element.")
        # a^(P-2) is the multiplicative inverse of a in F_p
        return self ** (P - 2)

    def __truediv__(self, other: Self) -> Self:
        """Field division."""
        return self * other.inverse()

    @classmethod
    def two_adic_generator(cls, bits: int) -> Self:
        """
        Get a generator for the multiplicative subgroup of order 2^bits.

        This is a direct lookup from a pre-computed list of generators.

        Args:
            bits: The order of the subgroup will be 2^bits. Must be in [0, TWO_ADICITY].

        Returns:
            A generator of the multiplicative subgroup of order 2^bits.

        Raises:
            ValueError: If `bits` is outside the valid range.
        """
        if not (0 <= bits <= TWO_ADICITY):
            raise ValueError(f"bits must be between 0 and {TWO_ADICITY}")
        return cls(value=TWO_ADIC_GENERATORS[bits])
