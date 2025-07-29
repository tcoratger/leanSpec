"""
Tests for the KoalaBear prime field Fp.
"""

import pytest
from lean_spec.subspecs.koalabear.field import Fp, P, TWO_ADICITY, TWO_ADIC_GENERATORS

def test_constants():
    """Verify field constants."""
    assert P == 2**31 - 2**24 + 1
    assert (P - 1) % (2**TWO_ADICITY) == 0
    assert (P - 1) % (2**(TWO_ADICITY + 1)) != 0
    assert len(TWO_ADIC_GENERATORS) == TWO_ADICITY + 1

def test_base_field_arithmetic():
    """Test basic arithmetic, equality, and error handling in the base field Fp."""
    a = Fp(5)
    b = Fp(10)

    # Test operations
    assert a + b == Fp(15)
    assert b - a == Fp(5)
    assert -a == Fp(P - 5)
    assert a * b == Fp(50)
    assert a / b == Fp(5) * Fp(10).inverse()

    # Test equality against the same and different types
    assert a == Fp(5)
    assert a != b
    assert (a == 5) is False
    assert (a != "5") is True

    # Test error on inverting the zero element
    with pytest.raises(ZeroDivisionError, match="Cannot invert the zero element."):
        Fp(0).inverse()

def test_two_adicity():
    """Test the properties of the two-adic generators."""
    # Test a generator for a subgroup of order 2^bits
    bits = 4  # 2^4 = 16
    gen = Fp.two_adic_generator(bits)
    assert gen == Fp(TWO_ADIC_GENERATORS[bits])

    # Check that the generator has the correct order
    assert gen ** (2**bits) == Fp(1)
    assert gen ** (2**(bits - 1)) != Fp(1)

    # Check relationship between generators
    # g_n^2 should equal g_{n-1}
    gen_n = Fp.two_adic_generator(TWO_ADICITY)
    gen_n_minus_1 = Fp.two_adic_generator(TWO_ADICITY - 1)
    assert gen_n**2 == gen_n_minus_1

    # The largest order generator should square to -1
    assert gen_n ** (2**(TWO_ADICITY - 1)) == Fp(-1)

    # Test error handling for out-of-bounds input
    with pytest.raises(ValueError, match=f"bits must be between 0 and {TWO_ADICITY}"):
        Fp.two_adic_generator(TWO_ADICITY + 1)

    with pytest.raises(ValueError, match=f"bits must be between 0 and {TWO_ADICITY}"):
        Fp.two_adic_generator(-1)
