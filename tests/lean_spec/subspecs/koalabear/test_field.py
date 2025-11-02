"""
Tests for the KoalaBear prime field Fp.
"""

import pytest

from lean_spec.subspecs.koalabear.field import (
    TWO_ADIC_GENERATORS,
    TWO_ADICITY,
    Fp,
    P,
)


def test_constants() -> None:
    """Verify field constants."""
    assert P == 2**31 - 2**24 + 1
    assert (P - 1) % (2**TWO_ADICITY) == 0
    assert (P - 1) % (2 ** (TWO_ADICITY + 1)) != 0
    assert len(TWO_ADIC_GENERATORS) == TWO_ADICITY + 1


def test_base_field_arithmetic() -> None:
    """
    Test basic arithmetic, equality, and error handling
    in the base field Fp.
    """
    a = Fp(value=5)
    b = Fp(value=10)

    # Test operations
    assert a + b == Fp(value=15)
    assert b - a == Fp(value=5)
    assert -a == Fp(value=P - 5)
    assert a * b == Fp(value=50)
    assert a / b == Fp(value=5) * Fp(value=10).inverse()

    # Test equality against the same and different types
    assert a == Fp(value=5)
    assert a != b
    assert a != 5  # type: ignore[comparison-overlap]
    assert a != "5"  # type: ignore[comparison-overlap]

    # Test error on inverting the zero element
    with pytest.raises(ZeroDivisionError, match="Cannot invert the zero element."):
        Fp(value=0).inverse()


def test_two_adicity() -> None:
    """Test the properties and error handling of the two-adic generators."""
    bits = 4  # 2^4 = 16
    gen = Fp.two_adic_generator(bits)
    assert gen == Fp(value=TWO_ADIC_GENERATORS[bits])

    # Check that the generator has the correct order
    assert gen ** (2**bits) == Fp(value=1)
    assert gen ** (2 ** (bits - 1)) != Fp(value=1)

    # Check relationship between generators: g_n^2 should equal g_{n-1}
    gen_n = Fp.two_adic_generator(TWO_ADICITY)
    gen_n_minus_1 = Fp.two_adic_generator(TWO_ADICITY - 1)
    assert gen_n**2 == gen_n_minus_1

    # The largest order generator should square to -1
    assert gen_n ** (2 ** (TWO_ADICITY - 1)) == Fp(value=-1)

    # Test error handling for out-of-bounds input
    with pytest.raises(ValueError, match=f"bits must be between 0 and {TWO_ADICITY}"):
        Fp.two_adic_generator(TWO_ADICITY + 1)

    with pytest.raises(ValueError, match=f"bits must be between 0 and {TWO_ADICITY}"):
        Fp.two_adic_generator(-1)


def test_bytes_protocol() -> None:
    """Test serialization using Python's bytes protocol."""
    # Test basic serialization
    fp = Fp(value=42)
    data = bytes(fp)
    assert len(data) == 4  # P_BYTES
    assert isinstance(data, bytes)

    # Test deserialization
    recovered = Fp.from_bytes(data)
    assert recovered == fp

    # Test round-trip for various values
    test_values = [0, 1, 42, 1000, P - 1]
    for value in test_values:
        fp = Fp(value=value)
        assert Fp.from_bytes(bytes(fp)) == fp

    # Test error handling for invalid data length
    with pytest.raises(ValueError, match="Expected 4 bytes, got 3"):
        Fp.from_bytes(b"\x01\x02\x03")

    with pytest.raises(ValueError, match="Expected 4 bytes, got 5"):
        Fp.from_bytes(b"\x01\x02\x03\x04\x05")

    # Test error handling for values exceeding the modulus
    invalid_data = P.to_bytes(4, byteorder="little")
    with pytest.raises(ValueError, match="exceeds field modulus"):
        Fp.from_bytes(invalid_data)


def test_serialize_list() -> None:
    """Test serialization of field element lists."""
    # Test empty list
    elements: list[Fp] = []
    data = Fp.serialize_list(elements)
    assert data == b""
    assert len(data) == 0

    # Test single element
    elements = [Fp(value=42)]
    data = Fp.serialize_list(elements)
    assert len(data) == 4
    assert data == bytes(Fp(value=42))

    # Test multiple elements
    elements = [Fp(value=1), Fp(value=2), Fp(value=3)]
    data = Fp.serialize_list(elements)
    assert len(data) == 12  # 3 * 4 bytes
    assert data == bytes(Fp(value=1)) + bytes(Fp(value=2)) + bytes(Fp(value=3))

    # Test round-trip
    recovered = Fp.deserialize_list(data, 3)
    assert recovered == elements


def test_deserialize_list() -> None:
    """Test deserialization of field element lists."""
    # Test empty list
    data = b""
    recovered = Fp.deserialize_list(data, 0)
    assert recovered == []

    # Test single element
    elements = [Fp(value=42)]
    data = Fp.serialize_list(elements)
    recovered = Fp.deserialize_list(data, 1)
    assert recovered == elements

    # Test multiple elements
    elements = [Fp(value=10), Fp(value=20), Fp(value=30), Fp(value=40)]
    data = Fp.serialize_list(elements)
    recovered = Fp.deserialize_list(data, 4)
    assert recovered == elements

    # Test error handling for incorrect length
    with pytest.raises(ValueError, match="Expected 8 bytes for 2 elements, got 4"):
        Fp.deserialize_list(b"\x01\x02\x03\x04", 2)

    with pytest.raises(ValueError, match="Expected 12 bytes for 3 elements, got 10"):
        Fp.deserialize_list(b"\x01" * 10, 3)


def test_serialize_list_roundtrip_property() -> None:
    """Property test: serialization round-trip should preserve values."""
    import random

    random.seed(42)

    for _ in range(100):
        # Generate random list of field elements
        count = random.randint(0, 20)
        elements = [Fp(value=random.randint(0, P - 1)) for _ in range(count)]

        # Round-trip
        data = Fp.serialize_list(elements)
        recovered = Fp.deserialize_list(data, count)

        assert recovered == elements
        assert len(data) == count * 4
