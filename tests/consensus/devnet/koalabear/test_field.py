"""KoalaBear field arithmetic: known-answer test vectors.

The prime modulus is P = 2^31 - 2^24 + 1 = 2130706433. Every field
element lives in [0, P). Vectors pin add, sub, mul, pow, negate,
inverse, and the 4-byte little-endian serialization so clients can
cross-check bit-for-bit.
"""

import pytest
from consensus_testing import FieldArithmeticTestFiller

from lean_spec.subspecs.koalabear.field import P

pytestmark = pytest.mark.valid_until("Devnet")


def test_add_zero_plus_zero(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """0 + 0 in the field."""
    field_arithmetic(operation="add", input={"a": "0", "b": "0"})


def test_add_one_plus_one(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """1 + 1 in the field."""
    field_arithmetic(operation="add", input={"a": "1", "b": "1"})


def test_add_p_minus_one_plus_one_wraps(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """(P - 1) + 1 wraps to zero under modular addition."""
    field_arithmetic(operation="add", input={"a": str(P - 1), "b": "1"})


def test_add_p_minus_one_plus_p_minus_one(
    field_arithmetic: FieldArithmeticTestFiller,
) -> None:
    """(P - 1) + (P - 1) sits just under 2P, reducing to P - 2."""
    field_arithmetic(operation="add", input={"a": str(P - 1), "b": str(P - 1)})


def test_sub_zero_minus_one_wraps(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """0 - 1 wraps to P - 1 under modular subtraction."""
    field_arithmetic(operation="sub", input={"a": "0", "b": "1"})


def test_mul_two_times_p_minus_one(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """2 * (P - 1) lies just below 2P and reduces to P - 2."""
    field_arithmetic(operation="mul", input={"a": "2", "b": str(P - 1)})


def test_mul_p_minus_one_squared(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """(P - 1)^2 exercises the widest intermediate before modular reduction."""
    field_arithmetic(operation="mul", input={"a": str(P - 1), "b": str(P - 1)})


def test_negate_zero_is_zero(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """Negation of zero returns zero."""
    field_arithmetic(operation="negate", input={"a": "0"})


def test_negate_one_is_p_minus_one(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """Negation of one returns P - 1."""
    field_arithmetic(operation="negate", input={"a": "1"})


def test_pow_base_zero_exponent_zero(
    field_arithmetic: FieldArithmeticTestFiller,
) -> None:
    """0^0 conventionally evaluates to 1 under the field's pow implementation."""
    field_arithmetic(operation="pow", input={"base": "0", "exponent": 0})


def test_pow_two_cubed(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """2^3 returns 8 and fits well within the field."""
    field_arithmetic(operation="pow", input={"base": "2", "exponent": 3})


def test_pow_p_minus_one_to_two(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """(P - 1)^2 via pow matches (P - 1) * (P - 1) via mul."""
    field_arithmetic(operation="pow", input={"base": str(P - 1), "exponent": 2})


def test_inverse_of_one_is_one(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """The multiplicative inverse of 1 is 1."""
    field_arithmetic(operation="inverse", input={"a": "1"})


def test_inverse_of_p_minus_one(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """(P - 1) is its own inverse since (P - 1) * (P - 1) = 1 mod P."""
    field_arithmetic(operation="inverse", input={"a": str(P - 1)})


def test_inverse_of_zero_is_rejected(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """Inverting zero must raise ZeroDivisionError rather than return a value."""
    field_arithmetic(
        operation="inverse",
        input={"a": "0"},
        expect_exception=ZeroDivisionError,
    )


def test_serialize_zero(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """Zero encodes as four zero bytes in little-endian order."""
    field_arithmetic(operation="serialize", input={"value": "0"})


def test_serialize_one(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """One encodes as 0x01 0x00 0x00 0x00."""
    field_arithmetic(operation="serialize", input={"value": "1"})


def test_serialize_p_minus_one(field_arithmetic: FieldArithmeticTestFiller) -> None:
    """P - 1 encodes with the widest representable little-endian payload."""
    field_arithmetic(operation="serialize", input={"value": str(P - 1)})
