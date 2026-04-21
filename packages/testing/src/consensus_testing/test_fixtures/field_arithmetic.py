"""KoalaBear field arithmetic test fixture.

Generates JSON test vectors for add, sub, mul, pow, inverse, negate, and
serialization roundtrip on the KoalaBear prime field. Clients must
reproduce identical outputs bit-for-bit.
"""

from typing import Any, ClassVar

from lean_spec.subspecs.koalabear.field import Fp

from .base import BaseConsensusFixture


def _decimal(value: int) -> str:
    """Format an integer as a decimal string (avoids JSON precision loss)."""
    return str(value)


def _to_hex(data: bytes) -> str:
    """Format raw bytes as a 0x-prefixed hex string."""
    return "0x" + data.hex()


def _from_hex(hex_str: str) -> bytes:
    """Parse a 0x-prefixed hex string into raw bytes."""
    return bytes.fromhex(hex_str.removeprefix("0x"))


class FieldArithmeticTest(BaseConsensusFixture):
    """Fixture for KoalaBear field arithmetic conformance.

    Each vector names an operation, supplies decimal operands, and
    reports the computed result. Serialization vectors additionally
    report the 4-byte little-endian byte encoding.

    JSON output: operation, input, output.
    """

    format_name: ClassVar[str] = "field_arithmetic"
    description: ClassVar[str] = "Tests KoalaBear prime-field arithmetic operations"

    operation: str
    """Field operation: add, sub, mul, pow, inverse, negate, or serialize."""

    input: dict[str, Any]
    """Operation-specific input parameters. See per-handler docstrings."""

    output: dict[str, Any] = {}
    """Computed output. Filled by make_fixture."""

    def make_fixture(self) -> "FieldArithmeticTest":
        """Dispatch to the operation handler and produce the computed output.

        Returns:
            A copy of this fixture with output populated.

        Raises:
            AssertionError: If the decode-failure path is triggered and the
                expected exception does not match.
            ValueError: If the operation name is unknown.
        """
        match self.operation:
            case "add":
                output = self._binary_op("+")
            case "sub":
                output = self._binary_op("-")
            case "mul":
                output = self._binary_op("*")
            case "pow":
                output = self._make_pow()
            case "inverse":
                output = self._make_inverse()
            case "negate":
                output = self._make_negate()
            case "serialize":
                output = self._make_serialize()
            case _:
                raise ValueError(f"Unknown operation: {self.operation}")
        return self.model_copy(update={"output": output})

    def _binary_op(self, op: str) -> dict[str, Any]:
        """Evaluate one of the binary field operations on the supplied operands.

        Input keys ``a`` and ``b`` are decimal strings representing field
        elements. The computed result is emitted as a decimal string.
        """
        a = Fp(int(self.input["a"]))
        b = Fp(int(self.input["b"]))
        if op == "+":
            result = a + b
        elif op == "-":
            result = a - b
        elif op == "*":
            result = a * b
        else:
            raise ValueError(f"Unknown binary operation: {op}")
        return {"result": _decimal(result.value)}

    def _make_pow(self) -> dict[str, Any]:
        """Exponentiate a field element by a non-negative integer exponent.

        Input keys ``base`` (decimal) and ``exponent`` (integer).
        """
        base = Fp(int(self.input["base"]))
        exponent = int(self.input["exponent"])
        result = base**exponent
        return {"result": _decimal(result.value)}

    def _make_inverse(self) -> dict[str, Any]:
        """Compute the multiplicative inverse.

        Supports the decode-failure path: when ``expect_exception`` is set
        the fixture asserts the inversion raises rather than returning.
        """
        a = Fp(int(self.input["a"]))
        if self.expect_exception is not None:
            raised: Exception | None = None
            try:
                a.inverse()
            except Exception as exc:
                raised = exc
            if raised is None:
                raise AssertionError(
                    f"Expected {self.expect_exception.__name__} from inverse of {a.value}"
                )
            if not isinstance(raised, self.expect_exception):
                raise AssertionError(
                    f"Expected {self.expect_exception.__name__} but got "
                    f"{type(raised).__name__}: {raised}"
                )
            return {"errorType": type(raised).__name__, "errorMessage": str(raised)}
        result = a.inverse()
        return {"result": _decimal(result.value)}

    def _make_negate(self) -> dict[str, Any]:
        """Compute the additive inverse."""
        a = Fp(int(self.input["a"]))
        result = -a
        return {"result": _decimal(result.value)}

    def _make_serialize(self) -> dict[str, Any]:
        """Emit the 4-byte little-endian encoding and roundtrip-decode back to the value."""
        a = Fp(int(self.input["value"]))
        encoded = a.encode_bytes()
        decoded = Fp.decode_bytes(encoded)
        assert decoded.value == a.value, "Fp encode roundtrip produced different value"
        return {"encoded": _to_hex(encoded), "byteLength": len(encoded)}
