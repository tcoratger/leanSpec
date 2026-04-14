"""SSZ test fixture format for serialization conformance testing."""

from typing import Any, ClassVar

from pydantic import field_serializer

from lean_spec.subspecs.koalabear.field import Fp
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types.base import CamelModel
from lean_spec.types.boolean import Boolean
from lean_spec.types.ssz_base import SSZType

from .base import BaseConsensusFixture


class SSZTest(BaseConsensusFixture):
    """Fixture for SSZ conformance testing.

    Verifies roundtrip serialization and Merkleization for any SSZ type.

    JSON output: typeName, value, serialized, root.
    """

    format_name: ClassVar[str] = "ssz"
    description: ClassVar[str] = "Tests SSZ serialization roundtrip and hash_tree_root"

    type_name: str
    """SSZ type class name."""

    value: SSZType
    """The SSZ value under test."""

    serialized: str = ""
    """Hex SSZ bytes. Empty until fixture generation fills it."""

    root: str = ""
    """Hex hash_tree_root. Empty until fixture generation fills it."""

    @field_serializer("value", when_used="json")
    def serialize_value(self, value: SSZType) -> Any:
        """Convert an SSZ value to a JSON-safe representation."""
        if isinstance(value, CamelModel):
            return value.to_json()
        # Boolean before int — Boolean subclasses int.
        if isinstance(value, Boolean):
            return bool(value)
        if isinstance(value, bytes):
            return "0x" + value.hex()
        if isinstance(value, int):
            return str(value)
        if isinstance(value, Fp):
            return str(value.value)
        return str(value)

    def make_fixture(self) -> "SSZTest":
        """Verify SSZ roundtrip and produce the reference encoding and root.

        Returns:
            A copy of this fixture with serialized and root populated.

        Raises:
            AssertionError: If decode(encode(value)) != value.
        """
        ssz_bytes = self.value.encode_bytes()
        decoded = self.value.decode_bytes(ssz_bytes)

        assert decoded == self.value, (
            f"SSZ roundtrip failed for {self.type_name}: "
            f"original != decoded\n"
            f"Original: {self.value}\n"
            f"Decoded: {decoded}"
        )

        root = hash_tree_root(self.value)

        return self.model_copy(
            update={
                "serialized": "0x" + ssz_bytes.hex(),
                "root": "0x" + root.hex(),
            }
        )
