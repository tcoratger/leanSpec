"""XMSS tweakable hash test fixture.

Generates JSON test vectors for the tweakable-hash primitive that
underpins the XMSS signature scheme. Pins the digest for each
(parameter, tweak, message) input so clients can align bit-for-bit on
the hashing contract.
"""

from typing import Any, ClassVar

from lean_spec.subspecs.koalabear.field import Fp
from lean_spec.subspecs.xmss.constants import PROD_CONFIG, TEST_CONFIG
from lean_spec.subspecs.xmss.poseidon import PROD_POSEIDON, TEST_POSEIDON
from lean_spec.subspecs.xmss.tweak_hash import (
    ChainTweak,
    TreeTweak,
    TweakHasher,
)
from lean_spec.subspecs.xmss.types import HashDigestVector, Parameter
from lean_spec.types import Uint64

from .base import BaseConsensusFixture


def _parameter_from_decimals(values: list[str]) -> Parameter:
    """Build a Parameter vector from a list of decimal field-element strings."""
    return Parameter(data=[Fp(int(v)) for v in values])


def _digest_from_decimals(values: list[str]) -> HashDigestVector:
    """Build a HashDigestVector from a list of decimal field-element strings."""
    return HashDigestVector(data=[Fp(int(v)) for v in values])


def _digest_to_decimals(digest: HashDigestVector) -> list[str]:
    """Render a HashDigestVector as a list of decimal field-element strings."""
    return [str(fp.value) for fp in digest.data]


class TweakHashTest(BaseConsensusFixture):
    """Fixture for XMSS tweakable hash conformance.

    Each vector names the XMSS mode (test or prod), the tweak type, the
    tweak fields, the public parameter, and the ordered list of message
    digests fed to the hasher. The fixture runs the spec's TweakHasher
    and emits the resulting digest.

    JSON output: mode, tweakType, tweak, input, output.
    """

    format_name: ClassVar[str] = "tweak_hash"
    description: ClassVar[str] = "Tests XMSS tweakable hash outputs"

    mode: str
    """XMSS mode: test or prod."""

    tweak_type: str
    """Tweak shape: chain or tree."""

    tweak: dict[str, Any]
    """Tweak fields. Keys differ by tweak_type."""

    input: dict[str, Any]
    """Hasher input. Keys parameter (decimals) and messageParts (list of decimal lists)."""

    output: dict[str, Any] = {}
    """Computed digest as a list of decimal field-element strings."""

    def make_fixture(self) -> "TweakHashTest":
        """Run the spec's TweakHasher and produce the digest.

        Returns:
            A copy of this fixture with output populated.

        Raises:
            ValueError: If the mode or tweak type is unknown.
        """
        if self.mode == "test":
            hasher = TweakHasher(config=TEST_CONFIG, poseidon=TEST_POSEIDON)
        elif self.mode == "prod":
            hasher = TweakHasher(config=PROD_CONFIG, poseidon=PROD_POSEIDON)
        else:
            raise ValueError(f"Unknown XMSS mode: {self.mode}")

        if self.tweak_type == "chain":
            tweak = ChainTweak(
                epoch=Uint64(int(self.tweak["epoch"])),
                chain_index=int(self.tweak["chainIndex"]),
                step=int(self.tweak["step"]),
            )
        elif self.tweak_type == "tree":
            tweak = TreeTweak(
                level=int(self.tweak["level"]),
                index=Uint64(int(self.tweak["index"])),
            )
        else:
            raise ValueError(f"Unknown tweak type: {self.tweak_type}")

        parameter = _parameter_from_decimals(self.input["parameter"])
        message_parts = [_digest_from_decimals(part) for part in self.input["messageParts"]]

        digest = hasher.apply(parameter, tweak, message_parts)

        return self.model_copy(update={"output": {"digest": _digest_to_decimals(digest)}})
