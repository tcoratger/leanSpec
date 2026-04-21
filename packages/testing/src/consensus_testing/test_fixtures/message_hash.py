"""XMSS message hash test fixture.

Generates JSON test vectors for the aborting hypercube encoding that
maps an XMSS message plus epoch randomness to a codeword (or None on
abort). Clients must reproduce the same codeword digits or the same
abort decision bit-for-bit.
"""

from typing import Any, ClassVar

from lean_spec.subspecs.koalabear.field import Fp
from lean_spec.subspecs.xmss.constants import PROD_CONFIG, TEST_CONFIG
from lean_spec.subspecs.xmss.message_hash import MessageHasher
from lean_spec.subspecs.xmss.poseidon import PROD_POSEIDON, TEST_POSEIDON
from lean_spec.subspecs.xmss.types import Parameter, Randomness
from lean_spec.types import Bytes32, Uint64

from .base import BaseConsensusFixture


class MessageHashTest(BaseConsensusFixture):
    """Fixture for XMSS message hash conformance.

    Each vector names the XMSS mode, provides the parameter, epoch,
    randomness, and message, and reports the resulting codeword. When
    the aborting decode rejects, the codeword field is null and an
    aborted flag signals the outcome.

    JSON output: mode, input, output.
    """

    format_name: ClassVar[str] = "message_hash"
    description: ClassVar[str] = "Tests XMSS aborting hypercube message-hash encoding"

    mode: str
    """XMSS mode: test or prod."""

    input: dict[str, Any]
    """Hasher input with keys parameter, epoch, rho, and message."""

    output: dict[str, Any] = {}
    """Computed codeword (or null when the aborting decode rejects)."""

    def make_fixture(self) -> "MessageHashTest":
        """Run the spec's MessageHasher and produce the codeword or abort signal.

        Returns:
            A copy of this fixture with output populated.

        Raises:
            ValueError: If the mode is unknown.
        """
        if self.mode == "test":
            hasher = MessageHasher(config=TEST_CONFIG, poseidon=TEST_POSEIDON)
        elif self.mode == "prod":
            hasher = MessageHasher(config=PROD_CONFIG, poseidon=PROD_POSEIDON)
        else:
            raise ValueError(f"Unknown XMSS mode: {self.mode}")

        parameter = Parameter(data=[Fp(int(v)) for v in self.input["parameter"]])
        rho = Randomness(data=[Fp(int(v)) for v in self.input["rho"]])
        epoch = Uint64(int(self.input["epoch"]))
        message_bytes = bytes.fromhex(self.input["message"].removeprefix("0x"))
        if len(message_bytes) != 32:
            raise ValueError(f"Message must be 32 bytes, got {len(message_bytes)}")
        message = Bytes32(message_bytes)

        codeword = hasher.apply(parameter, epoch, rho, message)

        output: dict[str, Any]
        if codeword is None:
            output = {"codeword": None, "aborted": True}
        else:
            output = {"codeword": codeword, "aborted": False}

        return self.model_copy(update={"output": output})
