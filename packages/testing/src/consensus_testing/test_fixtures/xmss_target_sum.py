"""XMSS target-sum encoder test fixture.

Generates JSON test vectors for the Winternitz target-sum encoding
check. Each vector pins whether a given (parameter, epoch, rho,
message) combination produces a codeword that lies on the required
hypercube layer.
"""

from typing import Any, ClassVar

from lean_spec.subspecs.koalabear.field import Fp
from lean_spec.subspecs.xmss.constants import PROD_CONFIG, TEST_CONFIG
from lean_spec.subspecs.xmss.message_hash import PROD_MESSAGE_HASHER, TEST_MESSAGE_HASHER
from lean_spec.subspecs.xmss.target_sum import TargetSumEncoder
from lean_spec.subspecs.xmss.types import Parameter, Randomness
from lean_spec.types import Bytes32, Uint64

from .base import BaseConsensusFixture


class XmssTargetSumTest(BaseConsensusFixture):
    """Fixture for XMSS target-sum encoding conformance.

    Each vector names the XMSS mode and supplies the encoder inputs.
    The fixture reports whether the candidate codeword matches the
    target sum (acceptance), along with the codeword digits and their
    sum for diagnostic cross-check.

    JSON output: mode, input, output.
    """

    format_name: ClassVar[str] = "xmss_target_sum"
    description: ClassVar[str] = "Tests XMSS Winternitz target-sum acceptance"

    mode: str
    """XMSS mode: test or prod."""

    input: dict[str, Any]
    """Encoder input with keys parameter, epoch, rho, and message."""

    output: dict[str, Any] = {}
    """Encoder verdict: acceptance flag, digits, digit sum, and target sum."""

    def make_fixture(self) -> "XmssTargetSumTest":
        """Run the spec's target-sum encoder and produce its verdict.

        Returns:
            A copy of this fixture with output populated.

        Raises:
            ValueError: If the mode is unknown.
        """
        if self.mode == "test":
            encoder = TargetSumEncoder(config=TEST_CONFIG, message_hasher=TEST_MESSAGE_HASHER)
        elif self.mode == "prod":
            encoder = TargetSumEncoder(config=PROD_CONFIG, message_hasher=PROD_MESSAGE_HASHER)
        else:
            raise ValueError(f"Unknown XMSS mode: {self.mode}")

        parameter = Parameter(data=[Fp(int(v)) for v in self.input["parameter"]])
        rho = Randomness(data=[Fp(int(v)) for v in self.input["rho"]])
        epoch = Uint64(int(self.input["epoch"]))
        message_bytes = bytes.fromhex(self.input["message"].removeprefix("0x"))
        if len(message_bytes) != 32:
            raise ValueError(f"Message must be 32 bytes, got {len(message_bytes)}")
        message = Bytes32(message_bytes)

        # Run the candidate-codeword hash so the diagnostic output carries the
        # digits and their sum regardless of whether the target-sum check passes.
        candidate = encoder.message_hasher.apply(parameter, epoch, rho, message)
        verdict = encoder.encode(parameter, message, rho, epoch)
        target = int(encoder.config.TARGET_SUM)

        output: dict[str, Any]
        if candidate is None:
            output = {
                "accepted": False,
                "aborted": True,
                "digits": None,
                "digitSum": None,
                "targetSum": target,
            }
        else:
            digit_sum = int(sum(candidate))
            output = {
                "accepted": verdict is not None,
                "aborted": False,
                "digits": candidate,
                "digitSum": digit_sum,
                "targetSum": target,
            }

        return self.model_copy(update={"output": output})
