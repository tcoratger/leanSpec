"""XMSS PRF test fixture.

Generates JSON test vectors for the SHAKE128-based PRF that XMSS uses
to derive hash-chain starting digests and signing randomness from a
master secret. Pins both PRF modes so clients align on the deterministic
key schedule.
"""

from typing import Any, ClassVar

from lean_spec.subspecs.xmss.constants import PROD_CONFIG, TEST_CONFIG
from lean_spec.subspecs.xmss.prf import Prf
from lean_spec.subspecs.xmss.types import PRFKey
from lean_spec.types import Bytes32, Uint64

from .base import BaseConsensusFixture


class XmssPrfTest(BaseConsensusFixture):
    """Fixture for XMSS PRF conformance.

    Each vector names the XMSS mode and the PRF role (chain start or
    randomness). The fixture runs the spec's PRF and emits the output
    as decimal field-element strings.

    JSON output: mode, role, input, output.
    """

    format_name: ClassVar[str] = "xmss_prf"
    description: ClassVar[str] = "Tests XMSS SHAKE128-based PRF outputs"

    mode: str
    """XMSS mode: test or prod."""

    role: str
    """PRF role: chain_start or randomness."""

    input: dict[str, Any]
    """PRF input; keys depend on role."""

    output: dict[str, Any] = {}
    """Computed PRF output as a list of decimal Fp strings."""

    def make_fixture(self) -> "XmssPrfTest":
        """Run the spec's PRF and produce the derived output.

        Returns:
            A copy of this fixture with output populated.

        Raises:
            ValueError: If mode or role is unknown.
        """
        if self.mode == "test":
            prf = Prf(config=TEST_CONFIG)
        elif self.mode == "prod":
            prf = Prf(config=PROD_CONFIG)
        else:
            raise ValueError(f"Unknown XMSS mode: {self.mode}")

        key_bytes = bytes.fromhex(self.input["key"].removeprefix("0x"))
        key = PRFKey(key_bytes)

        if self.role == "chain_start":
            epoch = Uint64(int(self.input["epoch"]))
            chain_index = Uint64(int(self.input["chainIndex"]))
            digest = prf.apply(key, epoch, chain_index)
            output = {"fieldElements": [str(fp.value) for fp in digest.data]}
        elif self.role == "randomness":
            epoch = Uint64(int(self.input["epoch"]))
            message_bytes = bytes.fromhex(self.input["message"].removeprefix("0x"))
            message = Bytes32(message_bytes)
            counter = Uint64(int(self.input["counter"]))
            randomness = prf.get_randomness(key, epoch, message, counter)
            output = {"fieldElements": [str(fp.value) for fp in randomness.data]}
        else:
            raise ValueError(f"Unknown PRF role: {self.role}")

        return self.model_copy(update={"output": output})
