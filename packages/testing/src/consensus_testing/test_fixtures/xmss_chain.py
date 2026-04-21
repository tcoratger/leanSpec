"""XMSS hash chain test fixture.

Generates JSON test vectors for the WOTS+ iterated hashing primitive
underlying XMSS. Each step applies the tweakable hash once, so pinning
start/intermediate/end digests lets clients verify chain traversal
without reconstructing the full signature.
"""

from typing import Any, ClassVar

from lean_spec.subspecs.koalabear.field import Fp
from lean_spec.subspecs.xmss.constants import PROD_CONFIG, TEST_CONFIG
from lean_spec.subspecs.xmss.poseidon import PROD_POSEIDON, TEST_POSEIDON
from lean_spec.subspecs.xmss.tweak_hash import TweakHasher
from lean_spec.subspecs.xmss.types import HashDigestVector, Parameter
from lean_spec.types import Uint64

from .base import BaseConsensusFixture


class XmssChainTest(BaseConsensusFixture):
    """Fixture for XMSS hash-chain conformance.

    Each vector names the XMSS mode, fixes the chain position, and
    supplies the starting digest. The fixture runs the spec's
    TweakHasher.hash_chain and emits the resulting digest.

    JSON output: mode, input, output.
    """

    format_name: ClassVar[str] = "xmss_chain"
    description: ClassVar[str] = "Tests XMSS WOTS+ hash chain intermediate digests"

    mode: str
    """XMSS mode: test or prod."""

    input: dict[str, Any]
    """Chain parameters: parameter, epoch, chainIndex, startStep, numSteps, startDigest."""

    output: dict[str, Any] = {}
    """Computed digest after the requested number of chain steps."""

    def make_fixture(self) -> "XmssChainTest":
        """Run the spec's hash_chain and produce the end-of-chain digest.

        Returns:
            A copy of this fixture with output populated.

        Raises:
            ValueError: If the mode is unknown.
        """
        if self.mode == "test":
            hasher = TweakHasher(config=TEST_CONFIG, poseidon=TEST_POSEIDON)
        elif self.mode == "prod":
            hasher = TweakHasher(config=PROD_CONFIG, poseidon=PROD_POSEIDON)
        else:
            raise ValueError(f"Unknown XMSS mode: {self.mode}")

        parameter = Parameter(data=[Fp(int(v)) for v in self.input["parameter"]])
        start_digest = HashDigestVector(data=[Fp(int(v)) for v in self.input["startDigest"]])
        epoch = Uint64(int(self.input["epoch"]))
        chain_index = int(self.input["chainIndex"])
        start_step = int(self.input["startStep"])
        num_steps = int(self.input["numSteps"])

        end_digest = hasher.hash_chain(
            parameter=parameter,
            epoch=epoch,
            chain_index=chain_index,
            start_step=start_step,
            num_steps=num_steps,
            start_digest=start_digest,
        )

        return self.model_copy(
            update={"output": {"endDigest": [str(fp.value) for fp in end_digest.data]}}
        )
