"""Poseidon permutation test fixture."""

from typing import Any, ClassVar

from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.poseidon import PARAMS_16, PARAMS_24, Poseidon


class PoseidonPermutationFixture(BaseConsensusFixture):
    """
    Emitted vector for Poseidon permutation conformance.

    JSON output: width, input, output.
    """

    width: int
    """State width of the permutation."""

    input: dict[str, Any]
    """Input state as decimal element strings."""

    output: dict[str, Any]
    """Computed output state as decimal element strings."""


class PoseidonPermutationTest(BaseTestSpec):
    """
    Spec for Poseidon permutation conformance.

    Each vector names the permutation width and supplies an input state
    as decimal strings. Generation runs the spec's permutation engine
    and emits the output state as decimal strings.
    """

    format_name: ClassVar[str] = "poseidon_permutation_test"
    description: ClassVar[str] = "Tests Poseidon permutation at widths 16 and 24"

    width: int
    """State width. Must be 16 or 24."""

    input: dict[str, Any]
    """Input state. Key inputState holds a list of decimal element strings."""

    def generate(self) -> PoseidonPermutationFixture:
        """
        Run the Poseidon permutation and produce the output state.

        Returns:
            The emitted vector with output populated.

        Raises:
            ValueError: If the width is unsupported.
        """
        if self.width == 16:
            engine = Poseidon(PARAMS_16)
        elif self.width == 24:
            engine = Poseidon(PARAMS_24)
        else:
            raise ValueError(f"Unsupported Poseidon width: {self.width}")

        state_ints = [int(raw_element) for raw_element in self.input["inputState"]]
        if len(state_ints) != self.width:
            raise ValueError(
                f"Input state length {len(state_ints)} does not match width {self.width}"
            )

        input_state = [Fp(state_int) for state_int in state_ints]
        output_state = engine.permute(input_state)

        return PoseidonPermutationFixture(
            width=self.width,
            input=self.input,
            output={"outputState": [str(int(fp)) for fp in output_state]},
        )
