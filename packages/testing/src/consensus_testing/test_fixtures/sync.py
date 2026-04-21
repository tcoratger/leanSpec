"""Sync layer test fixture format.

Emits JSON vectors for the client-facing sync helpers. Each vector
pins the expected verdict on a given input so clients can align their
sync-layer decisions bit-for-bit.
"""

from typing import Any, ClassVar

from lean_spec.subspecs.sync.checkpoint_sync import verify_checkpoint_state
from lean_spec.types import Uint64

from ..genesis import generate_pre_state
from .base import BaseConsensusFixture


class SyncTest(BaseConsensusFixture):
    """Fixture for sync-layer conformance.

    Currently supports one operation:

    - ``verify_checkpoint``: emits the SSZ-encoded anchor state plus the
      verification verdict a client must produce.

    JSON output: operation, input, output.
    """

    format_name: ClassVar[str] = "sync"
    description: ClassVar[str] = "Tests sync-layer helpers clients must reproduce"

    operation: str
    """Sync operation: currently only verify_checkpoint."""

    input: dict[str, Any]
    """Operation-specific input. See per-handler docstrings."""

    output: dict[str, Any] = {}
    """Computed output. Filled by make_fixture."""

    def make_fixture(self) -> "SyncTest":
        """Dispatch to the operation handler.

        Returns:
            A copy of this fixture with output populated.

        Raises:
            ValueError: If the operation name is unknown.
        """
        if self.operation == "verify_checkpoint":
            output = self._make_verify_checkpoint()
        else:
            raise ValueError(f"Unknown sync operation: {self.operation!r}")
        return self.model_copy(update={"output": output})

    def _make_verify_checkpoint(self) -> dict[str, Any]:
        """Build a genesis state for the given validator count and report the verdict.

        Input keys:

        - ``numValidators``: number of validators in the genesis state.

        Output:

        - ``valid``: result of verify_checkpoint_state on the built state.
        - ``stateBytes``: SSZ-encoded state hex, so clients can deserialize
          and run their own verify_checkpoint_state.
        - ``validatorCount``: echoed for diagnostic clarity.
        """
        num_validators = int(self.input["numValidators"])
        state = generate_pre_state(genesis_time=Uint64(0), num_validators=num_validators)
        valid = verify_checkpoint_state(state)
        return {
            "valid": valid,
            "stateBytes": "0x" + state.encode_bytes().hex(),
            "validatorCount": num_validators,
        }
