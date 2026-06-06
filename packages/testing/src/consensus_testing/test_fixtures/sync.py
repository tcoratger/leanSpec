"""Sync layer test fixture format."""

from typing import Any, ClassVar

from consensus_testing.genesis import build_anchor, generate_pre_state
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from lean_spec.node.sync.checkpoint_sync import verify_checkpoint_state
from lean_spec.spec.forks import Slot
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Uint64


class SyncFixture(BaseConsensusFixture):
    """
    Emitted vector for sync-layer conformance.

    JSON output: operation, input, output.
    """

    operation: str
    """Sync operation under test."""

    input: dict[str, Any]
    """Operation-specific input."""

    output: dict[str, Any]
    """Computed verdict and reference bytes."""


class SyncTest(BaseTestSpec):
    """
    Spec for sync-layer conformance.

    Currently supports one operation:

    - `verify_checkpoint`: emits the SSZ-encoded anchor state plus the
      verification verdict a client must produce.
    """

    format_name: ClassVar[str] = "sync_test"
    description: ClassVar[str] = "Tests sync-layer helpers clients must reproduce"

    operation: str
    """Sync operation: currently only verify_checkpoint."""

    input: dict[str, Any]
    """Operation-specific input. See per-handler docstrings."""

    def generate(self) -> SyncFixture:
        """
        Dispatch to the operation handler.

        Returns:
            The emitted vector with output populated.

        Raises:
            ValueError: If the operation name is unknown.
        """
        if self.operation == "verify_checkpoint":
            output = self._make_verify_checkpoint()
        else:
            raise ValueError(f"Unknown sync operation: {self.operation!r}")
        return SyncFixture(operation=self.operation, input=self.input, output=output)

    def _make_verify_checkpoint(self) -> dict[str, Any]:
        """
        Build a state for the given validator count and anchor slot and report the verdict.

        Input keys:

        - `numValidators`: number of validators in the state.
        - `anchorSlot`: optional slot to advance the chain through before
          verifying. Zero (default) yields a genesis state; positive values
          walk an empty-block chain through the slot so historical_block_hashes
          reflects a real advanced anchor.

        Output:

        - `valid`: result of verify_checkpoint_state on the built state.
        - `stateBytes`: SSZ-encoded state hex, so clients can deserialize
          and run their own verify_checkpoint_state.
        - `validatorCount`: echoed for diagnostic clarity.
        - `anchorSlot`: echoed so consumers see exactly which state was verified.
        """
        num_validators = int(self.input["numValidators"])
        anchor_slot = int(self.input.get("anchorSlot", 0))
        fork = LstarSpec()
        if anchor_slot == 0:
            state = generate_pre_state(
                fork=fork, genesis_time=Uint64(0), num_validators=num_validators
            )
        else:
            state, _ = build_anchor(
                fork=fork,
                num_validators=num_validators,
                anchor_slot=Slot(anchor_slot),
                genesis_time=Uint64(0),
            )
        valid = verify_checkpoint_state(state)
        return {
            "valid": valid,
            "stateBytes": "0x" + state.encode_bytes().hex(),
            "validatorCount": num_validators,
            "anchorSlot": anchor_slot,
        }
