"""
Boot anchor for the lean consensus node.

The forkchoice store starts at a trusted block plus the matching state.
Two sources are supported:

- Genesis: build the store from the genesis validator set the first time
  the node starts. No network round-trip; no state to verify.
- Checkpoint: fetch a finalized state from a peer, verify it, and build
  the forkchoice store from that state. The validators inside the state
  replace the genesis validator set as the source of truth.

Both paths land on the same shape so the rest of the boot sequence does
not branch on the anchor source. The protocol does not distinguish
"started from genesis" from "started from a finalized checkpoint" once
the store exists.
"""

from __future__ import annotations

from typing import cast

from lean_spec.forks import ForkProtocol, Store, Validators
from lean_spec.subspecs.genesis import GenesisConfig
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.sync.checkpoint_sync import (
    CheckpointSyncError,
    create_anchor_block,
    fetch_finalized_state,
    verify_checkpoint_state,
)
from lean_spec.types import Bytes32, Checkpoint, Slot, StrictBaseModel, ValidatorIndex


class Anchor(StrictBaseModel):
    """
    Starting state for the node's forkchoice store.

    Carries the three values the boot sequence needs to construct a Node
    and announce itself to peers:

    - validators: the validator set the store will see at slot zero of
      this run (either genesis or the checkpointed state's validators).
    - store: a pre-built forkchoice store on the checkpoint path, or None
      to ask Node.from_genesis to synthesize one from validators.
    - initial_status: the Status broadcast to peers before the listener
      starts serving inbound ReqResp queries.
    """

    validators: Validators
    """Validator set to wire into NodeConfig.validators."""

    store: Store | None
    """Pre-built forkchoice store, or None to synthesize from validators."""

    initial_status: Status
    """Status to publish on the event source before serving inbound traffic."""

    @classmethod
    def from_genesis(cls, genesis: GenesisConfig) -> Anchor:
        """
        Build an anchor from a fresh genesis configuration.

        No store is constructed here: Node.from_genesis synthesizes one
        from the validator set. The initial status carries zero roots and
        slot zero because the genesis block's identity is not yet computed
        at this point in the boot sequence.

        Args:
            genesis: Genesis YAML loaded from disk.

        Returns:
            An anchor that asks the node to synthesize its own store.
        """
        zero_checkpoint = Checkpoint(root=Bytes32.zero(), slot=Slot(0))
        return cls(
            validators=genesis.to_validators(),
            store=None,
            initial_status=Status(finalized=zero_checkpoint, head=zero_checkpoint),
        )

    @classmethod
    async def from_checkpoint(
        cls,
        url: str,
        genesis: GenesisConfig,
        fork: ForkProtocol,
        validator_id: ValidatorIndex | None,
    ) -> Anchor:
        """
        Build an anchor by fetching a finalized state from a peer.

        The fetched state replaces the genesis validator set: deposits and
        exits since genesis are baked into state.validators, so we use
        that as the source of truth.

        Args:
            url: HTTP endpoint of the node serving the checkpoint state.
            genesis: Local genesis. Only its genesis_time is consulted, as
                a chain-identity guard against syncing to the wrong network.
            fork: Fork specification driving state/store construction.
            validator_id: Local validator index used as a forkchoice
                tiebreaker hint. Same value passed on the genesis path.

        Raises:
            CheckpointSyncError: For every failure mode (HTTP transport,
                structural verification, genesis-time mismatch). Callers
                see one typed exception instead of three implicit branches.
        """
        state = await fetch_finalized_state(url, fork.state_class)

        # Defense in depth even though we trust the source: catches a
        # corrupted download or a misconfigured server before the bad state
        # contaminates the forkchoice store.
        if not verify_checkpoint_state(state):
            raise CheckpointSyncError("checkpoint state failed structural verification")

        # Genesis time is the only chain-identity guard we can apply at
        # this layer. A mismatch means the checkpoint belongs to a different
        # network; refusing to start is safer than silently corrupting the
        # node's view of history.
        if state.config.genesis_time != genesis.genesis_time:
            raise CheckpointSyncError(
                f"genesis time mismatch: checkpoint={state.config.genesis_time}, "
                f"local={genesis.genesis_time}"
            )

        anchor_block = create_anchor_block(state)
        # The fork protocol returns the structural Store contract; the
        # concrete Store is the only one wired into NodeConfig today.
        store = cast(Store, fork.create_store(state, anchor_block, validator_id))
        head_slot = store.blocks[store.head].slot

        return cls(
            validators=state.validators,
            store=store,
            initial_status=Status(
                finalized=store.latest_finalized,
                head=Checkpoint(root=store.head, slot=head_slot),
            ),
        )
