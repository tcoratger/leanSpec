"""Devnet4 fork specification — delegates to existing State/Store methods."""

from collections.abc import Iterable
from collections.abc import Set as AbstractSet

from lean_spec.subspecs.chain.clock import Interval
from lean_spec.subspecs.containers.attestation import (
    AggregatedAttestation,
    AttestationData,
    SignedAggregatedAttestation,
)
from lean_spec.subspecs.containers.block import Block, SignedBlock
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import Bytes32, Uint64

from ..protocol import ForkProtocol
from .state import State
from .store import Store


class Devnet4Spec(ForkProtocol):
    """
    Devnet4 consensus specification.

    Pure delegation to existing State and Store methods.
    This is the current codebase wrapped in ForkProtocol shape.
    """

    @classmethod
    def name(cls) -> str:
        """Return the fork name."""
        return "devnet4"

    @classmethod
    def version(cls) -> int:
        """Return the fork version number."""
        return 4

    @property
    def state_class(self) -> type[State]:
        """Return the State class for devnet4."""
        return State

    @property
    def store_class(self) -> type[Store]:
        """Return the Store class for devnet4."""
        return Store

    # Genesis

    def generate_genesis(self, genesis_time: Uint64, validators: Validators) -> State:
        """Generate devnet4 genesis state."""
        return State.generate_genesis(genesis_time, validators)

    # State transition

    def process_slots(self, state: State, target_slot: Slot) -> State:
        """Advance through empty slots."""
        return state.process_slots(target_slot)

    def process_block(self, state: State, block: Block) -> State:
        """Apply full block processing."""
        return state.process_block(block)

    def state_transition(self, state: State, block: Block, valid_signatures: bool = True) -> State:
        """Complete state transition function."""
        return state.state_transition(block, valid_signatures)

    def process_attestations(
        self, state: State, attestations: Iterable[AggregatedAttestation]
    ) -> State:
        """Apply attestations."""
        return state.process_attestations(attestations)

    def build_block(
        self,
        state: State,
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Bytes32,
        known_block_roots: AbstractSet[Bytes32],
        aggregated_payloads: (dict[AttestationData, set[AggregatedSignatureProof]] | None) = None,
    ) -> tuple[Block, State, list[AggregatedAttestation], list[AggregatedSignatureProof]]:
        """Build a block via existing State logic."""
        return state.build_block(
            slot, proposer_index, parent_root, known_block_roots, aggregated_payloads
        )

    # Store / forkchoice

    def store_on_block(self, store: Store, signed_block: SignedBlock) -> Store:
        """Process block through Store."""
        return store.on_block(signed_block)

    def store_on_tick(
        self,
        store: Store,
        target_interval: Interval,
        has_proposal: bool,
        is_aggregator: bool = False,
    ) -> tuple[Store, list[SignedAggregatedAttestation]]:
        """Advance store time."""
        return store.on_tick(target_interval, has_proposal, is_aggregator)

    def store_update_head(self, store: Store) -> Store:
        """Recompute head."""
        return store.update_head()
