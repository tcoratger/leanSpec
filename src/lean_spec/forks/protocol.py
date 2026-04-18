"""Fork protocol interface for leanSpec consensus."""

from abc import ABC, abstractmethod
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

from .devnet4.state import State
from .devnet4.store import Store


class ForkProtocol(ABC):
    """
    Abstract interface that each devnet fork must implement.

    Every consensus-altering operation is represented here.

    Fork implementations delegate to the concrete State/Store methods for their devnet version.
    """

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """Return the fork name, e.g. 'devnet4'."""
        ...

    @classmethod
    @abstractmethod
    def version(cls) -> int:
        """Return the fork version number (4 for devnet4, 5 for devnet5)."""
        ...

    # Fork-specific types

    @property
    @abstractmethod
    def state_class(self) -> type[State]:
        """Return the concrete State class for this fork."""
        ...

    @property
    @abstractmethod
    def store_class(self) -> type[Store]:
        """Return the concrete Store class for this fork."""
        ...

    # Genesis

    @abstractmethod
    def generate_genesis(self, genesis_time: Uint64, validators: Validators) -> State:
        """Generate a genesis state for this fork."""
        ...

    # State transition

    @abstractmethod
    def process_slots(self, state: State, target_slot: Slot) -> State:
        """Advance through empty slots up to target_slot."""
        ...

    @abstractmethod
    def process_block(self, state: State, block: Block) -> State:
        """Apply full block processing (header + body)."""
        ...

    @abstractmethod
    def state_transition(self, state: State, block: Block, valid_signatures: bool = True) -> State:
        """Complete state transition function."""
        ...

    @abstractmethod
    def process_attestations(
        self, state: State, attestations: Iterable[AggregatedAttestation]
    ) -> State:
        """Apply attestations and update justification/finalization."""
        ...

    @abstractmethod
    def build_block(
        self,
        state: State,
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Bytes32,
        known_block_roots: AbstractSet[Bytes32],
        aggregated_payloads: (dict[AttestationData, set[AggregatedSignatureProof]] | None) = None,
    ) -> tuple[Block, State, list[AggregatedAttestation], list[AggregatedSignatureProof]]:
        """Build a valid block on top of the given state."""
        ...

    # Store / forkchoice

    @abstractmethod
    def store_on_block(self, store: Store, signed_block: SignedBlock) -> Store:
        """Process a new block through the forkchoice store."""
        ...

    @abstractmethod
    def store_on_tick(
        self,
        store: Store,
        target_interval: Interval,
        has_proposal: bool,
        is_aggregator: bool = False,
    ) -> tuple[Store, list[SignedAggregatedAttestation]]:
        """Advance store time to the given interval."""
        ...

    @abstractmethod
    def store_update_head(self, store: Store) -> Store:
        """Recompute the canonical head."""
        ...

    # Store construction

    def create_store(
        self,
        state: State,
        anchor_block: Block,
        validator_id: ValidatorIndex | None,
    ) -> Store:
        """Create a forkchoice store from an anchor state and block."""
        return self.store_class.from_anchor(state, anchor_block, validator_id)

    # State upgrade

    def upgrade_state(self, state: State) -> State:
        """Migrate state from the previous fork. Default: identity."""
        return state
