"""State Container for the Lean Ethereum consensus specification."""

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Set as AbstractSet

from lean_spec.forks.lstar.containers.attestation import AggregatedAttestation, AttestationData
from lean_spec.forks.lstar.containers.block import Block, BlockHeader
from lean_spec.forks.lstar.containers.config import Config
from lean_spec.forks.lstar.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.forks.lstar.containers.validator import Validators
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import Bytes32, Checkpoint, Container, Slot, Uint64, ValidatorIndex

_LAZY_SPEC: object = None


def _spec() -> object:
    """Return the lstar fork spec; deferred import breaks the spec ↔ state cycle."""
    global _LAZY_SPEC
    if _LAZY_SPEC is None:
        from lean_spec.forks.lstar.spec import LstarSpec

        _LAZY_SPEC = LstarSpec()
    return _LAZY_SPEC


class State(Container):
    """The main consensus state object."""

    # Configuration
    config: Config
    """The chain's configuration parameters."""

    # Slot and block tracking
    slot: Slot
    """The current slot number."""

    latest_block_header: BlockHeader
    """The header of the most recent block."""

    # Checkpoints
    latest_justified: Checkpoint
    """The latest justified checkpoint."""

    latest_finalized: Checkpoint
    """The latest finalized checkpoint."""

    # Historical data
    historical_block_hashes: HistoricalBlockHashes
    """A list of historical block root hashes."""

    justified_slots: JustifiedSlots
    """A bitfield indicating which historical slots were justified."""

    validators: Validators
    """Registry of validators tracked by the state."""

    # Justification tracking (flattened for SSZ compatibility)
    justifications_roots: JustificationRoots
    """Roots of justified blocks."""

    justifications_validators: JustificationValidators
    """A bitlist of validators who participated in justifications."""

    @classmethod
    def generate_genesis(cls, genesis_time: Uint64, validators: Validators) -> State:
        """Generate a genesis state with empty history and proper initial values."""
        return _spec().generate_genesis(genesis_time, validators)  # type: ignore[attr-defined]

    def process_slots(self, target_slot: Slot) -> State:
        """Advance the state through empty slots up to, but not including, target_slot."""
        return _spec().process_slots(self, target_slot)  # type: ignore[attr-defined]

    def process_block_header(self, block: Block) -> State:
        """Validate the block header and update header-linked state."""
        return _spec().process_block_header(self, block)  # type: ignore[attr-defined]

    def process_block(self, block: Block) -> State:
        """Apply full block processing including header and body."""
        return _spec().process_block(self, block)  # type: ignore[attr-defined]

    def process_attestations(
        self,
        attestations: Iterable[AggregatedAttestation],
    ) -> State:
        """Apply attestations and update justification/finalization."""
        return _spec().process_attestations(self, attestations)  # type: ignore[attr-defined]

    def state_transition(self, block: Block, valid_signatures: bool = True) -> State:
        """Apply the complete state transition function for a block."""
        return _spec().state_transition(  # type: ignore[attr-defined]
            self, block, valid_signatures
        )

    def build_block(
        self,
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Bytes32,
        known_block_roots: AbstractSet[Bytes32],
        aggregated_payloads: dict[AttestationData, set[AggregatedSignatureProof]] | None = None,
    ) -> tuple[Block, State, list[AggregatedAttestation], list[AggregatedSignatureProof]]:
        """Build a valid block on top of this state."""
        return _spec().build_block(  # type: ignore[attr-defined]
            self,
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots=known_block_roots,
            aggregated_payloads=aggregated_payloads,
        )
