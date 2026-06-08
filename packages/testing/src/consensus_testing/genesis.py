"""Consensus layer pre-state generation."""

from consensus_testing.keys import XmssKeyManager
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Interval, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestations,
    Block,
    BlockBody,
    State,
    Validator,
    Validators,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Bytes32, Bytes52, Uint64

_DEFAULT_GENESIS_TIME = Uint64(0)

_DEFAULT_VALIDATOR_INDEX = ValidatorIndex(0)
"""Owning validator for a genesis store, unless overridden."""


def _build_validators(num_validators: int) -> Validators:
    """Build a validator registry with real XMSS keys from the shared key manager."""
    key_manager = XmssKeyManager.shared()

    if num_validators > len(key_manager):
        raise ValueError(
            f"Not enough keys: need {num_validators} validators "
            f"but the key manager has only {len(key_manager)} keys"
        )

    validators = []
    for validator_position in range(num_validators):
        validator_index = ValidatorIndex(validator_position)
        attestation_public_key, proposal_public_key = key_manager.get_public_keys(validator_index)
        validators.append(
            Validator(
                attestation_public_key=Bytes52(attestation_public_key.encode_bytes()),
                proposal_public_key=Bytes52(proposal_public_key.encode_bytes()),
                index=validator_index,
            )
        )

    return Validators(data=validators)


def generate_pre_state(
    fork: LstarSpec | None = None,
    genesis_time: Uint64 = _DEFAULT_GENESIS_TIME,
    num_validators: int = 4,
) -> State:
    """
    Generate a default pre-state for consensus tests.

    Args:
        fork: Fork dispatching genesis construction. Defaults to a fresh
            LstarSpec instance.
        genesis_time: The genesis timestamp.
        num_validators: Number of validators to include.

    Returns:
        A properly initialized consensus state.
    """
    fork = fork or LstarSpec()
    validators = _build_validators(num_validators)
    return fork.generate_genesis(genesis_time=genesis_time, validators=validators)


def build_anchor(
    num_validators: int,
    anchor_slot: Slot,
    fork: LstarSpec | None = None,
    genesis_time: Uint64 = _DEFAULT_GENESIS_TIME,
) -> tuple[State, Block]:
    """
    Build a consistent non-genesis anchor by advancing the genesis state.

    Simulates the mid-chain view that a checkpoint-synced node would have:
    a real state reached via the normal state transition from genesis,
    plus the real block at that slot.

    The resulting (state, block) pair is internally consistent. That means:

    - Block state_root equals hash_tree_root(state).
    - State historical_block_hashes lists the real roots for slots 0..anchor_slot-1.
    - State latest_block_header matches the anchor block header (without state_root).

    Args:
        fork: Fork dispatching genesis construction.
        num_validators: Size of the validator set in the anchor state.
        anchor_slot: Slot at which the anchor block lives. Must be > 0.
        genesis_time: Genesis timestamp for the underlying pre-state.

    Returns:
        A tuple of (anchor_state, anchor_block) ready to seed a fork choice
        store at a non-genesis starting point.

    Raises:
        ValueError: If anchor_slot is not strictly positive.
    """
    if anchor_slot <= Slot(0):
        raise ValueError(
            f"Anchor slot must be strictly positive, got {anchor_slot}. "
            "For a genesis anchor use generate_pre_state instead."
        )

    fork = fork or LstarSpec()
    state = generate_pre_state(fork=fork, genesis_time=genesis_time, num_validators=num_validators)

    # Reconstruct the genesis block from the state's latest header.
    # The genesis block is fully determined by the genesis state.
    genesis_block = Block(
        slot=state.latest_block_header.slot,
        proposer_index=state.latest_block_header.proposer_index,
        parent_root=state.latest_block_header.parent_root,
        state_root=hash_tree_root(state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    current_block = genesis_block
    parent_root = hash_tree_root(current_block)

    num_validators_u64 = Uint64(num_validators)

    # Advance through empty blocks, one per slot, up to and including anchor_slot.
    # Each block is built by the spec's own builder so the resulting state
    # carries the real chain history (historical block hashes, justified slots,
    # justification tracking) that a real mid-chain state would have.
    for next_slot in range(1, int(anchor_slot) + 1):
        slot = Slot(next_slot)
        proposer_index = ValidatorIndex.proposer_for_slot(slot, num_validators_u64)
        current_block, state, _, _ = fork.build_block(
            state,
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots={parent_root},
        )
        parent_root = hash_tree_root(current_block)

    return state, current_block


def make_validators(count: int) -> Validators:
    """Build a validator registry of the given size with zeroed public keys."""
    return Validators(
        data=[
            Validator(
                attestation_public_key=Bytes52(b"\x00" * 52),
                proposal_public_key=Bytes52(b"\x00" * 52),
                index=ValidatorIndex(validator_position),
            )
            for validator_position in range(count)
        ]
    )


def make_genesis_state(num_validators: int = 3, genesis_time: int = 0) -> State:
    """Build a genesis state with zeroed validator keys."""
    return LstarSpec().generate_genesis(
        genesis_time=Uint64(genesis_time),
        validators=make_validators(num_validators),
    )


def make_genesis_block(state: State) -> Block:
    """Build the genesis block matching a genesis state."""
    return Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )


def make_genesis_store(
    num_validators: int = 4,
    *,
    genesis_time: int = 0,
    validator_index: ValidatorIndex | None = _DEFAULT_VALIDATOR_INDEX,
    observer: bool = False,
    keyed: bool = True,
    time: Interval | None = None,
) -> Store:
    """
    Build a genesis fork-choice store.

    Uses real XMSS keys when keyed, else zeroed keys for any validator count.
    Set observer for a store with no owning validator.
    """
    state = (
        generate_pre_state(genesis_time=Uint64(genesis_time), num_validators=num_validators)
        if keyed
        else make_genesis_state(num_validators=num_validators, genesis_time=genesis_time)
    )
    store = LstarSpec().create_store(
        state,
        make_genesis_block(state),
        validator_index=None if observer else validator_index,
    )
    return store if time is None else store.model_copy(update={"time": time})
