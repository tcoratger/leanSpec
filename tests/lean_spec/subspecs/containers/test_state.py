"""Tests for the State container and its methods."""

from typing import Dict

import pytest

from lean_spec.subspecs.chain import DEVNET_CONFIG
from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    BlockHeader,
    Checkpoint,
    Config,
    SignedBlock,
    State,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.vote import SignedVote
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.types import Bytes32, List, Uint64, ValidatorIndex
from lean_spec.types.boolean import Boolean


@pytest.fixture
def sample_config() -> Config:
    """Provides a sample configuration with 10 validators."""
    return Config(num_validators=Uint64(10), genesis_time=Uint64(0))


@pytest.fixture
def genesis_state(sample_config: Config) -> State:
    """Provides a valid genesis state generated from the sample config."""
    return State.generate_genesis(
        genesis_time=sample_config.genesis_time,
        num_validators=sample_config.num_validators,
    )


def _create_block(
    slot: int, parent_header: BlockHeader, votes: list[SignedVote] | None = None
) -> SignedBlock:
    """Helper to create a basic, valid signed block for testing."""
    body = BlockBody(attestations=votes or [])
    block_message = Block(
        slot=Slot(slot),
        proposer_index=ValidatorIndex(slot % 10),  # Using sample_config num_validators
        parent_root=hash_tree_root(parent_header),
        state_root=Bytes32(b"\x00" * 32),  # Placeholder, to be filled in by STF
        body=body,
    )
    return SignedBlock(message=block_message, signature=Bytes32(b"\x00" * 32))


def _create_votes(indices: list[int]) -> list[Boolean]:
    """Creates a vote list with `True` at the specified indices."""
    votes = [False] * DEVNET_CONFIG.validator_registry_limit.as_int()
    for i in indices:
        votes[i] = True
    return votes


@pytest.fixture
def sample_block_header() -> BlockHeader:
    """Provides a sample, empty block header for state initialization."""
    return BlockHeader(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32(b"\x00" * 32),
        state_root=Bytes32(b"\x00" * 32),
        body_root=Bytes32(b"\x00" * 32),
    )


@pytest.fixture
def sample_checkpoint() -> Checkpoint:
    """Provides a sample, empty checkpoint for state initialization."""
    return Checkpoint(root=Bytes32(b"\x00" * 32), slot=Slot(0))


@pytest.fixture
def base_state(
    sample_config: Config,
    sample_block_header: BlockHeader,
    sample_checkpoint: Checkpoint,
) -> State:
    """Provides a base State object with default empty values."""
    return State(
        config=sample_config,
        slot=Slot(0),
        latest_block_header=sample_block_header,
        latest_justified=sample_checkpoint,
        latest_finalized=sample_checkpoint,
        historical_block_hashes=[],
        justified_slots=[],
        justifications_roots=[],
        justifications_validators=[],
    )


def test_is_proposer(
    sample_config: Config,
    sample_block_header: BlockHeader,
    sample_checkpoint: Checkpoint,
) -> None:
    """
    Test the `is_proposer` method with various slots and validator indices
    to ensure the round-robin proposer selection logic is correct.
    """

    def create_state_at_slot(slot: int) -> State:
        """Helper function to create a state object at a specific slot."""
        return State(
            config=sample_config,
            slot=Slot(slot),
            latest_block_header=sample_block_header,
            latest_justified=sample_checkpoint,
            latest_finalized=sample_checkpoint,
            historical_block_hashes=[],
            justified_slots=[],
            justifications_roots=[],
            justifications_validators=[],
        )

    # At slot 0, validator 0 should be the proposer (0 % 10 == 0)
    state_slot_0 = create_state_at_slot(0)
    assert state_slot_0.is_proposer(ValidatorIndex(0)) is True
    assert state_slot_0.is_proposer(ValidatorIndex(1)) is False

    # At slot 7, validator 7 should be the proposer (7 % 10 == 7)
    state_slot_7 = create_state_at_slot(7)
    assert state_slot_7.is_proposer(ValidatorIndex(7)) is True
    assert state_slot_7.is_proposer(ValidatorIndex(8)) is False

    # At slot 10, the selection wraps around to validator 0 (10 % 10 == 0)
    state_slot_10 = create_state_at_slot(10)
    assert state_slot_10.is_proposer(ValidatorIndex(0)) is True
    assert state_slot_10.is_proposer(ValidatorIndex(1)) is False

    # At slot 23, the selection wraps around to validator 3 (23 % 10 == 3)
    state_slot_23 = create_state_at_slot(23)
    assert state_slot_23.is_proposer(ValidatorIndex(3)) is True
    assert state_slot_23.is_proposer(ValidatorIndex(2)) is False


def test_get_justifications_empty(base_state: State) -> None:
    """
    Test `get_justifications` when the state contains no justification data.

    Verifies that the method correctly returns an empty dictionary when
    `justifications_roots` and `justifications_validators` are empty lists.
    """
    # Ensure the base state has empty justification lists
    assert not base_state.justifications_roots
    assert not base_state.justifications_validators

    # Call the method and assert it returns an empty dictionary
    justifications = base_state.get_justifications()
    assert justifications == {}


def test_get_justifications_single_root(base_state: State) -> None:
    """
    Test `get_justifications` with a single root and its associated votes.

    This test ensures the method can correctly parse and map one block root
    to its corresponding list of validator votes from the flattened structure.
    """
    # Define a single root being voted on
    root1 = Bytes32(b"\x01" * 32)

    # Create a sample list of votes for this root.
    #
    # The length must match the validator registry limit.
    votes1 = [False] * DEVNET_CONFIG.validator_registry_limit.as_int()
    votes1[2] = True  # Validator 2 voted
    votes1[5] = True  # Validator 5 voted

    # Create a new state instance with the desired justification data.
    state_with_data = base_state.model_copy(
        update={
            "justifications_roots": [root1],
            "justifications_validators": votes1,
        }
    )

    # Call the method to reconstruct the justifications map
    justifications = state_with_data.get_justifications()

    # Define the expected output
    expected = {root1: votes1}

    # Verify the output matches the expected structure and data
    assert justifications == expected


def test_get_justifications_multiple_roots(base_state: State) -> None:
    """
    Test `get_justifications` with multiple roots to verify correct slicing.

    This is the primary test case that validates the core logic of the method.
    It checks that the flattened `justifications_validators` list is correctly
    sliced and that each segment of votes is accurately mapped to its
    corresponding root from `justifications_roots`.
    """
    # Define multiple unique roots that are being voted on
    root1 = Bytes32(b"\x01" * 32)
    root2 = Bytes32(b"\x02" * 32)
    root3 = Bytes32(b"\x03" * 32)

    # Define distinct vote patterns for each root.
    # Each list must have a length equal to `VALIDATOR_REGISTRY_LIMIT`.
    limit = DEVNET_CONFIG.validator_registry_limit.as_int()
    votes1 = [False] * limit
    votes1[0] = True  # Validator 0 votes for root1

    votes2 = [False] * limit
    votes2[1] = True  # Validator 1 votes for root2
    votes2[2] = True  # Validator 2 votes for root2

    votes3 = [True] * limit  # All validators vote for root3

    # Create a new state instance with the desired justification data.
    state_with_data = base_state.model_copy(
        update={
            "justifications_roots": [root1, root2, root3],
            "justifications_validators": votes1 + votes2 + votes3,
        }
    )

    # Call the method to reconstruct the justifications map
    justifications = state_with_data.get_justifications()

    # Define the expected dictionary with roots mapped to their respective votes
    expected = {
        root1: votes1,
        root2: votes2,
        root3: votes3,
    }

    # Verify that the reconstructed map is identical to the expected map
    assert justifications == expected
    # Also verify that the number of roots matches
    assert len(justifications) == 3


def test_with_justifications_empty(
    sample_config: Config,
    sample_block_header: BlockHeader,
    sample_checkpoint: Checkpoint,
) -> None:
    """
    Test `with_justifications` returns a new state with cleared justifications.
    """
    # Create an initial state that has some justification data
    initial_state = State(
        config=sample_config,
        slot=Slot(0),
        latest_block_header=sample_block_header,
        latest_justified=sample_checkpoint,
        latest_finalized=sample_checkpoint,
        historical_block_hashes=[],
        justified_slots=[],
        justifications_roots=[Bytes32(b"\x01" * 32)],
        justifications_validators=[True] * DEVNET_CONFIG.validator_registry_limit.as_int(),
    )

    # Create a new state by setting an empty map
    new_state = initial_state.with_justifications({})

    # Verify that the new state's lists are empty
    assert not new_state.justifications_roots
    assert not new_state.justifications_validators

    # Verify that the original state remains unchanged (immutability)
    assert initial_state.justifications_roots
    assert initial_state.justifications_validators


def test_with_justifications_deterministic_order(base_state: State) -> None:
    """
    Test `with_justifications` always sorts roots for deterministic output.
    """
    root1 = Bytes32(b"\x01" * 32)
    root2 = Bytes32(b"\x02" * 32)
    limit = DEVNET_CONFIG.validator_registry_limit.as_int()
    votes1 = [False] * limit
    votes2 = [True] * limit

    # Provide the dictionary in an unsorted order (root2 comes before root1)
    justifications = {root2: votes2, root1: votes1}
    new_state = base_state.with_justifications(justifications)

    # Verify that the roots in the new state are sorted
    assert new_state.justifications_roots == [root1, root2]
    # Verify that the flattened validators list matches the sorted order
    assert new_state.justifications_validators == votes1 + votes2
    # Verify the original state is unchanged
    assert not base_state.justifications_roots


def test_with_justifications_invalid_length(base_state: State) -> None:
    """
    Test `with_justifications` raises an AssertionError for incorrect vote lengths.
    """
    root1 = Bytes32(b"\x01" * 32)
    # Create a list of votes that is one short of the required length
    invalid_votes = [True] * (DEVNET_CONFIG.validator_registry_limit - Uint64(1)).as_int()
    justifications = {root1: invalid_votes}

    # Verify that calling the method with this data raises an assertion error
    with pytest.raises(AssertionError):
        base_state.with_justifications(justifications)


@pytest.mark.parametrize(
    "justifications_map",
    [
        pytest.param({}, id="empty_justifications"),
        pytest.param({Bytes32(b"\x01" * 32): _create_votes([0])}, id="single_root"),
        pytest.param(
            {
                Bytes32(b"\x01" * 32): _create_votes([0]),
                Bytes32(b"\x02" * 32): _create_votes([1, 2]),
            },
            id="multiple_roots_sorted",
        ),
        pytest.param(
            {
                Bytes32(b"\x02" * 32): _create_votes([1, 2]),
                Bytes32(b"\x01" * 32): _create_votes([0]),
            },
            id="multiple_roots_unsorted",
        ),
        pytest.param(
            {
                Bytes32(b"\x03" * 32): [True] * DEVNET_CONFIG.validator_registry_limit.as_int(),
                Bytes32(b"\x01" * 32): _create_votes([0]),
                Bytes32(b"\x02" * 32): _create_votes([1, 2]),
            },
            id="complex_unsorted",
        ),
    ],
)
def test_justifications_roundtrip(
    base_state: State, justifications_map: Dict[Bytes32, list[bool]]
) -> None:
    """
    Test that data remains consistent after a with_justifications -> get cycle.
    """
    # Create a new state with the provided justifications map
    new_state = base_state.with_justifications(justifications_map)

    # Reconstruct the map using the getter from the new state
    reconstructed_map = new_state.get_justifications()

    # The expected result is the original map with sorted keys
    expected_map = dict(sorted(justifications_map.items()))

    # Assert that the reconstructed map is identical to the expected map
    assert reconstructed_map == expected_map


def test_generate_genesis(sample_config: Config) -> None:
    """
    Tests the `generate_genesis` class method to ensure it correctly
    initializes the state with default and provided values.
    """
    # Generate the genesis state.
    state = State.generate_genesis(
        genesis_time=sample_config.genesis_time,
        num_validators=sample_config.num_validators,
    )

    # Verify that the configuration is set correctly.
    assert state.config == sample_config
    # Verify the chain starts at slot 0.
    assert state.slot == Slot(0)
    # The body root of the initial header should be the hash of an empty body.
    assert state.latest_block_header.body_root == hash_tree_root(BlockBody(attestations=[]))
    # All historical and justification lists should be empty at genesis.
    assert not state.historical_block_hashes
    assert not state.justified_slots
    assert not state.justifications_roots
    assert not state.justifications_validators


def test_process_slot(genesis_state: State) -> None:
    """
    Tests `process_slot` to ensure it correctly caches the state root
    in the latest block header on the first slot after a block.
    """
    # The genesis state's latest_block_header has an empty state_root.
    assert genesis_state.latest_block_header.state_root == Bytes32(b"\x00" * 32)

    # Processing the next slot (slot 0 -> 1) should fill it.
    state_after_slot = genesis_state.process_slot()

    # The new header's state_root should be the hash_tree_root of the pre-slot state.
    expected_root = hash_tree_root(genesis_state)
    assert state_after_slot.latest_block_header.state_root == expected_root

    # Calling it again should not change the already-filled root.
    state_after_second_slot = state_after_slot.process_slot()
    assert state_after_second_slot.latest_block_header.state_root == expected_root


def test_process_slots(genesis_state: State) -> None:
    """
    Tests `process_slots` to verify it correctly advances the state
    across multiple empty slots.
    """
    # Advance the state from slot 0 to slot 5.
    target_slot = Slot(5)
    new_state = genesis_state.process_slots(target_slot)

    # Verify the state has reached the target slot.
    assert new_state.slot == target_slot
    # Verify the genesis state root was cached during the first slot transition.
    assert new_state.latest_block_header.state_root == hash_tree_root(genesis_state)

    # Test that it raises an error for a target slot in the past.
    with pytest.raises(AssertionError):
        new_state.process_slots(Slot(4))


def test_process_block_header_valid(genesis_state: State) -> None:
    """
    Tests `process_block_header` with a valid block to ensure all
    header-related state fields are updated correctly.
    """
    # Advance state to slot 1, where the new block will be.
    state_at_slot_1 = genesis_state.process_slots(Slot(1))
    genesis_header_root = hash_tree_root(state_at_slot_1.latest_block_header)

    # Create a valid block for slot 1.
    block = _create_block(1, state_at_slot_1.latest_block_header).message

    # Process the block header.
    new_state = state_at_slot_1.process_block_header(block)

    # Verify State Updates

    # The genesis block (parent) is finalized and justified.
    assert new_state.latest_finalized.root == genesis_header_root
    assert new_state.latest_justified.root == genesis_header_root
    # The historical hashes should contain the parent's root.
    assert new_state.historical_block_hashes == [genesis_header_root]
    # The justified status of slot 0 should be True.
    assert new_state.justified_slots == [True]
    # The latest header should be updated to the new block's header.
    assert new_state.latest_block_header.slot == block.slot
    assert new_state.latest_block_header.parent_root == block.parent_root
    # The new header's state_root is empty, to be filled in the next slot.
    assert new_state.latest_block_header.state_root == Bytes32(b"\x00" * 32)


@pytest.mark.parametrize(
    "bad_slot, bad_proposer, bad_parent_root, error_msg",
    [
        (2, 1, None, "Block slot mismatch"),
        (1, 2, None, "Incorrect block proposer"),
        (1, 1, Bytes32(b"\xde" * 32), "Block parent root mismatch"),
    ],
)
def test_process_block_header_invalid(
    genesis_state: State, bad_slot, bad_proposer, bad_parent_root, error_msg
) -> None:
    """
    Tests that `process_block_header` raises an AssertionError for various
    invalid header properties.
    """
    state_at_slot_1 = genesis_state.process_slots(Slot(1))
    parent_header = state_at_slot_1.latest_block_header
    parent_root = hash_tree_root(parent_header)

    # Create a block with potentially invalid data.
    block = Block(
        slot=Slot(bad_slot),
        proposer_index=ValidatorIndex(bad_proposer),
        parent_root=bad_parent_root or parent_root,
        state_root=Bytes32(b"\x00" * 32),
        body=BlockBody(attestations=[]),
    )

    # Expect an assertion error with a specific message.
    with pytest.raises(AssertionError, match=error_msg):
        state_at_slot_1.process_block_header(block)


def test_process_attestations_justification_and_finalization(genesis_state: State) -> None:
    """
    Tests `process_attestations` in a multi-slot scenario to verify
    the full justification and finalization lifecycle.
    """
    # --- Setup: build a short chain: genesis -> slot 1 -> slot 4 ---
    state = genesis_state

    # Move to slot 1 (so we can produce a block at slot 1)
    state = state.process_slots(Slot(1))

    # Produce block at slot 1 (no attestations)
    block1 = SignedBlock(
        message=Block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(1 % 10),  # sample config uses 10 validators
            parent_root=hash_tree_root(state.latest_block_header),
            state_root=Bytes32(b"\x00" * 32),  # placeholder, not checked in process_block
            body=BlockBody(attestations=[]),
        ),
        signature=Bytes32(b"\x00" * 32),
    )
    state = state.process_block(block1.message)

    # # Move to slot 4 and produce a block there
    # state = state.process_slots(Slot(4))
    # block4 = SignedBlock(
    #     message=Block(
    #         slot=Slot(4),
    #         proposer_index=ValidatorIndex(4 % 10),
    #         parent_root=hash_tree_root(state.latest_block_header),
    #         state_root=Bytes32(b"\x00" * 32),
    #         body=BlockBody(
    #             attestations=List[SignedVote, DEVNET_CONFIG.validator_registry_limit.as_int()]([])
    #         ),
    #     ),
    #     signature=Bytes32(b"\x00" * 32),
    # )
    # state = state.process_block(block4.message)

    # # Advance to slot 5 so that the history now includes the root for slot 4.
    # # (The history records the parent of the current block; slot 4's root gets
    # # added when we process a block whose parent is at slot 4.)
    # state = state.process_slots(Slot(5))

    # # Checkpoints: source = genesis, target = slot 4
    # genesis_checkpoint = Checkpoint(
    #     root=hash_tree_root(genesis_state.latest_block_header),
    #     slot=Slot(0),
    # )
    # checkpoint4 = Checkpoint(
    #     root=state.historical_block_hashes[4],  # root of block at slot 4
    #     slot=Slot(4),
    # )

    # # --- Create votes: 7 of 10 validators vote to justify slot 4 from genesis ---
    # votes_for_4 = [
    #     SignedVote(
    #         data=Vote(
    #             validator_id=ValidatorIndex(i),
    #             slot=Slot(4),
    #             head=checkpoint4,
    #             target=checkpoint4,
    #             source=genesis_checkpoint,
    #         )
    #     )
    #     for i in range(7)
    # ]

    # # --- Process attestations ---
    # new_state = state.process_attestations(
    #     List[SignedVote, DEVNET_CONFIG.validator_registry_limit.as_int()](votes_for_4)
    # )

    # # --- Assertions ---
    # # Checkpoint 4 should now be justified.
    # assert new_state.latest_justified == checkpoint4
    # # The justified bit for slot 4 should be set.
    # assert bool(new_state.justified_slots[4]) is True
    # # Because there are no other justifiable slots between 0 and 4,
    # # the source (genesis) should be finalized.
    # assert new_state.latest_finalized == genesis_checkpoint
    # # The per-root votes for the now-justified root should be cleared.
    # assert checkpoint4.root not in new_state.get_justifications()


# def test_state_transition_full(genesis_state: State) -> None:
#     """
#     Performs an end-to-end test of the `state_transition` function,
#     simulating a complete block processing cycle.
#     """
#     # 1. Start from a known state (genesis).
#     state = genesis_state

#     # 2. Create a valid block for the next slot.
#     state_at_slot_1 = state.process_slots(Slot(1))
#     signed_block = _create_block(1, state_at_slot_1.latest_block_header)
#     block = signed_block.message

#     # 3. Manually compute the expected post-state.
#     expected_state = state_at_slot_1.process_block(block)
#     # The block must commit to the correct final state root.
#     block_with_correct_root = block.model_copy(
#         update={"state_root": hash_tree_root(expected_state)}
#     )
#     final_signed_block = signed_block.model_copy(message=block_with_correct_root)

#     # 4. Call the state transition function.
#     final_state = state.state_transition(final_signed_block, valid_signatures=True)

#     # 5. The resulting state must be identical to the manually computed one.
#     assert final_state == expected_state

#     # 6. Test failure cases.
#     with pytest.raises(AssertionError, match="Block signatures must be valid"):
#         state.state_transition(final_signed_block, valid_signatures=False)

#     block_with_bad_root = block.model_copy(update={"state_root": Bytes32(b"\x00" * 32)})
#     signed_block_with_bad_root = signed_block.model_copy(message=block_with_bad_root)
#     with pytest.raises(AssertionError, match="Invalid block state root"):
#         state.state_transition(signed_block_with_bad_root, valid_signatures=True)
