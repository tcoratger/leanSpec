"""Advanced tests for forkchoice focusing on coverage and edge cases."""

import pytest
from typing_extensions import Dict

from lean_spec.subspecs.containers import Block, BlockBody, Checkpoint, Config, SignedVote, Vote
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.forkchoice.helpers import (
    get_fork_choice_head,
    get_latest_justified,
    get_vote_target,
)
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64, ValidatorIndex


@pytest.fixture
def config() -> Config:
    """Sample configuration."""
    return Config(genesis_time=Uint64(1000), num_validators=Uint64(100))


@pytest.fixture
def simple_store(config: Config) -> Store:
    """Create a simple store for testing."""
    genesis_checkpoint = Checkpoint(root=Bytes32(b"genesis" + b"\x00" * 25), slot=Slot(0))

    return Store(
        time=Uint64(0),
        config=config,
        head=Bytes32(b"genesis" + b"\x00" * 25),
        safe_target=Bytes32(b"genesis" + b"\x00" * 25),
        latest_justified=genesis_checkpoint,
        latest_finalized=genesis_checkpoint,
    )


class TestForkChoiceAdvanced:
    """Advanced fork choice algorithm tests."""

    def test_deep_chain_fork_choice(self) -> None:
        """Test fork choice with a deep chain."""
        # Create a 5-block chain
        blocks = {}
        # NOTE: Using a non-zero parent for genesis to ensure it's not the ZERO_HASH
        prev_hash = Bytes32(b"pre-genesis" + b"\x00" * 21)
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=prev_hash,
            state_root=Bytes32(b"block0" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )
        genesis_hash = hash_tree_root(genesis_block)
        blocks[genesis_hash] = genesis_block
        prev_hash = genesis_hash

        for i in range(1, 5):
            block = Block(
                slot=Slot(i),
                proposer_index=Uint64(i),
                parent_root=prev_hash,
                state_root=Bytes32(f"block{i}".encode() + b"\x00" * (32 - len(f"block{i}"))),
                body=BlockBody(attestations=[]),
            )
            block_hash = hash_tree_root(block)
            blocks[block_hash] = block
            prev_hash = block_hash

        deepest_hash = prev_hash  # The last block hash

        # Vote for the deepest block
        votes = {ValidatorIndex(0): Checkpoint(root=deepest_hash, slot=Slot(4))}

        head = get_fork_choice_head(blocks, genesis_hash, votes)
        assert head == deepest_hash

    def test_fork_choice_with_multiple_forks(self) -> None:
        """Test fork choice with multiple competing forks."""
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )
        genesis_hash = hash_tree_root(genesis)

        # Create 3 competing forks at slot 1
        fork_a = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"fork_a" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )
        fork_a_hash = hash_tree_root(fork_a)

        fork_b = Block(
            slot=Slot(1),
            proposer_index=Uint64(2),
            parent_root=genesis_hash,
            state_root=Bytes32(b"fork_b" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )
        fork_b_hash = hash_tree_root(fork_b)

        fork_c = Block(
            slot=Slot(1),
            proposer_index=Uint64(3),
            parent_root=genesis_hash,
            state_root=Bytes32(b"fork_c" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )
        fork_c_hash = hash_tree_root(fork_c)

        blocks = {
            genesis_hash: genesis,
            fork_a_hash: fork_a,
            fork_b_hash: fork_b,
            fork_c_hash: fork_c,
        }

        # Fork A gets 3 votes, Fork B gets 2 votes, Fork C gets 1 vote
        votes = {
            ValidatorIndex(0): Checkpoint(root=fork_a_hash, slot=Slot(1)),
            ValidatorIndex(1): Checkpoint(root=fork_a_hash, slot=Slot(1)),
            ValidatorIndex(2): Checkpoint(root=fork_a_hash, slot=Slot(1)),
            ValidatorIndex(3): Checkpoint(root=fork_b_hash, slot=Slot(1)),
            ValidatorIndex(4): Checkpoint(root=fork_b_hash, slot=Slot(1)),
            ValidatorIndex(5): Checkpoint(root=fork_c_hash, slot=Slot(1)),
        }

        head = get_fork_choice_head(blocks, genesis_hash, votes)
        assert head == fork_a_hash  # Fork A should win

    def test_fork_choice_ancestor_votes(self) -> None:
        """Test that votes for descendants count for ancestors."""
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )
        genesis_hash = hash_tree_root(genesis)

        block_1 = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block1" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )
        block_1_hash = hash_tree_root(block_1)

        block_2 = Block(
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=block_1_hash,
            state_root=Bytes32(b"block2" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )
        block_2_hash = hash_tree_root(block_2)

        blocks = {
            genesis_hash: genesis,
            block_1_hash: block_1,
            block_2_hash: block_2,
        }

        # Vote for block_2 should count for both block_2 and block_1
        votes = {ValidatorIndex(0): Checkpoint(root=block_2_hash, slot=Slot(2))}

        head = get_fork_choice_head(blocks, genesis_hash, votes)
        assert head == block_2_hash


class TestStoreAdvanced:
    """Advanced Store functionality tests."""

    def test_store_update_head(self, simple_store: Store) -> None:
        """Test store head update functionality."""
        # Add a block to the store
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"genesis_state" + b"\x00" * 19),
            body=BlockBody(attestations=[]),
        )
        simple_store.blocks[simple_store.head] = genesis_block

        block = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=simple_store.head,  # Use store's head as parent
            state_root=Bytes32(b"block1" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )

        block_hash = hash_tree_root(block)
        simple_store.blocks[block_hash] = block

        # Add a vote for the new block
        checkpoint = Checkpoint(root=block_hash, slot=Slot(1))
        simple_store.latest_known_votes[ValidatorIndex(0)] = checkpoint

        # Update head
        simple_store.update_head()

        # Head should be updated to the new block
        assert simple_store.head == block_hash

    def test_store_tick_interval_actions(self, simple_store: Store) -> None:
        """Test different interval actions during tick."""
        # FIX: Advance time to 3 using the object's method instead of direct assignment.
        for _ in range(3):
            simple_store.tick_interval(has_proposal=False)

        initial_time = simple_store.time.as_int()
        assert initial_time == 3

        # Add new votes for testing interval 0 and 3 actions
        checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(0))
        simple_store.latest_new_votes[ValidatorIndex(0)] = checkpoint

        # Test interval 0 (start of slot with proposal)
        simple_store.tick_interval(has_proposal=True)  # time becomes 4, interval is 0

        # Votes should be accepted and moved to known votes
        assert len(simple_store.latest_new_votes) == 0
        assert ValidatorIndex(0) in simple_store.latest_known_votes
        assert simple_store.time.as_int() == initial_time + 1

    def test_store_safe_target_update(self, simple_store: Store) -> None:
        """Test safe target update with vote threshold."""
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )
        simple_store.blocks[simple_store.head] = genesis_block

        # Set up config for 2/3 majority (need 67 votes out of 100)
        # Add votes for testing
        checkpoint = Checkpoint(root=simple_store.head, slot=Slot(0))

        # Add enough votes for 2/3 majority
        for i in range(67):
            simple_store.latest_new_votes[ValidatorIndex(i)] = checkpoint

        # Update safe target
        simple_store.update_safe_target()

        # Safe target should be updated
        assert simple_store.safe_target is not None

    def test_store_get_proposal_head(self, simple_store: Store) -> None:
        """Test getting proposal head for a slot."""
        # Get proposal head for slot 0
        head = simple_store.get_proposal_head(0)

        # Should return current head
        assert head == simple_store.head

    def test_store_get_vote_target(self, simple_store: Store) -> None:
        """Test getting vote target for attestation."""
        # Add blocks to store for vote target calculation
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )

        simple_store.blocks[simple_store.head] = genesis_block

        # Get vote target
        target = simple_store.get_vote_target()

        # Should return a checkpoint
        assert isinstance(target, Checkpoint)
        assert target.root is not None
        assert isinstance(target.slot, Slot)


class TestVoteTargetAdvanced:
    """Advanced vote target selection tests."""

    def test_vote_target_with_old_finalized(self) -> None:
        """Test vote target selection with very old finalized checkpoint."""
        # Create a chain where finalized block is far back
        blocks = {}

        # Create 10 blocks
        prev_hash = Bytes32(b"pre-genesis" + b"\x00" * 21)
        for i in range(10):
            block = Block(
                slot=Slot(i),
                proposer_index=Uint64(i),
                parent_root=prev_hash,
                state_root=Bytes32(f"block{i}".encode() + b"\x00" * (32 - len(f"block{i}"))),
                body=BlockBody(attestations=[]),
            )
            block_hash = hash_tree_root(block)
            blocks[block_hash] = block
            prev_hash = block_hash

        # Very old finalized checkpoint (slot 0)
        finalized = Checkpoint(
            root=next(h for h, b in blocks.items() if b.slot == Slot(0)), slot=Slot(0)
        )

        # Current head is at slot 9
        head_hash = next(h for h, b in blocks.items() if b.slot == Slot(9))

        target = get_vote_target(head_hash, head_hash, finalized, blocks)

        # Should return a valid checkpoint
        assert isinstance(target, Checkpoint)
        assert target.root in blocks
        assert target.slot.as_int() >= 0

    def test_vote_target_walks_back_from_head(self) -> None:
        """Test that vote target walks back from head when needed."""
        # Create blocks
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )
        genesis_hash = hash_tree_root(genesis)

        block_1 = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block1" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )
        block_1_hash = hash_tree_root(block_1)

        block_2 = Block(
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=block_1_hash,
            state_root=Bytes32(b"block2" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )
        block_2_hash = hash_tree_root(block_2)

        blocks = {
            genesis_hash: genesis,
            block_1_hash: block_1,
            block_2_hash: block_2,
        }

        # Finalized at genesis
        finalized = Checkpoint(root=genesis_hash, slot=Slot(0))

        # Head is at block_2, but safe target is at block_1
        target = get_vote_target(block_2_hash, block_1_hash, finalized, blocks)

        # Should walk back towards safe target
        assert target.root in blocks


class TestAttestationValidation:
    """Advanced attestation validation tests."""

    def test_validate_attestation_slot_order(self, simple_store: Store) -> None:
        """Test attestation validation with slot ordering constraints."""
        # Add blocks for validation
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )
        genesis_hash = hash_tree_root(genesis_block)

        block_1 = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block1" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )
        block_1_hash = hash_tree_root(block_1)

        simple_store.blocks[genesis_hash] = genesis_block
        simple_store.blocks[block_1_hash] = block_1

        # Valid attestation with correct slot ordering
        vote = Vote(
            validator_id=Uint64(0),
            slot=Slot(1),
            head=Checkpoint(root=block_1_hash, slot=Slot(1)),
            source=Checkpoint(root=genesis_hash, slot=Slot(0)),
            target=Checkpoint(root=block_1_hash, slot=Slot(1)),
        )

        signed_vote = SignedVote(data=vote, signature=Bytes32(b"signature" + b"\x00" * 23))

        # Should validate successfully
        simple_store.validate_attestation(signed_vote)

    def test_validate_attestation_invalid_slot_order(self, simple_store: Store) -> None:
        """Test attestation validation fails with invalid slot ordering."""
        # Add blocks
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )
        genesis_hash = hash_tree_root(genesis_block)

        block_1 = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block1" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )
        block_1_hash = hash_tree_root(block_1)

        simple_store.blocks[genesis_hash] = genesis_block
        simple_store.blocks[block_1_hash] = block_1

        # Invalid attestation - source slot > target slot
        vote = Vote(
            validator_id=Uint64(0),
            slot=Slot(2),
            head=Checkpoint(root=block_1_hash, slot=Slot(1)),
            source=Checkpoint(root=block_1_hash, slot=Slot(1)),
            target=Checkpoint(root=genesis_hash, slot=Slot(0)),  # Invalid: target < source
        )

        signed_vote = SignedVote(data=vote, signature=Bytes32(b"signature" + b"\x00" * 23))

        # Should raise assertion error
        with pytest.raises(AssertionError, match="Source slot must not exceed target slot"):
            simple_store.validate_attestation(signed_vote)


class TestEdgeCasesAdvanced:
    """Advanced edge case tests."""

    def test_fork_choice_zero_hash_root(self) -> None:
        """Test fork choice behavior with zero hash as starting root."""
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )
        genesis_hash = hash_tree_root(genesis)
        blocks = {genesis_hash: genesis}

        # Use ZERO_HASH as root - should default to earliest block
        from lean_spec.subspecs.forkchoice.constants import ZERO_HASH

        head = get_fork_choice_head(blocks, ZERO_HASH, {})
        assert head == genesis_hash

    def test_get_latest_justified_with_ties(self) -> None:
        """Test get_latest_justified when multiple states have same slot."""
        from lean_spec.subspecs.containers import State

        checkpoint_same_slot = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(10))

        class MockState:
            def __init__(self) -> None:
                self.latest_justified = checkpoint_same_slot

        mock_state_1 = MockState()
        mock_state_2 = MockState()

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): mock_state_1,  # type: ignore
            Bytes32(b"state2" + b"\x00" * 26): mock_state_2,  # type: ignore
        }

        result = get_latest_justified(states)
        assert result == checkpoint_same_slot

    def test_vote_processing_order_matters(self, simple_store: Store) -> None:
        """Test that vote processing order affects the result correctly."""
        # Process votes in different order and verify latest wins

        old_checkpoint = Checkpoint(root=Bytes32(b"old" + b"\x00" * 29), slot=Slot(1))
        new_checkpoint = Checkpoint(root=Bytes32(b"new" + b"\x00" * 29), slot=Slot(2))

        # Process old vote first
        simple_store.latest_new_votes[ValidatorIndex(5)] = old_checkpoint

        # Process new vote from same validator - should supersede
        simple_store.latest_new_votes[ValidatorIndex(5)] = new_checkpoint

        # Should only have the newer vote
        assert simple_store.latest_new_votes[ValidatorIndex(5)] == new_checkpoint
        assert simple_store.latest_new_votes[ValidatorIndex(5)].slot == Slot(2)

    def test_store_time_intervals_coverage(self, simple_store: Store) -> None:
        """Test all different interval behaviors in tick_interval."""
        # FIX: Advance time using the object's method instead of direct assignment.
        for _ in range(3):
            simple_store.tick_interval(has_proposal=False)
        assert simple_store.time.as_int() == 3

        # Add a test vote to be processed in interval 0
        checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(0))
        simple_store.latest_new_votes[ValidatorIndex(0)] = checkpoint
        assert len(simple_store.latest_new_votes) == 1

        # Test interval 0 with proposal (time -> 4)
        simple_store.tick_interval(has_proposal=True)
        assert len(simple_store.latest_new_votes) == 0  # Votes should be processed

        # Test interval 1 (time -> 5)
        simple_store.tick_interval(has_proposal=False)

        # Test interval 2 (time -> 6, update safe target)
        simple_store.tick_interval(has_proposal=False)

        # Test interval 3 (time -> 7, process votes)
        simple_store.latest_new_votes[ValidatorIndex(1)] = checkpoint
        assert len(simple_store.latest_new_votes) == 1
        simple_store.tick_interval(has_proposal=False)
        assert len(simple_store.latest_new_votes) == 0  # Votes should be processed
