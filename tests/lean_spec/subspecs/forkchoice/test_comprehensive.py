"""Comprehensive tests for forkchoice based on specification."""

from typing import Dict

import pytest

from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    BlockHeader,
    Checkpoint,
    Config,
    SignedVote,
    State,
    Vote,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.forkchoice.helpers import (
    get_fork_choice_head,
    get_latest_justified,
    get_vote_target,
)
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64, ValidatorIndex


class TestStoreLifecycle:
    """Test Store creation and lifecycle operations."""

    @pytest.fixture
    def config(self) -> Config:
        """Sample configuration."""
        return Config(genesis_time=Uint64(1000), num_validators=Uint64(100))

    @pytest.fixture
    def genesis_state(self, config: Config) -> State:
        """Create a valid genesis state using its factory."""
        # Use the canonical State.generate_genesis factory to create a valid object.
        return State.generate_genesis(
            genesis_time=config.genesis_time, num_validators=config.num_validators
        )

    @pytest.fixture
    def genesis_block(self, genesis_state: State) -> Block:
        """Create genesis block consistent with the genesis state."""
        # Create a block whose state_root matches the actual genesis_state fixture.
        return Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=hash_tree_root(genesis_state),
            body=BlockBody(attestations=[]),
        )

    def test_store_initialization(self, genesis_state: State, genesis_block: Block) -> None:
        """Test store initialization from genesis state and block."""
        store = Store.create_forkchoice_store(genesis_state, genesis_block)

        assert store.config == genesis_state.config
        assert store.latest_justified == genesis_state.latest_justified
        assert store.latest_finalized == genesis_state.latest_finalized
        assert len(store.blocks) == 1
        assert len(store.states) == 1
        assert len(store.latest_known_votes) == 0
        assert len(store.latest_new_votes) == 0

    def test_store_time_advancement(self, genesis_state: State, genesis_block: Block) -> None:
        """Test time advancement with interval ticking."""
        store = Store.create_forkchoice_store(genesis_state, genesis_block)
        initial_time = store.time.as_int()

        # Advance by several intervals
        target_time = store.config.genesis_time.as_int() + 100
        store.advance_time(target_time, has_proposal=False)

        assert store.time.as_int() > initial_time

    def test_store_accept_new_votes(self, genesis_state: State, genesis_block: Block) -> None:
        """Test accepting new votes and updating forkchoice."""
        store = Store.create_forkchoice_store(genesis_state, genesis_block)

        # Add some new votes
        checkpoint = Checkpoint(root=hash_tree_root(genesis_block), slot=Slot(0))
        store.latest_new_votes[ValidatorIndex(0)] = checkpoint
        store.latest_new_votes[ValidatorIndex(1)] = checkpoint

        # Accept new votes
        store.accept_new_votes()

        # New votes should be moved to known votes
        assert len(store.latest_new_votes) == 0
        assert len(store.latest_known_votes) == 2
        assert store.latest_known_votes[ValidatorIndex(0)] == checkpoint
        assert store.latest_known_votes[ValidatorIndex(1)] == checkpoint


class TestForkChoiceAlgorithm:
    """Test LMD GHOST fork choice algorithm."""

    @pytest.fixture
    def chain_blocks(self) -> Dict[Bytes32, Block]:
        """Create a test blockchain with forking."""
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )
        genesis_hash = hash_tree_root(genesis)

        # Main chain
        block_1 = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block1" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )
        block_1_hash = hash_tree_root(block_1)

        block_2a = Block(  # Fork A
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=block_1_hash,
            state_root=Bytes32(b"block2a" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )

        block_2b = Block(  # Fork B
            slot=Slot(2),
            proposer_index=Uint64(3),
            parent_root=block_1_hash,
            state_root=Bytes32(b"block2b" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )

        block_3a = Block(  # Extend Fork A
            slot=Slot(3),
            proposer_index=Uint64(4),
            parent_root=hash_tree_root(block_2a),
            state_root=Bytes32(b"block3a" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )

        return {
            genesis_hash: genesis,
            block_1_hash: block_1,
            hash_tree_root(block_2a): block_2a,
            hash_tree_root(block_2b): block_2b,
            hash_tree_root(block_3a): block_3a,
        }

    def test_fork_choice_no_votes(self, chain_blocks: Dict[Bytes32, Block]) -> None:
        """Test fork choice returns starting point when no votes."""
        genesis_hash = next(h for h, b in chain_blocks.items() if b.slot == Slot(0))

        head = get_fork_choice_head(chain_blocks, genesis_hash, {})
        assert head == genesis_hash

    def test_fork_choice_single_vote(self, chain_blocks: Dict[Bytes32, Block]) -> None:
        """Test fork choice with a single vote."""
        genesis_hash = next(h for h, b in chain_blocks.items() if b.slot == Slot(0))
        block_3a_hash = next(h for h, b in chain_blocks.items() if b.slot == Slot(3))

        votes = {ValidatorIndex(0): Checkpoint(root=block_3a_hash, slot=Slot(3))}

        head = get_fork_choice_head(chain_blocks, genesis_hash, votes)
        assert head == block_3a_hash

    def test_fork_choice_competing_votes(self, chain_blocks: Dict[Bytes32, Block]) -> None:
        """Test fork choice with competing votes on different forks."""
        # The common ancestor of the forks is block_1, not genesis.
        block_1_hash = next(h for h, b in chain_blocks.items() if b.slot == Slot(1))

        # Find blocks by a reliable property like proposer_index.
        block_2a_hash = next(
            h
            for h, b in chain_blocks.items()
            if b.slot == Slot(2) and b.proposer_index == Uint64(2)
        )
        block_2b_hash = next(
            h
            for h, b in chain_blocks.items()
            if b.slot == Slot(2) and b.proposer_index == Uint64(3)
        )
        # The head should be the end of the winning fork.
        block_3a_hash = next(h for h, b in chain_blocks.items() if b.slot == Slot(3))

        # Fork A gets 2 votes, Fork B gets 1 vote.
        votes = {
            ValidatorIndex(0): Checkpoint(root=block_2a_hash, slot=Slot(2)),
            ValidatorIndex(1): Checkpoint(root=block_2a_hash, slot=Slot(2)),
            ValidatorIndex(2): Checkpoint(root=block_2b_hash, slot=Slot(2)),
        }

        # Start the GHOST algorithm from the common ancestor.
        head = get_fork_choice_head(chain_blocks, block_1_hash, votes)

        # Fork A has more votes, so the head should be the leaf of that fork (block_3a).
        assert head == block_3a_hash

    def test_fork_choice_tie_breaking(self, chain_blocks: Dict[Bytes32, Block]) -> None:
        """Test fork choice tiebreaking by slot then hash."""
        block_1_hash = next(h for h, b in chain_blocks.items() if b.slot == Slot(1))

        # Get both forks at slot 2
        forks = [(h, b) for h, b in chain_blocks.items() if b.slot == Slot(2)]
        assert len(forks) == 2

        # Give equal votes to both forks
        votes = {
            ValidatorIndex(0): Checkpoint(root=forks[0][0], slot=Slot(2)),
            ValidatorIndex(1): Checkpoint(root=forks[1][0], slot=Slot(2)),
        }

        head = get_fork_choice_head(chain_blocks, block_1_hash, votes)

        # Should pick the one with highest hash (tiebreaker)
        expected_winner = max(forks, key=lambda x: x[0])
        assert head == expected_winner[0]


class TestVoteTargetSelection:
    """Test vote target computation based on safe targets."""

    def test_safe_target_computation(self) -> None:
        """Test safe target computation with 2/3 majority."""
        config = Config(genesis_time=Uint64(1000), num_validators=Uint64(9))  # 2/3 = 6

        genesis_state = State.generate_genesis(
            genesis_time=config.genesis_time, num_validators=config.num_validators
        )
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=hash_tree_root(genesis_state),
            body=BlockBody(attestations=[]),
        )
        genesis_block_hash = hash_tree_root(genesis_block)

        store = Store.create_forkchoice_store(genesis_state, genesis_block)

        # Add votes for safe target computation
        target_checkpoint = Checkpoint(root=genesis_block_hash, slot=Slot(0))
        for i in range(6):  # 2/3 majority
            store.latest_new_votes[ValidatorIndex(i)] = target_checkpoint

        # Update safe target
        store.update_safe_target()

        # Safe target should be set
        assert store.safe_target == genesis_block_hash

    def test_get_vote_target_recent_finalized(self) -> None:
        """Test vote target selection with recent finalization."""
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

        blocks = {
            genesis_hash: genesis,
            block_1_hash: block_1,
        }

        # Recent finalization
        finalized = Checkpoint(root=genesis_hash, slot=Slot(0))

        target = get_vote_target(
            head=block_1_hash,
            safe_target=block_1_hash,
            latest_finalized=finalized,
            blocks=blocks,
        )

        # Should target the head block since finalization is recent
        assert target.root == block_1_hash
        assert target.slot == Slot(1)


class TestJustificationAndFinalization:
    """Test checkpoint justification and finalization logic."""

    def test_get_latest_justified_empty(self) -> None:
        """Test get_latest_justified with no states."""
        result = get_latest_justified({})
        assert result is None

    def test_get_latest_justified_multiple_states(self) -> None:
        """Test get_latest_justified selects highest slot."""
        checkpoint_1 = Checkpoint(root=Bytes32(b"test1" + b"\x00" * 27), slot=Slot(10))
        checkpoint_2 = Checkpoint(root=Bytes32(b"test2" + b"\x00" * 27), slot=Slot(20))
        checkpoint_3 = Checkpoint(root=Bytes32(b"test3" + b"\x00" * 27), slot=Slot(15))

        config = Config(genesis_time=Uint64(1000), num_validators=Uint64(100))

        # Create a valid BlockHeader to use in the mock states.
        dummy_header = BlockHeader(
            slot=Slot(0),
            proposer_index=0,
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"\x00" * 32),
            body_root=Bytes32(b"\x00" * 32),
        )
        finalized_checkpoint = Checkpoint(root=Bytes32(b"\x00" * 32), slot=Slot(0))

        states = {
            Bytes32(b"state1" + b"\x00" * 26): State(
                config=config,
                slot=Slot(10),
                latest_justified=checkpoint_1,
                latest_finalized=finalized_checkpoint,
                latest_block_header=dummy_header,
                historical_block_hashes=[],
                justified_slots=[],
                justifications_roots=[],
                justifications_validators=[],
            ),
            Bytes32(b"state2" + b"\x00" * 26): State(
                config=config,
                slot=Slot(20),
                latest_justified=checkpoint_2,
                latest_finalized=finalized_checkpoint,
                latest_block_header=dummy_header,
                historical_block_hashes=[],
                justified_slots=[],
                justifications_roots=[],
                justifications_validators=[],
            ),
            Bytes32(b"state3" + b"\x00" * 26): State(
                config=config,
                slot=Slot(15),
                latest_justified=checkpoint_3,
                latest_finalized=finalized_checkpoint,
                latest_block_header=dummy_header,
                historical_block_hashes=[],
                justified_slots=[],
                justifications_roots=[],
                justifications_validators=[],
            ),
        }

        result = get_latest_justified(states)
        assert result == checkpoint_2  # Should return the one with highest slot


class TestAttestationProcessing:
    """Test attestation validation and processing."""

    @pytest.fixture
    def store_with_blocks(self) -> Store:
        """Create store with test blocks for attestation processing."""
        config = Config(genesis_time=Uint64(1000), num_validators=Uint64(100))

        genesis_state = State.generate_genesis(
            genesis_time=config.genesis_time, num_validators=config.num_validators
        )
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=hash_tree_root(genesis_state),
            body=BlockBody(attestations=[]),
        )

        store = Store.create_forkchoice_store(genesis_state, genesis_block)

        # Add more blocks for testing
        block_1 = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=hash_tree_root(genesis_block),
            state_root=Bytes32(b"block1" + b"\x00" * 26),
            body=BlockBody(attestations=[]),
        )

        store.blocks[hash_tree_root(block_1)] = block_1
        return store

    def test_attestation_validation_valid(self, store_with_blocks: Store) -> None:
        """Test valid attestation passes validation."""
        genesis_hash = next(h for h, b in store_with_blocks.blocks.items() if b.slot == Slot(0))
        block_1_hash = next(h for h, b in store_with_blocks.blocks.items() if b.slot == Slot(1))

        vote = Vote(
            validator_id=Uint64(0),
            slot=Slot(1),
            head=Checkpoint(root=block_1_hash, slot=Slot(1)),
            source=Checkpoint(root=genesis_hash, slot=Slot(0)),
            target=Checkpoint(root=block_1_hash, slot=Slot(1)),
        )

        signed_vote = SignedVote(data=vote, signature=Bytes32(b"signature" + b"\x00" * 23))

        # Should not raise any exception
        store_with_blocks.validate_attestation(signed_vote)

    def test_attestation_validation_invalid_source(self, store_with_blocks: Store) -> None:
        """Test attestation with invalid source fails validation."""
        block_1_hash = next(h for h, b in store_with_blocks.blocks.items() if b.slot == Slot(1))

        vote = Vote(
            validator_id=Uint64(0),
            slot=Slot(1),
            head=Checkpoint(root=block_1_hash, slot=Slot(1)),
            source=Checkpoint(root=Bytes32(b"unknown" + b"\x00" * 25), slot=Slot(0)),
            target=Checkpoint(root=block_1_hash, slot=Slot(1)),
        )

        signed_vote = SignedVote(data=vote, signature=Bytes32(b"signature" + b"\x00" * 23))

        with pytest.raises(AssertionError, match="Unknown source block"):
            store_with_blocks.validate_attestation(signed_vote)

    def test_process_network_attestation(self, store_with_blocks: Store) -> None:
        """Test processing attestation from network gossip."""
        genesis_hash = next(h for h, b in store_with_blocks.blocks.items() if b.slot == Slot(0))
        block_1_hash = next(h for h, b in store_with_blocks.blocks.items() if b.slot == Slot(1))

        vote = Vote(
            validator_id=Uint64(5),
            slot=Slot(1),
            head=Checkpoint(root=block_1_hash, slot=Slot(1)),
            source=Checkpoint(root=genesis_hash, slot=Slot(0)),
            target=Checkpoint(root=block_1_hash, slot=Slot(1)),
        )

        signed_vote = SignedVote(data=vote, signature=Bytes32(b"signature" + b"\x00" * 23))

        # Convert Uint64 to int before adding, then advance time.
        target_time = store_with_blocks.config.genesis_time.as_int() + 100
        store_with_blocks.advance_time(target_time, False)

        # Process as network attestation
        store_with_blocks.process_attestation(signed_vote, is_from_block=False)

        # Should be in new votes
        assert ValidatorIndex(5) in store_with_blocks.latest_new_votes
        assert store_with_blocks.latest_new_votes[ValidatorIndex(5)] == vote.target

    def test_process_block_attestation(self, store_with_blocks: Store) -> None:
        """Test processing attestation from block."""
        genesis_hash = next(h for h, b in store_with_blocks.blocks.items() if b.slot == Slot(0))
        block_1_hash = next(h for h, b in store_with_blocks.blocks.items() if b.slot == Slot(1))

        vote = Vote(
            validator_id=Uint64(7),
            slot=Slot(1),
            head=Checkpoint(root=block_1_hash, slot=Slot(1)),
            source=Checkpoint(root=genesis_hash, slot=Slot(0)),
            target=Checkpoint(root=block_1_hash, slot=Slot(1)),
        )

        signed_vote = SignedVote(data=vote, signature=Bytes32(b"signature" + b"\x00" * 23))

        # Process as block attestation
        store_with_blocks.process_attestation(signed_vote, is_from_block=True)

        # Should be in known votes
        assert ValidatorIndex(7) in store_with_blocks.latest_known_votes
        assert store_with_blocks.latest_known_votes[ValidatorIndex(7)] == vote.target
        assert ValidatorIndex(7) not in store_with_blocks.latest_new_votes


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_fork_choice_with_min_score(self) -> None:
        """Test fork choice with minimum score threshold."""
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=[]),
        )
        genesis_hash = hash_tree_root(genesis)

        child = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"child" + b"\x00" * 27),
            body=BlockBody(attestations=[]),
        )
        child_hash = hash_tree_root(child)

        blocks = {
            genesis_hash: genesis,
            child_hash: child,
        }

        # Give child only 1 vote
        votes = {ValidatorIndex(0): Checkpoint(root=child_hash, slot=Slot(1))}

        # With min_score = 2, child should be excluded
        head = get_fork_choice_head(blocks, genesis_hash, votes, min_score=2)
        assert head == genesis_hash  # Should stay at genesis

        # With min_score = 1, child should be included
        head = get_fork_choice_head(blocks, genesis_hash, votes, min_score=1)
        assert head == child_hash  # Should choose child

    def test_vote_superseding(self) -> None:
        """Test that newer votes supersede older ones."""
        config = Config(genesis_time=Uint64(1000), num_validators=Uint64(100))

        genesis_state = State.generate_genesis(
            genesis_time=config.genesis_time, num_validators=config.num_validators
        )
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x00" * 32),
            state_root=hash_tree_root(genesis_state),
            body=BlockBody(attestations=[]),
        )

        store = Store.create_forkchoice_store(genesis_state, genesis_block)

        # Add blocks at different slots
        block_1 = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=hash_tree_root(genesis_block),
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

        store.blocks[block_1_hash] = block_1
        store.blocks[block_2_hash] = block_2

        # First vote from validator 0 for slot 1
        old_checkpoint = Checkpoint(root=block_1_hash, slot=Slot(1))
        store.latest_new_votes[ValidatorIndex(0)] = old_checkpoint

        # Newer vote from same validator for slot 2
        new_checkpoint = Checkpoint(root=block_2_hash, slot=Slot(2))
        store.latest_new_votes[ValidatorIndex(0)] = new_checkpoint

        # Should only have the newer vote
        assert store.latest_new_votes[ValidatorIndex(0)] == new_checkpoint
        assert store.latest_new_votes[ValidatorIndex(0)].slot == Slot(2)
