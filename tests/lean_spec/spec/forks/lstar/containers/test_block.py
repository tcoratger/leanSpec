"""Tests for the Block container family."""

import pytest
from pydantic import ValidationError

from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestations,
    Block,
    BlockBody,
    BlockHeader,
    MultiMessageAggregate,
    SignedBlock,
)
from lean_spec.spec.ssz import ByteList512KiB, Bytes32


def _empty_body() -> BlockBody:
    """A block body carrying no attestations."""
    return BlockBody(attestations=AggregatedAttestations(data=[]))


def _block() -> Block:
    """A minimal block with a zeroed state root and an empty body."""
    return Block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body=_empty_body(),
    )


class TestBlockBodyImmutability:
    """Frozen-model semantics forbid post-construction mutation."""

    def test_assigning_attestations_raises(self) -> None:
        """Assigning new attestations on a constructed body raises."""
        body = _empty_body()
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for BlockBody\nattestations\n"
            r"  Instance is frozen \[type=frozen_instance, input_value=.*, "
            r"input_type=.*\]\n    For further information visit "
            r"https://errors\.pydantic\.dev/[^\s]+/v/frozen_instance\Z",
        ):
            body.attestations = AggregatedAttestations(data=[])


class TestBlockHeaderImmutability:
    """Frozen-model semantics forbid post-construction mutation."""

    def test_assigning_state_root_raises(self) -> None:
        """Assigning a new state root on a constructed header raises."""
        header = BlockHeader(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=Bytes32.zero(),
        )
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for BlockHeader\nstate_root\n"
            r"  Instance is frozen \[type=frozen_instance, input_value=.*, "
            r"input_type=.*\]\n    For further information visit "
            r"https://errors\.pydantic\.dev/[^\s]+/v/frozen_instance\Z",
        ):
            header.state_root = Bytes32(b"\xff" * 32)


class TestBlockImmutability:
    """Frozen-model semantics forbid post-construction mutation."""

    def test_assigning_state_root_raises(self) -> None:
        """Assigning a new state root on a constructed block raises."""
        block = _block()
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for Block\nstate_root\n"
            r"  Instance is frozen \[type=frozen_instance, input_value=.*, "
            r"input_type=.*\]\n    For further information visit "
            r"https://errors\.pydantic\.dev/[^\s]+/v/frozen_instance\Z",
        ):
            block.state_root = Bytes32(b"\xff" * 32)

    def test_assigning_body_raises(self) -> None:
        """Assigning a new body on a constructed block raises."""
        block = _block()
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for Block\nbody\n"
            r"  Instance is frozen \[type=frozen_instance, input_value=.*, "
            r"input_type=.*\]\n    For further information visit "
            r"https://errors\.pydantic\.dev/[^\s]+/v/frozen_instance\Z",
        ):
            block.body = _empty_body()


class TestSignedBlockImmutability:
    """Frozen-model semantics forbid post-construction mutation."""

    def test_assigning_proof_raises(self) -> None:
        """Assigning a new proof on a constructed signed block raises."""
        proof = MultiMessageAggregate(proof=ByteList512KiB(data=b""))
        signed_block = SignedBlock(block=_block(), proof=proof)
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for SignedBlock\nproof\n"
            r"  Instance is frozen \[type=frozen_instance, input_value=.*, "
            r"input_type=.*\]\n    For further information visit "
            r"https://errors\.pydantic\.dev/[^\s]+/v/frozen_instance\Z",
        ):
            signed_block.proof = proof
