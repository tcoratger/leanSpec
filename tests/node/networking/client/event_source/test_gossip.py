"""
Tests for the gossip message handler.

This module tests the GossipHandler class and GossipMessageError exception
that handle incoming gossip messages from peers in the P2P network.
"""

from __future__ import annotations

import pytest

from consensus_testing import make_signed_attestation, make_signed_block
from lean_spec.node.networking.client.event_source import (
    GossipHandler,
    GossipMessageError,
)
from lean_spec.node.networking.gossipsub.topic import (
    ENCODING_POSTFIX,
    TOPIC_PREFIX,
    ForkMismatchError,
    GossipTopic,
    TopicKind,
)
from lean_spec.node.snappy import compress
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import SignedAttestation, SignedBlock
from lean_spec.spec.ssz import Bytes32

FORK_DIGEST = "0xaabbccdd"
WRONG_FORK_DIGEST = "0x11223344"


def _block_topic(digest: str = FORK_DIGEST) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/block/{ENCODING_POSTFIX}"


def _attestation_topic(digest: str = FORK_DIGEST, subnet_id: int = 0) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/attestation_{subnet_id}/{ENCODING_POSTFIX}"


def _aggregation_topic(digest: str = FORK_DIGEST) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/aggregation/{ENCODING_POSTFIX}"


def _make_block() -> SignedBlock:
    return make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
    )


def _make_attestation() -> SignedAttestation:
    return make_signed_attestation(
        validator=ValidatorIndex(0),
        target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
    )


def make_block_topic(network_name: str = "0x00000000") -> str:
    """Create a valid block topic string."""
    return f"/{TOPIC_PREFIX}/{network_name}/block/{ENCODING_POSTFIX}"


def make_attestation_topic(network_name: str = "0x00000000", subnet_id: int = 0) -> str:
    """Create a valid attestation subnet topic string."""
    return f"/{TOPIC_PREFIX}/{network_name}/attestation_{subnet_id}/{ENCODING_POSTFIX}"


def make_test_signed_block() -> SignedBlock:
    """Create a minimal signed block for testing."""
    return make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
    )


def make_test_signed_attestation() -> SignedAttestation:
    """Create a minimal signed attestation for testing."""
    return make_signed_attestation(
        validator=ValidatorIndex(0),
        target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
    )


class TestGossipMessageError:
    """Tests for the GossipMessageError exception."""

    def test_is_exception_subclass(self) -> None:
        """GossipMessageError inherits from Exception."""
        assert issubclass(GossipMessageError, Exception)

    def test_message_preserved(self) -> None:
        """Error message is preserved."""
        message = "Test error message"
        error = GossipMessageError(message)
        assert str(error) == message

    def test_can_be_raised_and_caught(self) -> None:
        """Can be raised and caught properly."""
        with pytest.raises(GossipMessageError) as exception_info:
            raise GossipMessageError("specific error")
        assert str(exception_info.value) == "specific error"


class TestGossipHandlerGetTopic:
    """Tests for GossipHandler.get_topic() method."""

    def test_valid_block_topic(self) -> None:
        """Parses valid block topic string."""
        handler = GossipHandler(network_name="0x12345678")
        topic_str = "/leanconsensus/0x12345678/block/ssz_snappy"

        topic = handler.get_topic(topic_str)

        assert isinstance(topic, GossipTopic)
        assert topic.kind == TopicKind.BLOCK
        assert topic.network_name == "0x12345678"

    def test_valid_attestation_subnet_topic(self) -> None:
        """Parses valid attestation subnet topic string."""
        handler = GossipHandler(network_name="0x00000000")
        topic_str = "/leanconsensus/0x00000000/attestation_0/ssz_snappy"

        topic = handler.get_topic(topic_str)

        assert isinstance(topic, GossipTopic)
        assert topic.kind == TopicKind.ATTESTATION_SUBNET
        assert topic.network_name == "0x00000000"

    def test_invalid_topic_format_missing_parts(self) -> None:
        """Raises GossipMessageError for topic with missing parts."""
        handler = GossipHandler(network_name="0x00000000")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.get_topic("/invalid/topic")
        assert str(exception_info.value) == (
            "Invalid topic: Invalid topic format: expected 4 parts, got 2"
        )

    def test_invalid_topic_format_wrong_prefix(self) -> None:
        """Raises GossipMessageError for wrong network prefix."""
        handler = GossipHandler(network_name="0x00000000")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.get_topic("/wrongprefix/0x00000000/block/ssz_snappy")
        assert str(exception_info.value) == (
            "Invalid topic: Invalid prefix: expected 'leanconsensus', got 'wrongprefix'"
        )

    def test_invalid_topic_format_wrong_encoding(self) -> None:
        """Raises GossipMessageError for wrong encoding suffix."""
        handler = GossipHandler(network_name="0x00000000")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.get_topic("/leanconsensus/0x00000000/block/ssz")
        assert str(exception_info.value) == (
            "Invalid topic: Invalid encoding: expected 'ssz_snappy', got 'ssz'"
        )

    def test_invalid_topic_format_unknown_topic_name(self) -> None:
        """Raises GossipMessageError for unknown topic name."""
        handler = GossipHandler(network_name="0x00000000")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.get_topic("/leanconsensus/0x00000000/unknown/ssz_snappy")
        assert str(exception_info.value) == "Invalid topic: Unknown topic: 'unknown'"

    def test_empty_topic_string(self) -> None:
        """Raises GossipMessageError for empty topic string."""
        handler = GossipHandler(network_name="0x00000000")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.get_topic("")
        assert str(exception_info.value) == (
            "Invalid topic: Invalid topic format: expected 4 parts, got 1"
        )


class TestGossipHandlerDecodeMessage:
    """Tests for GossipHandler.decode_message() method."""

    def test_decode_valid_block_message(self) -> None:
        """Decodes valid block message correctly."""
        handler = GossipHandler(network_name="0x00000000")
        block = make_test_signed_block()
        ssz_bytes = block.encode_bytes()
        compressed = compress(ssz_bytes)
        topic_str = make_block_topic()

        decoded_message = handler.decode_message(topic_str, compressed)

        assert isinstance(decoded_message, SignedBlock)

    def test_decode_valid_attestation_message(self) -> None:
        """Decodes valid attestation message correctly."""
        handler = GossipHandler(network_name="0x00000000")
        attestation = make_test_signed_attestation()
        ssz_bytes = attestation.encode_bytes()
        compressed = compress(ssz_bytes)
        topic_str = make_attestation_topic()

        decoded_message = handler.decode_message(topic_str, compressed)

        assert isinstance(decoded_message, SignedAttestation)

    def test_decode_invalid_topic_format(self) -> None:
        """Raises GossipMessageError for invalid topic format."""
        handler = GossipHandler(network_name="0x00000000")
        compressed = compress(b"\x00" * 32)

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message("/bad/topic", compressed)
        assert str(exception_info.value) == (
            "Invalid topic: Invalid topic format: expected 4 parts, got 2"
        )

    def test_decode_invalid_snappy_compression(self) -> None:
        """Raises GossipMessageError for invalid Snappy data."""
        handler = GossipHandler(network_name="0x00000000")
        topic_str = make_block_topic()
        # Invalid snappy: claims uncompressed length of 1000 bytes but has truncated data
        # Snappy format: [uncompressed_length varint][compressed_data]
        invalid_snappy = b"\xe8\x07"  # varint for 1000, but no data following

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(topic_str, invalid_snappy)
        assert str(exception_info.value) == (
            "Snappy decompression failed: "
            "Unexpected end of input at position 2, output has 0 bytes but expected 1000"
        )

    def test_decode_invalid_ssz_encoding(self) -> None:
        """Raises GossipMessageError for invalid SSZ data."""
        handler = GossipHandler(network_name="0x00000000")
        topic_str = make_block_topic()
        # Valid Snappy compression wrapping garbage SSZ
        compressed = compress(b"\xff\xff\xff\xff")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(topic_str, compressed)
        assert str(exception_info.value) == "SSZ decode failed: Uint32: expected 4 bytes, got 0"

    def test_decode_empty_snappy_data(self) -> None:
        """Raises GossipMessageError for empty compressed data."""
        handler = GossipHandler(network_name="0x00000000")
        topic_str = make_block_topic()

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(topic_str, b"")
        assert str(exception_info.value) == "Snappy decompression failed: Empty input"

    def test_decode_truncated_ssz_data(self) -> None:
        """Raises GossipMessageError for truncated SSZ data."""
        handler = GossipHandler(network_name="0x00000000")
        block = make_test_signed_block()
        ssz_bytes = block.encode_bytes()
        truncated = ssz_bytes[:10]  # Truncate SSZ data
        compressed = compress(truncated)
        topic_str = make_block_topic()

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(topic_str, compressed)
        assert str(exception_info.value) == "SSZ decode failed: Slot: expected 8 bytes, got 2"


class TestGossipReceptionEdgeCases:
    """Edge case tests for gossip reception."""

    def test_handler_fork_digest_stored(self) -> None:
        """Handler stores network name for topic validation."""
        digest = "0xaabbccdd"
        handler = GossipHandler(network_name=digest)
        assert handler.network_name == digest

    def test_handler_with_different_fork_digests(self) -> None:
        """Handler works with various network name formats."""
        for digest in ["0x00000000", "0xffffffff", "0x12345678", "0xabcdef01"]:
            handler = GossipHandler(network_name=digest)
            topic_str = f"/{TOPIC_PREFIX}/{digest}/block/{ENCODING_POSTFIX}"
            topic = handler.get_topic(topic_str)
            assert topic.network_name == digest

    def test_decode_corrupted_snappy_data(self) -> None:
        """Detects corruption in Snappy compressed data."""
        handler = GossipHandler(network_name="0x00000000")
        topic_str = make_block_topic()

        # Create truncated snappy data that claims large uncompressed length
        # This will fail during decompression with "Truncated" or similar error
        corrupted = b"\xff\xff\xff\x7f"  # varint claiming huge uncompressed length

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(topic_str, corrupted)
        assert str(exception_info.value) == (
            "Snappy decompression failed: "
            "Unexpected end of input at position 4, output has 0 bytes but expected 268435455"
        )


class TestGossipHandlerForkMismatch:
    """
    Network name validation on incoming gossip messages.

    Every gossip topic embeds a network name identifying the consensus fork.
    Messages from peers on a different fork must be rejected immediately
    to avoid processing incompatible data.
    """

    def test_decode_message_raises_fork_mismatch(self) -> None:
        """Rejects messages whose topic carries a different network name."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        block = _make_block()
        compressed = compress(block.encode_bytes())

        with pytest.raises(ForkMismatchError) as exception_info:
            handler.decode_message(_block_topic(WRONG_FORK_DIGEST), compressed)
        assert str(exception_info.value) == (
            f"Fork mismatch: expected {FORK_DIGEST}, got {WRONG_FORK_DIGEST}"
        )

    def test_get_topic_raises_fork_mismatch(self) -> None:
        """Rejects topic strings with mismatched network name."""
        handler = GossipHandler(network_name=FORK_DIGEST)

        with pytest.raises(ForkMismatchError) as exception_info:
            handler.get_topic(_block_topic(WRONG_FORK_DIGEST))
        assert str(exception_info.value) == (
            f"Fork mismatch: expected {FORK_DIGEST}, got {WRONG_FORK_DIGEST}"
        )

    def test_fork_mismatch_error_attributes(self) -> None:
        """ForkMismatchError exposes expected and actual digests."""
        error = ForkMismatchError(expected=FORK_DIGEST, actual=WRONG_FORK_DIGEST)

        assert error.expected == FORK_DIGEST
        assert error.actual == WRONG_FORK_DIGEST

    def test_fork_mismatch_is_value_error(self) -> None:
        """ForkMismatchError inherits from ValueError."""
        assert issubclass(ForkMismatchError, ValueError)

    def test_decode_message_fork_mismatch_not_wrapped_as_gossip_error(self) -> None:
        """ForkMismatchError propagates directly, not wrapped in GossipMessageError."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        compressed = compress(b"\x00" * 32)

        with pytest.raises(ForkMismatchError):
            handler.decode_message(_block_topic(WRONG_FORK_DIGEST), compressed)

        # Verify it does NOT raise GossipMessageError
        try:
            handler.decode_message(_block_topic(WRONG_FORK_DIGEST), compressed)
        except ForkMismatchError:
            pass
        except GossipMessageError:
            pytest.fail("ForkMismatchError should not be wrapped in GossipMessageError")


class TestGossipHandlerAggregationTopic:
    """
    Aggregated attestation topic parsing and decoding.

    The aggregation topic carries attestations that have been aggregated
    by a committee member. The gossip handler must recognize this topic
    kind and decode its SSZ payload accordingly.
    """

    def test_get_topic_recognizes_aggregation(self) -> None:
        """Parses aggregation topic and returns AGGREGATED_ATTESTATION kind."""
        handler = GossipHandler(network_name=FORK_DIGEST)

        topic = handler.get_topic(_aggregation_topic())

        assert topic == GossipTopic(
            kind=TopicKind.AGGREGATED_ATTESTATION,
            network_name=FORK_DIGEST,
        )

    def test_decode_message_invalid_ssz_for_aggregation(self) -> None:
        """Raises GossipMessageError when SSZ bytes are invalid for aggregation."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        compressed = compress(b"\xff\xff\xff\xff")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(_aggregation_topic(), compressed)
        assert str(exception_info.value) == "SSZ decode failed: Slot: expected 8 bytes, got 4"


class TestGossipHandlerDecodeRoundtrip:
    """
    SSZ encode-compress-decode roundtrip fidelity.

    Gossip messages are SSZ-encoded, Snappy-compressed, and sent over
    the wire. Decoding must recover the original SSZ bytes exactly,
    ensuring no data loss through the compression layer.
    """

    def test_block_roundtrip_preserves_ssz(self) -> None:
        """Block SSZ bytes are identical after decode."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        block = _make_block()
        original_bytes = block.encode_bytes()

        decoded_message = handler.decode_message(
            _block_topic(),
            compress(original_bytes),
        )

        assert isinstance(decoded_message, SignedBlock)
        assert decoded_message.encode_bytes() == original_bytes

    def test_attestation_roundtrip_preserves_ssz(self) -> None:
        """Attestation SSZ bytes are identical after decode."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        attestation = _make_attestation()
        original_bytes = attestation.encode_bytes()

        decoded_message = handler.decode_message(
            _attestation_topic(),
            compress(original_bytes),
        )

        assert isinstance(decoded_message, SignedAttestation)
        assert decoded_message.encode_bytes() == original_bytes


class TestGossipHandlerForkValidation:
    """Test suite for GossipHandler fork compatibility validation."""

    def test_decode_message_rejects_wrong_fork(self) -> None:
        """GossipHandler.decode_message() raises ForkMismatchError for wrong fork."""
        handler = GossipHandler(network_name="0x12345678")

        # Topic with different network_name
        wrong_fork_topic = "/leanconsensus/0xdeadbeef/block/ssz_snappy"

        with pytest.raises(ForkMismatchError) as exc_info:
            handler.decode_message(wrong_fork_topic, b"dummy_data")

        assert exc_info.value.expected == "0x12345678"
        assert exc_info.value.actual == "0xdeadbeef"

    def test_get_topic_rejects_wrong_fork(self) -> None:
        """GossipHandler.get_topic() raises ForkMismatchError for wrong fork."""
        handler = GossipHandler(network_name="0x12345678")

        # Topic with different network_name
        wrong_fork_topic = "/leanconsensus/0xdeadbeef/attestation/ssz_snappy"

        with pytest.raises(ForkMismatchError) as exc_info:
            handler.get_topic(wrong_fork_topic)

        assert exc_info.value.expected == "0x12345678"
        assert exc_info.value.actual == "0xdeadbeef"

    def test_get_topic_accepts_matching_fork(self) -> None:
        """GossipHandler.get_topic() returns topic for matching fork."""
        handler = GossipHandler(network_name="0x12345678")
        assert handler.get_topic("/leanconsensus/0x12345678/block/ssz_snappy") == GossipTopic(
            kind=TopicKind.BLOCK, network_name="0x12345678"
        )
