"""Tests for GossipSub protocol implementation."""

import pytest

from lean_spec.subspecs.networking.config import (
    MESSAGE_DOMAIN_INVALID_SNAPPY,
    MESSAGE_DOMAIN_VALID_SNAPPY,
)
from lean_spec.subspecs.networking.gossipsub import (
    GossipsubMessage,
    GossipsubParameters,
    MessageId,
)


class TestGossipsubParameters:
    """Test suite for GossipSub protocol parameters."""

    def test_default_parameters(self) -> None:
        """
        Test default GossipSub parameters and their relationships.

        Validates that default parameter values maintain expected relationships
        for proper protocol operation and that all values are positive.
        """
        params = GossipsubParameters()

        # Test logical relationships
        assert params.d_low < params.d < params.d_high
        assert params.d_lazy <= params.d
        assert params.mcache_gossip <= params.mcache_len

        # Test all timing/count parameters are positive
        positive_params = [
            params.heartbeat_interval_secs,
            params.fanout_ttl_secs,
            params.seen_ttl_secs,
            params.mcache_len,
            params.mcache_gossip,
        ]
        for param in positive_params:
            assert param > 0


class TestGossipsubMessage:
    """Test suite for GossipSub message handling and ID computation."""

    @pytest.mark.parametrize(
        "has_snappy,decompress_succeeds,expected_domain",
        [
            # No decompressor
            (False, False, MESSAGE_DOMAIN_INVALID_SNAPPY),
            # Valid decompression
            (True, True, MESSAGE_DOMAIN_VALID_SNAPPY),
            # Failed decompression
            (True, False, MESSAGE_DOMAIN_INVALID_SNAPPY),
        ],
    )
    def test_message_id_computation(
        self, has_snappy: bool, decompress_succeeds: bool, expected_domain: bytes
    ) -> None:
        """
        Test message ID computation across different snappy scenarios.

        Args:
            has_snappy: Whether to provide a snappy decompressor.
            decompress_succeeds: Whether decompression should succeed.
            expected_domain: Expected domain bytes for ID computation.
        """
        topic = b"test_topic"
        raw_data = b"raw_test_data"
        decompressed_data = b"decompressed_test_data"

        snappy_decompress = None
        if has_snappy:
            if decompress_succeeds:

                def snappy_decompress(data: bytes) -> bytes:
                    return decompressed_data
            else:

                def snappy_decompress(data: bytes) -> bytes:
                    raise Exception("Decompression failed")

        message = GossipsubMessage(topic, raw_data, snappy_decompress)
        message_id = message.id

        # Should always be exactly 20 bytes
        assert len(message_id) == 20
        assert isinstance(message_id, bytes)

        # Test deterministic behavior - same inputs should produce same ID
        message2 = GossipsubMessage(topic, raw_data, snappy_decompress)
        assert message_id == message2.id

        # Test that snappy success/failure affects the ID
        if has_snappy:
            # Create message without snappy - should produce different ID if decompression succeeded
            msg_no_snappy = GossipsubMessage(topic, raw_data, None)
            if decompress_succeeds:
                assert message_id != msg_no_snappy.id  # Different domains
            else:
                # Both use invalid domain, but this tests the flow works
                assert len(msg_no_snappy.id) == 20

    def test_message_id_caching(self) -> None:
        """
        Test that message IDs are cached and deterministic.

        Verifies caching behavior and that identical messages always
        produce the same ID across multiple instantiations.
        """
        topic = b"test_topic"
        data = b"test_data"

        # Test caching within single message
        decompress_calls = 0

        def counting_decompress(data: bytes) -> bytes:
            nonlocal decompress_calls
            decompress_calls += 1
            return b"decompressed"

        message = GossipsubMessage(topic, data, counting_decompress)
        first_id = message.id
        second_id = message.id

        assert decompress_calls == 1  # Called only once (cached)
        assert first_id == second_id
        assert first_id is second_id  # Same object reference

        # Test deterministic behavior across different message instances
        message2 = GossipsubMessage(topic, data)
        message3 = GossipsubMessage(topic, data)

        assert message2.id == message3.id

    @pytest.mark.parametrize(
        "topic,data,description",
        [
            (b"", b"", "empty topic and data"),
            (b"topic", b"data1", "basic case 1"),
            (b"topic", b"data2", "basic case 2"),
            (b"topic1", b"data", "different topic"),
            (b"topic2", b"data", "different topic"),
            (b"x" * 1000, b"y" * 5000, "large inputs"),
            (b"\x00\xff\x01\xfe", bytes(range(16)), "binary data"),
        ],
    )
    def test_message_id_edge_cases(self, topic: bytes, data: bytes, description: str) -> None:
        """
        Test message ID computation across various edge cases and input sizes.

        Parametrized test ensuring the algorithm works correctly with:
        - Empty inputs
        - Different topics/data combinations
        - Large inputs
        - Binary data with null bytes and non-UTF-8 sequences

        Args:
            topic: Topic bytes to test.
            data: Data bytes to test.
            description: Description of the test case.
        """
        message = GossipsubMessage(topic, data)
        message_id = message.id

        # Should always produce exactly 20-byte ID
        assert len(message_id) == 20
        assert isinstance(message_id, bytes)

        # Test deterministic behavior - same inputs produce same ID
        message2 = GossipsubMessage(topic, data)
        assert message_id == message2.id

    def test_message_uniqueness_and_collision_resistance(self) -> None:
        """
        Test message ID uniqueness and collision resistance.

        Ensures different inputs produce different outputs and tests
        resistance to common collision attack patterns.
        """
        # Test cases designed to catch collision vulnerabilities
        test_cases = [
            # Basic different inputs
            (b"topic1", b"data"),
            (b"topic2", b"data"),
            (b"topic", b"data1"),
            (b"topic", b"data2"),
            # Topic/data swapping
            (b"abc", b"def"),
            (b"def", b"abc"),
            # Length-based attacks
            (b"ab", b"cd"),
            (b"a", b"bcd"),
            # Null byte insertion
            (b"topic", b"data"),
            (b"top\x00ic", b"data"),
        ]

        messages = [GossipsubMessage(topic, data) for topic, data in test_cases]
        ids = [msg.id for msg in messages]

        # All IDs should be unique (no collisions)
        assert len(ids) == len(set(ids))

        # All should be 20 bytes
        for msg_id in ids:
            assert len(msg_id) == 20


class TestMessageIdType:
    """Test suite for MessageId type validation."""

    def test_message_id_pydantic_validation(self) -> None:
        """
        Test MessageId validation in Pydantic models.

        The MessageId type annotation includes Pydantic field constraints
        that enforce 20-byte length when used in models.
        """
        from pydantic import BaseModel, ValidationError

        class TestModel(BaseModel):
            msg_id: MessageId

        # Valid 20-byte ID should work
        valid_model = TestModel(msg_id=b"12345678901234567890")
        assert len(valid_model.msg_id) == 20

        # Invalid lengths should raise ValidationError
        invalid_cases = [
            (b"", "empty bytes"),
            (b"short", "too short"),
            (b"too_long_message_id_bytes", "too long"),
        ]

        for invalid_id, _case_desc in invalid_cases:
            with pytest.raises(ValidationError, match=".*"):
                TestModel(msg_id=invalid_id)


class TestGossipsubIntegration:
    """Integration tests for complete GossipSub workflows."""

    def test_realistic_blockchain_scenarios(self) -> None:
        """Test realistic blockchain message scenarios."""
        # Some Ethereum like GossipSub topics and payloads
        scenarios = [
            (b"/eth2/beacon_block/ssz_snappy", b"beacon_block_ssz_data"),
            (b"/eth2/beacon_aggregate_and_proof/ssz_snappy", b"aggregate_proof_ssz"),
            (b"/eth2/voluntary_exit/ssz_snappy", b"voluntary_exit_message"),
        ]

        def mock_snappy_decompress(data: bytes) -> bytes:
            return data + b"_decompressed"  # Simulate decompression

        messages = []
        for topic, data in scenarios:
            # Test both with and without snappy
            msg_with_snappy = GossipsubMessage(topic, data, mock_snappy_decompress)
            msg_without_snappy = GossipsubMessage(topic, data)
            messages.extend([msg_with_snappy, msg_without_snappy])

        ids = [msg.id for msg in messages]

        # All messages should produce valid, unique IDs
        assert len(ids) == len(set(ids))  # All unique
        for msg_id in ids:
            assert len(msg_id) == 20
            assert isinstance(msg_id, bytes)

        # Verify snappy vs non-snappy messages produce different IDs
        for i in range(0, len(messages), 2):
            with_snappy_id = messages[i].id
            without_snappy_id = messages[i + 1].id
            assert with_snappy_id != without_snappy_id
