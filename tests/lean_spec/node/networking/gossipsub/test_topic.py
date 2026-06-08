"""Tests for gossipsub topic parsing and formatting."""

import pytest

from lean_spec.node.networking.gossipsub import (
    ForkMismatchError,
    GossipTopic,
    TopicKind,
    parse_topic_string,
)
from lean_spec.spec.forks import SubnetId


class TestTopicForkValidation:
    """Test suite for topic fork compatibility validation."""

    def test_validate_fork_success(self) -> None:
        """Test validate_fork passes for matching network_name."""
        topic = GossipTopic(kind=TopicKind.BLOCK, network_name="0x12345678")
        topic.validate_fork("0x12345678")  # Should not raise

    def test_validate_fork_raises_on_mismatch(self) -> None:
        """Test validate_fork raises ForkMismatchError on mismatch."""
        topic = GossipTopic(kind=TopicKind.BLOCK, network_name="0x12345678")
        with pytest.raises(ForkMismatchError) as exc_info:
            topic.validate_fork("0xdeadbeef")

        assert exc_info.value.expected == "0xdeadbeef"
        assert exc_info.value.actual == "0x12345678"

    def test_from_string_validated_success(self) -> None:
        """Test from_string_validated parses and validates successfully."""
        assert GossipTopic.from_string_validated(
            "/leanconsensus/0x12345678/block/ssz_snappy",
            expected_network_name="0x12345678",
        ) == GossipTopic(kind=TopicKind.BLOCK, network_name="0x12345678")

    def test_from_string_validated_raises_on_mismatch(self) -> None:
        """Test from_string_validated raises ForkMismatchError on mismatch."""
        with pytest.raises(ForkMismatchError):
            GossipTopic.from_string_validated(
                "/leanconsensus/0x12345678/block/ssz_snappy",
                expected_network_name="0xdeadbeef",
            )

    def test_from_string_validated_raises_on_invalid_topic(self) -> None:
        """Test from_string_validated raises ValueError for invalid topics."""
        with pytest.raises(ValueError) as exception_info:
            GossipTopic.from_string_validated("/invalid/topic", "0x12345678")
        assert str(exception_info.value) == "Invalid topic format: expected 4 parts, got 2"


class TestTopicFormatting:
    """Test suite for topic string formatting and parsing."""

    def test_gossip_topic_creation(self) -> None:
        """Test GossipTopic creation."""
        topic = GossipTopic(kind=TopicKind.BLOCK, network_name="0x12345678")
        assert topic == GossipTopic(kind=TopicKind.BLOCK, network_name="0x12345678")
        assert str(topic) == "/leanconsensus/0x12345678/block/ssz_snappy"

    def test_gossip_topic_from_string(self) -> None:
        """Test parsing topic string."""
        topic_str = "/leanconsensus/0x12345678/block/ssz_snappy"
        assert GossipTopic.from_string(topic_str) == GossipTopic(
            kind=TopicKind.BLOCK, network_name="0x12345678"
        )

    def test_gossip_topic_factory_methods(self) -> None:
        """Test GossipTopic factory methods."""
        assert GossipTopic.block("0xabcd1234") == GossipTopic(
            kind=TopicKind.BLOCK, network_name="0xabcd1234"
        )
        assert GossipTopic.attestation_subnet("0xabcd1234", SubnetId(0)) == GossipTopic(
            kind=TopicKind.ATTESTATION_SUBNET, network_name="0xabcd1234", subnet_id=SubnetId(0)
        )

    def test_parse_topic_string(self) -> None:
        """Test topic string parsing."""
        assert parse_topic_string("/leanconsensus/0x12345678/block/ssz_snappy") == (
            "leanconsensus",
            "0x12345678",
            "block",
            "ssz_snappy",
        )

    def test_invalid_topic_string(self) -> None:
        """Test handling of invalid topic strings."""
        with pytest.raises(ValueError) as exception_info:
            GossipTopic.from_string("/invalid/topic")
        assert str(exception_info.value) == "Invalid topic format: expected 4 parts, got 2"

        with pytest.raises(ValueError) as exception_info:
            GossipTopic.from_string("/wrongprefix/0x123/block/ssz_snappy")
        assert (
            str(exception_info.value)
            == "Invalid prefix: expected 'leanconsensus', got 'wrongprefix'"
        )

    def test_topic_kind_enum(self) -> None:
        """Test TopicKind enum."""
        assert TopicKind.BLOCK.value == "block"
        assert TopicKind.ATTESTATION_SUBNET.value == "attestation"
        assert str(TopicKind.BLOCK) == "block"
