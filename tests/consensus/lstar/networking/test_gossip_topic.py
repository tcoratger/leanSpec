"""Test vectors for gossipsub topic string encoding and parsing."""

import pytest

from consensus_testing import GossipTopicRoundtrip, NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

FORK_DIGEST = "12345678"
"""Arbitrary fork digest used across topic tests."""


# --- Block topics ---


def test_block_topic(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Block topic with typical fork digest."""
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="block", network_name=FORK_DIGEST),
    )


def test_block_topic_different_digest(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Block topic with a different fork digest to verify digest embedding."""
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="block", network_name="aabbccdd"),
    )


# --- Aggregation topics ---


def test_aggregation_topic(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Committee aggregation topic."""
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="aggregation", network_name=FORK_DIGEST),
    )


# --- Attestation subnet topics ---


def test_attestation_subnet_zero(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Attestation subnet 0. First subnet ID."""
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="attestation", network_name=FORK_DIGEST, subnet_id=0),
    )


def test_attestation_subnet_seven(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Attestation subnet 7. Mid-range subnet ID."""
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="attestation", network_name=FORK_DIGEST, subnet_id=7),
    )


def test_attestation_subnet_63(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Attestation subnet 63. Last subnet in a 64-subnet network."""
    networking_codec_test(
        codec=GossipTopicRoundtrip(
            topic_kind="attestation", network_name=FORK_DIGEST, subnet_id=63
        ),
    )


# --- Edge cases ---


def test_block_topic_zero_digest(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Block topic with all-zero fork digest."""
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="block", network_name="00000000"),
    )


def test_block_topic_max_digest(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Block topic with all-0xff fork digest."""
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="block", network_name="ffffffff"),
    )
