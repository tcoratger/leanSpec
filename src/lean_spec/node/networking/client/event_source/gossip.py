"""Decoder for inbound gossipsub messages."""

from __future__ import annotations

from dataclasses import dataclass

from lean_spec.node.networking.client.event_source.protocol import GossipMessageError
from lean_spec.node.networking.gossipsub.topic import (
    ForkMismatchError,
    GossipTopic,
    TopicKind,
)
from lean_spec.node.snappy import SnappyDecompressionError, decompress
from lean_spec.spec.forks import SignedAggregatedAttestation, SignedAttestation, SignedBlock
from lean_spec.spec.ssz.exceptions import SSZSerializationError


@dataclass(slots=True)
class GossipHandler:
    """
    Handles incoming gossip messages from peers.

    Parses gossip message format, decompresses Snappy, decodes SSZ, and
    returns the appropriate decoded object.

    Supported topic kinds:

    - Block: Decodes to SignedBlock
    - Attestation: Decodes to SignedAttestation


    WHY TOPIC VALIDATION?
    ---------------------
    Topics contain:

    - Network name: 4-byte identifier derived from genesis + fork version.
    - Message type: "blocks" or "attestation".
    - Encoding: Always "ssz_snappy" for Ethereum.

    Validating the topic prevents:

    - Routing attacks: Reject messages for different forks.
    - Type confusion: Ensure we decode with the correct schema.
    - Protocol violations: Reject malformed topic strings.


    WHY SNAPPY?
    -----------
    Snappy reduces bandwidth by 50-70% for typical consensus messages.
    Beacon blocks contain many signatures and hashes which compress well.
    The framing format adds CRC32C checksums for corruption detection.


    WHY SSZ?
    --------
    SSZ (Simple Serialize) is Ethereum's canonical format because:

    - Deterministic: Same object always produces same bytes.
    - Merkleizable: Efficient proofs of inclusion.
    - Schema-driven: Type information comes from context, not wire format.

    The topic tells us the schema. The SSZ bytes are just raw data.
    """

    network_name: str
    """Expected network name for topic validation.

    Messages with mismatched fork digests are rejected. This prevents
    cross-fork message injection attacks.
    """

    def decode_message(
        self,
        topic_str: str,
        compressed_data: bytes,
    ) -> SignedBlock | SignedAttestation | SignedAggregatedAttestation | None:
        """
        Decode a gossip message from topic and compressed data.

        Processing proceeds in order:

        1. Parse topic to determine message type.
        2. Validate network name.
        3. Decompress Snappy-framed data.
        4. Decode SSZ bytes using the appropriate schema.

        Each step can fail independently. Failures are wrapped in
        GossipMessageError for uniform handling. Fork mismatches raise
        ForkMismatchError.

        Args:
            topic_str: Full topic string (e.g., "/leanconsensus/0x.../block/ssz_snappy").
            compressed_data: Snappy-compressed SSZ data.

        Returns:
            Decoded block or attestation.

        Raises:
            ForkMismatchError: If network_name does not match.
            GossipMessageError: If the message cannot be decoded.
        """
        # Step 1: Parse topic to determine message type and validate fork.
        #
        # The topic string contains the network name and message kind.
        # Invalid topics are rejected before decompression to avoid
        # wasting CPU on malformed or cross-fork messages.
        try:
            topic = GossipTopic.from_string_validated(topic_str, self.network_name)
        except ForkMismatchError:
            raise
        except ValueError as exception:
            raise GossipMessageError(f"Invalid topic: {exception}") from exception

        # Step 2: Decompress raw Snappy data.
        #
        # Gossip uses raw Snappy block format (not framing).
        # This matches libp2p gossipsub's SnappyTransform behavior.
        #
        # Failed decompression indicates network corruption or a malicious peer.
        try:
            ssz_bytes = decompress(compressed_data)
        except SnappyDecompressionError as exception:
            raise GossipMessageError(f"Snappy decompression failed: {exception}") from exception

        # Step 3: Decode SSZ based on topic kind.
        #
        # SSZ decoding fails if the bytes don't match the expected schema.
        # For example: wrong length, invalid field values, or truncation.
        #
        # The topic determines which schema to use. This is why topic
        # validation must happen first.
        try:
            match topic.kind:
                case TopicKind.BLOCK:
                    return SignedBlock.decode_bytes(ssz_bytes)
                case TopicKind.ATTESTATION_SUBNET:
                    return SignedAttestation.decode_bytes(ssz_bytes)
                case TopicKind.AGGREGATED_ATTESTATION:
                    return SignedAggregatedAttestation.decode_bytes(ssz_bytes)
        except SSZSerializationError as exception:
            raise GossipMessageError(f"SSZ decode failed: {exception}") from exception

    def get_topic(self, topic_str: str) -> GossipTopic:
        """
        Parse and validate a topic string without decoding the payload.

        Useful when only topic validation is needed (e.g., checking fork
        digest before investing in decompression/deserialization).

        Args:
            topic_str: Full topic string.

        Returns:
            Parsed GossipTopic.

        Raises:
            ForkMismatchError: If network_name does not match.
            GossipMessageError: If the topic is invalid.
        """
        try:
            return GossipTopic.from_string_validated(topic_str, self.network_name)
        except ForkMismatchError:
            raise
        except ValueError as exception:
            raise GossipMessageError(f"Invalid topic: {exception}") from exception
