"""
Wire-format parser for inbound gossipsub messages.

GOSSIP MESSAGE FORMAT
---------------------
Incoming gossip messages arrive on QUIC streams with the gossipsub protocol ID.
The message format is:

+------------------+---------------------------------------------+
| Field            | Description                                 |
+==================+=============================================+
| topic_length     | Varint: byte length of the topic string     |
+------------------+---------------------------------------------+
| topic            | UTF-8 string identifying message type       |
+------------------+---------------------------------------------+
| data_length      | Varint: byte length of compressed data      |
+------------------+---------------------------------------------+
| data             | Snappy-compressed SSZ-encoded message       |
+------------------+---------------------------------------------+

Varints use LEB128 encoding (1-10 bytes depending on value).
Most lengths fit in 1-2 bytes since messages are typically under 16KB.


MESSAGE DEDUPLICATION
---------------------
Gossipsub uses message IDs to prevent duplicate delivery. The Ethereum
consensus spec defines message ID as:

    message_id = SHA256(MESSAGE_DOMAIN + topic_length + topic + data)[:20]

MESSAGE_DOMAIN is 0x00 for invalid Snappy, 0x01 for valid Snappy. This
domain separation ensures a message cannot be "replayed" by flipping
between compressed and raw forms.
"""

from __future__ import annotations

from dataclasses import dataclass

from lean_spec.node.networking.client.event_source.protocol import GossipMessageError
from lean_spec.node.networking.gossipsub.topic import (
    ForkMismatchError,
    GossipTopic,
)
from lean_spec.node.networking.transport.protocols import InboundStreamProtocol
from lean_spec.node.networking.varint import VarintError, decode_varint


@dataclass(slots=True)
class GossipHandler:
    """
    Parses and validates topics for incoming gossip messages from peers.

    Topics contain:

    - Network name: 4-byte identifier derived from genesis + fork version.
    - Message type: "blocks" or "attestation".
    - Encoding: Always "ssz_snappy" for Ethereum.

    Validating the topic prevents:

    - Routing attacks: Reject messages for different forks.
    - Type confusion: Ensure we decode with the correct schema.
    - Protocol violations: Reject malformed topic strings.
    """

    network_name: str
    """Expected network name for topic validation.

    Messages with mismatched fork digests are rejected. This prevents
    cross-fork message injection attacks.
    """

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


async def read_gossip_message(stream: InboundStreamProtocol) -> tuple[str, bytes]:
    """
    Read a gossip message from a QUIC stream.

    Gossip message wire format::

        [topic_length: varint][topic: UTF-8][data_length: varint][data: bytes]

    Args:
        stream: QUIC stream to read from.

    Returns:
        Tuple of (topic_string, compressed_data).

    Raises:
        GossipMessageError: If the message format is invalid.


    WHY VARINTS?
    ------------
    Varints (LEB128 encoding) use 1 byte for values 0-127, 2 bytes for
    128-16383, etc. Since topic lengths are typically ~50 bytes and data
    lengths under 1MB, varints save bandwidth compared to fixed-width integers.

    The libp2p gossipsub wire format uses varints throughout.


    WHY INCREMENTAL PARSING?
    ------------------------
    Varints have variable length. We cannot know how many bytes to read
    for the topic length until we try to decode it. The incremental
    approach:

    1. Read available data into buffer.
    2. Try to parse varint. If not enough bytes, read more.
    3. Once varint is complete, read the indicated payload.
    4. Repeat for data length and data payload.

    This handles network fragmentation gracefully. Data may arrive in
    arbitrary chunks due to QUIC framing.


    EDGE CASES HANDLED
    ------------------
    - Truncated varint: VarintError raised, we keep reading.
    - Truncated topic/data: Loop continues until complete.
    - Empty message: Caught before any parsing.
    - Invalid UTF-8 topic: GossipMessageError raised.
    - Stream closes early: GossipMessageError with "Truncated" message.
    """
    # Accumulate data in a buffer.
    #
    # Network data arrives in arbitrary chunks. We need to buffer until
    # we have complete fields. A bytearray is efficient for appending.
    buffer = bytearray()

    # Read and parse incrementally.
    #
    # The outer loop reads chunks from the network.
    # The inner parsing attempts to extract fields from the buffer.
    # We only return once we have a complete message.
    while True:
        chunk = await stream.read()
        if not chunk:
            # Stream closed. If buffer is empty, peer sent nothing.
            # If buffer has data, the message is incomplete.
            if not buffer:
                raise GossipMessageError("Empty gossip message")
            break
        buffer.extend(chunk)

        # Attempt to parse the accumulated data.
        #
        # Parsing can fail partway through if we don't have enough bytes.
        # In that case, we continue the outer loop to read more data.
        try:
            # Parse topic length varint.
            #
            # The varint tells us how many bytes the topic string occupies.
            # Most topics are ~50 bytes, so this is typically a 1-byte varint.
            topic_length, topic_length_bytes = decode_varint(bytes(buffer), 0)
            topic_end = topic_length_bytes + topic_length

            if len(buffer) >= topic_end:
                # We have the complete topic string.
                #
                # Topics are UTF-8 encoded. Invalid encoding indicates
                # a protocol violation or corrupted data.
                topic_str = buffer[topic_length_bytes:topic_end].decode("utf-8")

                if len(buffer) > topic_end:
                    # Parse data length varint.
                    #
                    # This tells us how many bytes of compressed data follow.
                    # Block messages can be several hundred KB compressed.
                    data_length, data_length_bytes = decode_varint(bytes(buffer), topic_end)
                    data_start = topic_end + data_length_bytes
                    data_end = data_start + data_length

                    if len(buffer) >= data_end:
                        # We have the complete message.
                        #
                        # Extract the compressed data and return.
                        # The caller will decompress and decode.
                        compressed_data = bytes(buffer[data_start:data_end])
                        return topic_str, compressed_data

        except VarintError:
            # Varint is incomplete (truncated in the middle).
            #
            # This is normal - we may have read only part of a varint.
            # Continue reading more data from the stream.
            continue

        except UnicodeDecodeError as exception:
            # Topic bytes are not valid UTF-8.
            #
            # This indicates a protocol violation or corruption.
            # Fail immediately rather than trying to recover.
            raise GossipMessageError(f"Invalid topic encoding: {exception}") from exception

    # Loop exited without returning a complete message.
    #
    # The stream closed before we received all expected data.
    # This could be a network failure or peer misbehavior.
    raise GossipMessageError("Truncated gossip message")
