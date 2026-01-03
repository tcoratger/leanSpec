"""
Discovery v5 Message Types
==========================

This module defines the message types used in the Discovery v5 protocol.
All messages are RLP-encoded and sent over UDP.
"""

from lean_spec.types import StrictBaseModel


class Ping(StrictBaseModel):
    """
    PING message for liveness checking.

    Sent to verify that a node is still online and to update
    the routing table entry.

    Attributes:
        request_id: Unique identifier for request/response matching.
        enr_seq: Sender's current ENR sequence number.
    """

    request_id: bytes
    """Random bytes to match request with response (max 8 bytes)."""

    enr_seq: int
    """Sender's ENR sequence number for freshness checking."""


class Pong(StrictBaseModel):
    """
    PONG message in response to PING.

    Attributes:
        request_id: Echoed from the PING request.
        enr_seq: Responder's current ENR sequence number.
        recipient_ip: Sender's observed IP address.
        recipient_port: Sender's observed UDP port.
    """

    request_id: bytes
    """Echoed request_id from PING."""

    enr_seq: int
    """Responder's ENR sequence number."""

    recipient_ip: bytes
    """IP address as seen by the responder (4 or 16 bytes)."""

    recipient_port: int
    """UDP port as seen by the responder."""


class FindNode(StrictBaseModel):
    """
    FINDNODE request to query for nodes near a target.

    The responder returns nodes from their routing table that are
    at the specified distance(s) from themselves.

    Attributes:
        request_id: Unique request identifier.
        distances: List of log2 distances to query (0-256).
    """

    request_id: bytes
    """Random bytes for request/response matching."""

    distances: list[int]
    """
    List of log2 distances to return nodes for.

    Distance 0 returns the node itself (its ENR).
    Distance 256 is the maximum distance.
    """


class Nodes(StrictBaseModel):
    """
    NODES response containing discovered node records.

    May be sent in multiple messages if the response is large.

    Attributes:
        request_id: Echoed from FINDNODE request.
        total: Total number of NODES messages for this request.
        enrs: List of ENR records as RLP-encoded bytes.
    """

    request_id: bytes
    """Echoed request_id from FINDNODE."""

    total: int
    """Total number of NODES responses for this request."""

    enrs: list[bytes]
    """List of RLP-encoded ENR records."""


class TalkReq(StrictBaseModel):
    """
    TALKREQ for application-level protocol negotiation.

    Used by Ethereum clients for topic-based peer discovery
    and subnet advertisement.

    Attributes:
        request_id: Unique request identifier.
        protocol: Protocol identifier string.
        request: Protocol-specific request payload.
    """

    request_id: bytes
    """Random bytes for request/response matching."""

    protocol: bytes
    """Protocol identifier (e.g., b"eth2" for consensus)."""

    request: bytes
    """Protocol-specific request payload."""


class TalkResp(StrictBaseModel):
    """
    TALKRESP response to TALKREQ.

    Attributes:
        request_id: Echoed from TALKREQ.
        response: Protocol-specific response payload.
    """

    request_id: bytes
    """Echoed request_id from TALKREQ."""

    response: bytes
    """Protocol-specific response payload."""
