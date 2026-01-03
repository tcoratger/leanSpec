"""Additional Request/Response Protocols"""

from lean_spec.types import StrictBaseModel

from ..enr.eth2 import AttestationSubnets, SyncCommitteeSubnets
from ..types import DisconnectReason, ProtocolId, SeqNumber

PING_PROTOCOL_V1: ProtocolId = "/leanconsensus/req/ping/1/"
"""Protocol ID for Ping v1."""


class Ping(StrictBaseModel):
    """
    Ping request/response message.

    Ping is used to check liveness and exchange sequence numbers.
    The sequence number indicates the freshness of the node's metadata.
    """

    seq_number: SeqNumber
    """Current metadata sequence number."""


GOODBYE_PROTOCOL_V1: ProtocolId = "/leanconsensus/req/goodbye/1/"
"""Protocol ID for Goodbye v1."""


class Goodbye(StrictBaseModel):
    """
    Goodbye request message for graceful disconnection.

    Sent before closing a connection to inform the peer why
    the connection is being terminated.
    """

    reason: DisconnectReason
    """The reason for disconnection."""


METADATA_PROTOCOL_V1: ProtocolId = "/leanconsensus/req/metadata/1/"
"""Protocol ID for Metadata v1."""


class MetadataRequest(StrictBaseModel):
    """
    Metadata request message.

    An empty request asking for the peer's current metadata.
    """

    pass  # Empty request


class Metadata(StrictBaseModel):
    """
    Metadata response containing node capabilities.

    The metadata describes the node's current subscriptions
    and capabilities. The sequence number increases whenever
    the metadata changes.
    """

    seq_number: SeqNumber
    """Metadata version, increases on any change."""

    attnets: AttestationSubnets
    """Attestation subnet subscriptions."""

    syncnets: SyncCommitteeSubnets
    """Sync committee subnet subscriptions."""
