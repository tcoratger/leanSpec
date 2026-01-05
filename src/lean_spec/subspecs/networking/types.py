"""Networking-related type definitions for the specification."""

from lean_spec.types import Uint64
from lean_spec.types.byte_arrays import Bytes4, Bytes32

DomainType = Bytes4
"""A 4-byte value used for domain separation in message-ids."""

NodeId = Bytes32
"""32-byte node identifier for Discovery v5, derived from ``keccak256(pubkey)``."""

ProtocolId = str
"""A string representing a libp2p protocol ID."""

SeqNumber = Uint64
"""Sequence number used in ENR records, metadata, and ping messages."""

SubnetId = Uint64
"""Subnet identifier (0-63) for attestation subnet partitioning."""

Multiaddr = str
"""Multiaddress string, e.g. ``/ip4/192.168.1.1/tcp/9000``."""

ForkDigest = Bytes4
"""4-byte fork identifier ensuring network isolation between forks."""
