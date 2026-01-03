"""
Ethereum Node Records (EIP-778)
===============================

ENR is an open format for p2p connectivity information that enables:

- Arbitrary key/value pairs for transport protocols
- Multiple identity schemes (currently "v4" with secp256k1)
- Authoritative updates via sequence numbers

Record Format::

    record = [signature, seq, k1, v1, k2, v2, ...]

Max size: 300 bytes. Text form: `enr:` + URL-safe base64.

References:
----------
- EIP-778: https://eips.ethereum.org/EIPS/eip-778
"""

from .enr import ENR
from .eth2 import FAR_FUTURE_EPOCH, AttestationSubnets, Eth2Data, SyncCommitteeSubnets
from .keys import EnrKey

__all__ = [
    "ENR",
    "EnrKey",
    "Eth2Data",
    "AttestationSubnets",
    "SyncCommitteeSubnets",
    "FAR_FUTURE_EPOCH",
]
