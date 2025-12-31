"""Validator container for the Lean Ethereum consensus specification."""

from __future__ import annotations

from lean_spec.types import Bytes52, Container, Uint64

from ..xmss.containers import PublicKey


class Validator(Container):
    """Represents a validator's static metadata and operational interface."""

    pubkey: Bytes52
    """XMSS one-time signature public key."""

    index: Uint64 = Uint64(0)
    """Validator index in the registry."""

    def get_pubkey(self) -> PublicKey:
        """Get the XMSS public key from this validator."""
        return PublicKey.decode_bytes(bytes(self.pubkey))
