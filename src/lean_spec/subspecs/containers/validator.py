"""Validator container for the Lean Ethereum consensus specification."""

from lean_spec.types import Bytes52, Container

from ..xmss.containers import PublicKey
from ..xmss.interface import PROD_SIGNATURE_SCHEME, GeneralizedXmssScheme


class Validator(Container):
    """Represents a validator's static metadata."""

    pubkey: Bytes52
    """XMSS one-time signature public key."""

    def get_pubkey(self, scheme: GeneralizedXmssScheme = PROD_SIGNATURE_SCHEME) -> PublicKey:
        """
        Get the XMSS public key from this validator.

        Args:
            scheme: The XMSS signature scheme to use (defaults to PROD_SIGNATURE_SCHEME).

        Returns:
            The parsed XMSS public key.
        """
        return PublicKey.from_bytes(bytes(self.pubkey), scheme.config)
