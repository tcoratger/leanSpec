"""Validator container for the Lean Ethereum consensus specification."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lean_spec.types import Bytes52, Container, ValidatorIndex

from ..xmss.containers import PublicKey
from ..xmss.interface import TEST_SIGNATURE_SCHEME, GeneralizedXmssScheme
from .attestation import Attestation, AttestationData
from .checkpoint import Checkpoint

if TYPE_CHECKING:
    from ..forkchoice.store import Store
    from .attestation import Attestation
    from .slot import Slot


class Validator(Container):
    """Represents a validator's static metadata and operational interface."""

    pubkey: Bytes52
    """XMSS one-time signature public key."""

    index: ValidatorIndex = ValidatorIndex(0)
    """Validator index in the registry."""

    def get_pubkey(self, scheme: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME) -> PublicKey:
        """Get the XMSS public key from this validator."""
        return PublicKey.from_bytes(bytes(self.pubkey), scheme.config)

    def produce_attestation(
        self,
        store: Store,
        slot: Slot,
    ) -> Attestation:
        """
        Produce an attestation for the given slot.

        This method constructs an Attestation object according to the lean protocol
        specification. The attestation represents the validator's view of the chain
        state and their choice for the next justified checkpoint.

        The algorithm:
        1. Get the current head from the store
        2. Calculate the appropriate attestation target using current forkchoice state
        3. Use the store's latest justified checkpoint as the attestation source
        4. Construct and return the complete Attestation object

        Args:
            store: The forkchoice store providing the current chain view.
            slot: The slot for which to produce the attestation.

        Returns:
            A fully constructed Attestation object ready for signing and broadcast.
        """
        # Get the head block the validator sees for this slot
        head_checkpoint = Checkpoint(
            root=store.head,
            slot=store.blocks[store.head].slot,
        )

        # Calculate the target checkpoint for this attestation
        target_checkpoint = store.get_attestation_target()

        # Create the attestation using current forkchoice state
        return Attestation(
            validator_id=self.index,
            data=AttestationData(
                slot=slot,
                head=head_checkpoint,
                target=target_checkpoint,
                source=store.latest_justified,
            ),
        )
