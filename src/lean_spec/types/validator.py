"""Validator-related type definitions and utilities for the specification."""

from .uint import Uint64


class ValidatorIndex(Uint64):
    """
    A validator's index in the registry.

    Extends Uint64 with proposer selection logic for determining
    if this validator is the proposer for a given slot.
    """

    def is_proposer(self, slot: Uint64, num_validators: Uint64) -> bool:
        """
        Determine if this validator is the proposer for a given slot.

        Uses round-robin proposer selection based on slot number and total
        validator count, following the lean protocol specification.

        Parameters:
        ----------
        slot : Uint64
            The slot number to check proposer assignment for.
        num_validators : Uint64
            Total number of validators in the registry.

        Returns:
        -------
        bool
            True if this validator is the proposer for the slot, False otherwise.
        """
        return slot % num_validators == self
