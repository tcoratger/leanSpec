"""Consensus layer pre-state generation."""

from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator, ValidatorIndex
from lean_spec.types import Bytes52, Uint64

from ..keys import XmssKeyManager

_DEFAULT_GENESIS_TIME = Uint64(0)


def generate_pre_state(
    genesis_time: Uint64 = _DEFAULT_GENESIS_TIME,
    num_validators: int = 4,
) -> State:
    """
    Generate a default pre-state for consensus tests.

    Args:
        genesis_time: The genesis timestamp (defaults to Uint64(0)).
        num_validators: Number of validators (defaults to 4).

    Returns:
        A properly initialized consensus state.
    """
    key_manager = XmssKeyManager.shared()
    available_keys = len(key_manager)

    assert num_validators <= available_keys, (
        f"Not enough keys to generate state. "
        f"Expecting a minimum of {num_validators} validators "
        f"but the key manager has only {available_keys} keys"
    )

    validator_list = []
    for i in range(num_validators):
        idx = ValidatorIndex(i)
        attestation_pubkey, proposal_pubkey = key_manager.get_public_keys(idx)
        validator_list.append(
            Validator(
                attestation_pubkey=Bytes52(attestation_pubkey.encode_bytes()),
                proposal_pubkey=Bytes52(proposal_pubkey.encode_bytes()),
                index=idx,
            )
        )

    return State.generate_genesis(
        genesis_time=genesis_time, validators=Validators(data=validator_list)
    )
