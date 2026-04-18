"""Consensus layer pre-state generation."""

from lean_spec.forks.devnet4.state import State
from lean_spec.forks.protocol import ForkProtocol
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.validator import Validator, ValidatorIndex
from lean_spec.types import Bytes52, Uint64

from .keys import XmssKeyManager

_DEFAULT_GENESIS_TIME = Uint64(0)


def _build_validators(num_validators: int) -> Validators:
    """Build a validator registry with real XMSS keys from the shared key manager."""
    key_manager = XmssKeyManager.shared()

    if num_validators > len(key_manager):
        raise ValueError(
            f"Not enough keys: need {num_validators} validators "
            f"but the key manager has only {len(key_manager)} keys"
        )

    validators = []
    for i in range(num_validators):
        idx = ValidatorIndex(i)
        attestation_pubkey, proposal_pubkey = key_manager.get_public_keys(idx)
        validators.append(
            Validator(
                attestation_pubkey=Bytes52(attestation_pubkey.encode_bytes()),
                proposal_pubkey=Bytes52(proposal_pubkey.encode_bytes()),
                index=idx,
            )
        )

    return Validators(data=validators)


def generate_pre_state(
    genesis_time: Uint64 = _DEFAULT_GENESIS_TIME,
    num_validators: int = 4,
    fork: ForkProtocol | None = None,
) -> State:
    """Generate a default pre-state for consensus tests.

    When a fork is provided, genesis is generated through the fork's
    protocol implementation. This ensures each fork produces its own
    correct genesis state (e.g. Devnet5 may add new State fields).

    Args:
        genesis_time: The genesis timestamp.
        num_validators: Number of validators to include.
        fork: ForkProtocol instance to use for genesis generation.
            Defaults to State.generate_genesis for backward compatibility.

    Returns:
        A properly initialized consensus state.
    """
    validators = _build_validators(num_validators)

    if fork is not None:
        return fork.generate_genesis(genesis_time=genesis_time, validators=validators)

    return State.generate_genesis(genesis_time=genesis_time, validators=validators)
