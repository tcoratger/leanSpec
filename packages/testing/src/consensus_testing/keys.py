"""
XMSS Key Management for Consensus Testing
==========================================

This module provides XMSS key pairs for test validators.

To avoid expensive key generation during test runs, keys are
pre-generated once and stored in a JSON file.

File Format
-----------
The JSON file contains an array of key pairs:

    [
        {"public": "<hex-encoded SSZ>", "secret": "<hex-encoded SSZ>"},
        {"public": "<hex-encoded SSZ>", "secret": "<hex-encoded SSZ>"},
        ...,
    ]

Regenerating Keys
-----------------
If you need more validators or epochs, update the constants and run:

    python -m consensus_testing.keys

This regenerates `test_keys.json` with the new parameters.
"""

import json
from pathlib import Path
from typing import NamedTuple

from lean_spec.subspecs.containers import Attestation
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey, Signature
from lean_spec.subspecs.xmss.interface import TEST_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.types import Uint64, ValidatorIndex

KEYS_FILE = Path(__file__).parent / "test_keys.json"
"""Path to the pre-generated keys file."""

NUM_VALIDATORS = 12
"""Number of validator key pairs to generate."""

DEFAULT_MAX_SLOT = Slot(100)
"""Maximum slot for test signatures (inclusive)."""

NUM_ACTIVE_EPOCHS = int(DEFAULT_MAX_SLOT) + 1
"""Number of epochs each key is valid for (DEFAULT_MAX_SLOT + 1 to include genesis)."""


class KeyPair(NamedTuple):
    """
    A validator's XMSS key pair.

    Attributes:
    ----------
    public : PublicKey
        The public key used for signature verification.
    secret : SecretKey
        The secret key used for signing. Contains Merkle tree structures.
    """

    public: PublicKey
    secret: SecretKey


def _load_keys_from_file() -> dict[ValidatorIndex, KeyPair]:
    """
    Load pre-generated keys from the JSON file.

    Returns:
    -------
    dict[ValidatorIndex, KeyPair]
        Mapping from validator index to key pair.

    Raises:
    ------
    FileNotFoundError
        If the keys file doesn't exist. Run `python -m consensus_testing.keys`.
    """
    if not KEYS_FILE.exists():
        raise FileNotFoundError(
            f"Pre-generated keys not found: {KEYS_FILE}\nRun: python -m consensus_testing.keys"
        )

    data = json.loads(KEYS_FILE.read_text())
    return {
        ValidatorIndex(i): KeyPair(
            public=PublicKey.decode_bytes(bytes.fromhex(kp["public"])),
            secret=SecretKey.decode_bytes(bytes.fromhex(kp["secret"])),
        )
        for i, kp in enumerate(data)
    }


_CACHED_KEYS: dict[ValidatorIndex, KeyPair] | None = None
"""Module-level cache (loaded once on first access)"""


def _get_keys() -> dict[ValidatorIndex, KeyPair]:
    """Get pre-generated keys, loading from file on first call."""
    global _CACHED_KEYS
    if _CACHED_KEYS is None:
        _CACHED_KEYS = _load_keys_from_file()
    return _CACHED_KEYS


class XmssKeyManager:
    """
    Key manager for test validators using pre-generated XMSS keys.

    This class provides access to validator key pairs and signing operations.
    Keys are loaded from `test_keys.json` on first access.

    Parameters
    ----------
    max_slot : Slot, optional
        Maximum slot for signatures. Defaults to Slot(100).
        Must not exceed the pre-generated key lifetime.
    scheme : GeneralizedXmssScheme, optional
        XMSS scheme for signing operations. Defaults to TEST_SIGNATURE_SCHEME.

    Examples:
    --------
    >>> manager = XmssKeyManager()
    >>> key_pair = manager[ValidatorIndex(0)]
    >>> pubkey = manager.get_public_key(ValidatorIndex(1))
    >>> signature = manager.sign_attestation(attestation)
    """

    def __init__(
        self,
        max_slot: Slot | None = None,
        scheme: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME,
    ) -> None:
        """Initialize the key manager with pre-generated XMSS keys."""
        self.max_slot = max_slot if max_slot is not None else DEFAULT_MAX_SLOT
        self.scheme = scheme
        self._keys = _get_keys()
        self._state: dict[ValidatorIndex, KeyPair] = {}  # Tracks advanced key states

    def __getitem__(self, validator_index: ValidatorIndex) -> KeyPair:
        """
        Get a validator's key pair.

        Parameters
        ----------
        validator_index : ValidatorIndex
            The validator index (0 to NUM_VALIDATORS-1).

        Returns:
        -------
        KeyPair
            The validator's public and secret keys.

        Raises:
        ------
        KeyError
            If the validator index is not in the pre-generated set.
        """
        if validator_index in self._state:
            return self._state[validator_index]

        if validator_index not in self._keys:
            raise KeyError(
                f"Validator {validator_index} not found. Available: {list(self._keys.keys())}"
            )

        key_pair = self._keys[validator_index]
        self._state[validator_index] = key_pair
        return key_pair

    def sign_attestation(self, attestation: Attestation) -> Signature:
        """
        Sign an attestation using the validator's XMSS key.

        This method handles key advancement automatically when signing for
        slots outside the currently prepared interval.

        Parameters
        ----------
        attestation : Attestation
            The attestation to sign. Uses `validator_id` and `data.slot`.

        Returns:
        -------
        Signature
            The XMSS signature.

        Raises:
        ------
        ValueError
            If the slot exceeds the key's maximum lifetime.
        """
        validator_id = attestation.validator_id
        key_pair = self[validator_id]
        sk = key_pair.secret
        epoch = attestation.data.slot

        # Advance key state if needed to cover the requested epoch
        prepared = self.scheme.get_prepared_interval(sk)
        while int(epoch) not in prepared:
            activation = self.scheme.get_activation_interval(sk)
            if prepared.stop >= activation.stop:
                raise ValueError(f"Epoch {epoch} exceeds key lifetime {activation.stop}")
            sk = self.scheme.advance_preparation(sk)
            prepared = self.scheme.get_prepared_interval(sk)

        # Save advanced state for future calls
        self._state[validator_id] = KeyPair(public=key_pair.public, secret=sk)

        # Sign the attestation's hash tree root
        message = bytes(hash_tree_root(attestation))
        return self.scheme.sign(sk, epoch, message)

    def get_public_key(self, validator_index: ValidatorIndex) -> PublicKey:
        """Get a validator's public key."""
        return self[validator_index].public

    def get_all_public_keys(self) -> dict[ValidatorIndex, PublicKey]:
        """Get all pre-generated public keys."""
        return {i: kp.public for i, kp in self._keys.items()}

    def __contains__(self, validator_index: ValidatorIndex) -> bool:
        """Check if a validator has pre-generated keys."""
        return validator_index in self._keys

    def __len__(self) -> int:
        """Return the number of available validators."""
        return len(self._keys)


def generate_keys() -> None:
    """
    Generate XMSS key pairs and save to JSON file.

    This function generates `NUM_VALIDATORS` key pairs with `NUM_ACTIVE_EPOCHS`
    lifetime and saves them to `KEYS_FILE`.

    Run via: `python -m consensus_testing.keys`
    """
    print(f"Generating {NUM_VALIDATORS} XMSS key pairs ({NUM_ACTIVE_EPOCHS} epochs)...")

    key_pairs = []
    for i in range(NUM_VALIDATORS):
        print(f"  Validator {i}...")
        pk, sk = TEST_SIGNATURE_SCHEME.key_gen(Uint64(0), Uint64(NUM_ACTIVE_EPOCHS))
        key_pairs.append(
            {
                "public": pk.encode_bytes().hex(),
                "secret": sk.encode_bytes().hex(),
            }
        )

    KEYS_FILE.write_text(json.dumps(key_pairs, indent=2))
    print(f"Saved to {KEYS_FILE}")


if __name__ == "__main__":
    generate_keys()
