"""
Validator registry for managing validator keys.

Loads validator keys from JSON configuration files.

The registry supports two configuration files:

1. **validators.json** - Maps node IDs to validator indices:
   ```json
   {
     "node_0": [0, 1],
     "node_1": [2]
   }
   ```

2. **validator-keys-manifest.json** - Contains key metadata and paths:
   ```json
   {
     "num_validators": 3,
     "validators": [
       {"index": 0, "pubkey_hex": "0xe2a03c...", "privkey_file": "validator_0_sk.ssz"}
     ]
   }
   ```
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from lean_spec.subspecs.xmss import SecretKey
from lean_spec.types import Uint64


@dataclass(frozen=True, slots=True)
class ValidatorEntry:
    """
    A single validator's key material.

    Holds both the index and the secret key needed for signing.
    """

    index: Uint64
    """Validator index in the registry."""

    secret_key: SecretKey
    """XMSS secret key for signing."""


@dataclass(slots=True)
class ValidatorRegistry:
    """
    Registry of validator keys controlled by this node.

    The registry holds secret keys for validators assigned to this node.
    It provides lookup by validator index for signing operations.
    """

    _validators: dict[Uint64, ValidatorEntry] = field(default_factory=dict)
    """Map from validator index to entry."""

    def add(self, entry: ValidatorEntry) -> None:
        """
        Add a validator entry to the registry.

        Args:
            entry: Validator entry to add.
        """
        self._validators[entry.index] = entry

    def get(self, index: Uint64) -> ValidatorEntry | None:
        """
        Get validator entry by index.

        Args:
            index: Validator index to look up.

        Returns:
            Validator entry if found, None otherwise.
        """
        return self._validators.get(index)

    def has(self, index: Uint64) -> bool:
        """
        Check if we control this validator.

        Args:
            index: Validator index to check.

        Returns:
            True if we have keys for this validator.
        """
        return index in self._validators

    def indices(self) -> list[Uint64]:
        """
        Get all validator indices we control.

        Returns:
            List of validator indices.
        """
        return list(self._validators.keys())

    def __len__(self) -> int:
        """Number of validators in the registry."""
        return len(self._validators)

    @classmethod
    def from_json(
        cls,
        node_id: str,
        validators_path: Path | str,
        manifest_path: Path | str,
    ) -> ValidatorRegistry:
        """
        Load validator registry from JSON configuration files.

        The loading process:
        1. Read validators.json to find indices assigned to this node
        2. Read manifest to get key file paths
        3. Load secret keys from SSZ files

        Args:
            node_id: Identifier for this node in validators.json.
            validators_path: Path to validators.json.
            manifest_path: Path to validator-keys-manifest.json.

        Returns:
            Registry populated with validator keys for this node.
        """
        validators_path = Path(validators_path)
        manifest_path = Path(manifest_path)

        # Load node-to-validator mapping.
        with validators_path.open() as f:
            validators_config = json.load(f)

        # Get indices assigned to this node.
        #
        # If node not in config, return empty registry.
        assigned_indices = validators_config.get(node_id, [])
        if not assigned_indices:
            return cls()

        # Load manifest with key metadata.
        with manifest_path.open() as f:
            manifest = json.load(f)

        # Build index-to-entry lookup from manifest.
        manifest_entries = {v["index"]: v for v in manifest.get("validators", [])}

        # Load keys for assigned validators.
        registry = cls()
        manifest_dir = manifest_path.parent

        for index in assigned_indices:
            entry = manifest_entries.get(index)
            if entry is None:
                continue

            # Load secret key from SSZ file.
            privkey_file = manifest_dir / entry["privkey_file"]
            secret_key = SecretKey.decode_bytes(privkey_file.read_bytes())

            registry.add(
                ValidatorEntry(
                    index=Uint64(index),
                    secret_key=secret_key,
                )
            )

        return registry

    @classmethod
    def from_secret_keys(cls, keys: dict[int, SecretKey]) -> ValidatorRegistry:
        """
        Create registry from a dictionary of secret keys.

        Convenience method for testing or programmatic key loading.

        Args:
            keys: Mapping from validator index to secret key.

        Returns:
            Registry populated with provided keys.
        """
        registry = cls()
        for index, secret_key in keys.items():
            registry.add(
                ValidatorEntry(
                    index=Uint64(index),
                    secret_key=secret_key,
                )
            )
        return registry

    @classmethod
    def from_key_dir(
        cls,
        node_id: str,
        validators_path: Path | str,
        keys_dir: Path | str,
    ) -> ValidatorRegistry:
        """
        Load registry from leansig-test-keys format.

        This format uses individual JSON files per validator:
        - validators.json: maps node IDs to validator indices
        - keys_dir/{index}.json: contains public/secret hex strings

        Compatible with https://github.com/leanEthereum/leansig-test-keys

        Args:
            node_id: Identifier for this node in validators.json.
            validators_path: Path to validators.json.
            keys_dir: Directory containing {index}.json key files.

        Returns:
            Registry populated with validator keys for this node.
        """
        validators_path = Path(validators_path)
        keys_dir = Path(keys_dir)

        # Load node-to-validator mapping.
        with validators_path.open() as f:
            validators_config = json.load(f)

        # Get indices assigned to this node.
        assigned_indices = validators_config.get(node_id, [])
        if not assigned_indices:
            return cls()

        # Load keys for assigned validators.
        registry = cls()

        for index in assigned_indices:
            key_file = keys_dir / f"{index}.json"
            if not key_file.exists():
                continue

            with key_file.open() as f:
                key_data = json.load(f)

            # Keys are hex-encoded without 0x prefix.
            secret_key = SecretKey.decode_bytes(bytes.fromhex(key_data["secret"]))

            registry.add(
                ValidatorEntry(
                    index=Uint64(index),
                    secret_key=secret_key,
                )
            )

        return registry
