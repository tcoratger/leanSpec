"""Tests for ValidatorRegistry."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lean_spec.subspecs.validator import ValidatorRegistry
from lean_spec.subspecs.validator.registry import ValidatorEntry
from lean_spec.types import Uint64


class TestValidatorEntry:
    """Tests for ValidatorEntry."""

    def test_entry_is_frozen(self) -> None:
        """ValidatorEntry is immutable."""
        mock_key = MagicMock()
        entry = ValidatorEntry(index=Uint64(0), secret_key=mock_key)

        with pytest.raises(AttributeError):
            entry.index = Uint64(1)  # type: ignore[misc]


class TestValidatorRegistry:
    """Tests for ValidatorRegistry."""

    def test_empty_registry(self) -> None:
        """New registry is empty."""
        registry = ValidatorRegistry()
        assert len(registry) == 0
        assert registry.indices() == []

    def test_add_and_get(self) -> None:
        """Entry can be added and retrieved."""
        registry = ValidatorRegistry()
        mock_key = MagicMock()
        entry = ValidatorEntry(index=Uint64(42), secret_key=mock_key)

        registry.add(entry)

        assert len(registry) == 1
        assert registry.get(Uint64(42)) is entry
        assert registry.has(Uint64(42))

    def test_get_nonexistent(self) -> None:
        """Getting nonexistent entry returns None."""
        registry = ValidatorRegistry()
        assert registry.get(Uint64(99)) is None

    def test_has_nonexistent(self) -> None:
        """has() returns False for nonexistent entry."""
        registry = ValidatorRegistry()
        assert not registry.has(Uint64(99))

    def test_indices(self) -> None:
        """indices() returns all validator indices."""
        registry = ValidatorRegistry()
        for i in [3, 1, 4]:
            mock_key = MagicMock()
            registry.add(ValidatorEntry(index=Uint64(i), secret_key=mock_key))

        indices = registry.indices()
        assert set(indices) == {Uint64(1), Uint64(3), Uint64(4)}

    def test_from_secret_keys(self) -> None:
        """Registry can be created from dict of secret keys."""
        mock_keys = {0: MagicMock(), 2: MagicMock()}

        registry = ValidatorRegistry.from_secret_keys(mock_keys)

        assert len(registry) == 2
        assert registry.has(Uint64(0))
        assert registry.has(Uint64(2))
        assert not registry.has(Uint64(1))


class TestValidatorRegistryFromJson:
    """Tests for JSON loading."""

    def test_from_json_basic(self, tmp_path: Path) -> None:
        """Registry loads from JSON files."""
        # Create validators.json
        validators_file = tmp_path / "validators.json"
        validators_file.write_text(
            json.dumps(
                {
                    "node_0": [0, 1],
                    "node_1": [2],
                }
            )
        )

        # Create manifest.json
        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text(
            json.dumps(
                {
                    "validators": [
                        {"index": 0, "privkey_file": "key_0.ssz"},
                        {"index": 1, "privkey_file": "key_1.ssz"},
                        {"index": 2, "privkey_file": "key_2.ssz"},
                    ],
                }
            )
        )

        # Create dummy key files
        (tmp_path / "key_0.ssz").write_bytes(b"key0")
        (tmp_path / "key_1.ssz").write_bytes(b"key1")

        # Mock SecretKey.decode_bytes
        mock_key = MagicMock()
        with patch(
            "lean_spec.subspecs.xmss.SecretKey.decode_bytes",
            return_value=mock_key,
        ):
            registry = ValidatorRegistry.from_json(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

        assert len(registry) == 2
        assert registry.has(Uint64(0))
        assert registry.has(Uint64(1))
        assert not registry.has(Uint64(2))

    def test_from_json_unknown_node(self, tmp_path: Path) -> None:
        """Unknown node returns empty registry."""
        validators_file = tmp_path / "validators.json"
        validators_file.write_text(json.dumps({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text(json.dumps({"validators": []}))

        registry = ValidatorRegistry.from_json(
            node_id="unknown_node",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert len(registry) == 0

    def test_from_json_missing_validator_in_manifest(self, tmp_path: Path) -> None:
        """Missing validator in manifest is skipped."""
        validators_file = tmp_path / "validators.json"
        validators_file.write_text(json.dumps({"node_0": [0, 99]}))

        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text(
            json.dumps(
                {
                    "validators": [
                        {"index": 0, "privkey_file": "key_0.ssz"},
                    ],
                }
            )
        )

        (tmp_path / "key_0.ssz").write_bytes(b"key0")

        mock_key = MagicMock()
        with patch(
            "lean_spec.subspecs.xmss.SecretKey.decode_bytes",
            return_value=mock_key,
        ):
            registry = ValidatorRegistry.from_json(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

        # Only index 0 should be loaded (99 is not in manifest)
        assert len(registry) == 1
        assert registry.has(Uint64(0))
