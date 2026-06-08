"""Tests for the fork protocol abstraction."""

import ast
from pathlib import Path

import pytest

import lean_spec
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import (
    ForkProtocol,
    LstarSpec,
    Slot,
    ValidatorIndex,
    protocol,
)
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestations,
    Block,
    BlockBody,
    State,
    Validator,
    Validators,
)
from lean_spec.spec.ssz import Bytes32, Bytes52, Uint64
from tests.lean_spec.helpers.builders import make_validators

_LEAN_SPEC_FILE = lean_spec.__file__
assert _LEAN_SPEC_FILE is not None  # noqa: S101
_SUBSPECS_ROOT: Path = Path(_LEAN_SPEC_FILE).parent / "subspecs"
"""Filesystem root for subspec source files. Used by import-guard tests."""

_FORBIDDEN_FORK_PREFIXES: tuple[str, ...] = ("lean_spec.spec.forks.lstar",)
"""
Module prefixes that subspec code must never import directly.

Subspecs are meant to be fork-agnostic shared libraries.
"""


class TestForkProtocolGeneric:
    """ForkProtocol must not hard-reference any devnet."""

    def test_cannot_instantiate_directly(self) -> None:
        """ForkProtocol is abstract; concrete forks must implement upgrade_state."""
        with pytest.raises(TypeError) as exception_info:
            ForkProtocol()
        assert str(exception_info.value) == (
            "Can't instantiate abstract class ForkProtocol without an implementation "
            "for abstract methods 'create_store', 'generate_genesis', 'upgrade_state'"
        )

    def test_protocol_module_imports_no_devnet_package(self) -> None:
        """The protocol module must not import any devnet package."""
        source = protocol.__file__
        assert source is not None
        tree = ast.parse(Path(source).read_text())

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module_name = node.module or ""
                assert "devnet" not in module_name, f"Forbidden import from {module_name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert "devnet" not in alias.name, f"Forbidden import of {alias.name}"

    def test_subspecs_do_not_import_concrete_fork(self) -> None:
        """Subspecs must remain fork-agnostic."""
        offenders: list[str] = []
        for source_file in _SUBSPECS_ROOT.rglob("*.py"):
            tree = ast.parse(source_file.read_text(), filename=str(source_file))
            location = source_file.relative_to(_SUBSPECS_ROOT.parent)
            for node in ast.walk(tree):
                # `from X import Y` — `X` is the module being imported from.
                if isinstance(node, ast.ImportFrom):
                    module_name = node.module or ""
                    if any(
                        module_name.startswith(forbidden_prefix)
                        for forbidden_prefix in _FORBIDDEN_FORK_PREFIXES
                    ):
                        offenders.append(f"{location}:{node.lineno}: from {module_name} import ...")
                # `import X` — each `alias.name` is a fully-qualified module path.
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if any(
                            alias.name.startswith(forbidden_prefix)
                            for forbidden_prefix in _FORBIDDEN_FORK_PREFIXES
                        ):
                            offenders.append(f"{location}:{node.lineno}: import {alias.name}")

        assert not offenders, "Subspecs must not import concrete forks:\n" + "\n".join(offenders)


class TestLstarSpec:
    """Tests for the LstarSpec fork implementation."""

    def test_identity(self) -> None:
        """LstarSpec reports stable name and version."""
        assert LstarSpec.NAME == "lstar"
        assert LstarSpec.VERSION == 4

    def test_gossip_digest(self) -> None:
        """LstarSpec carries the gossipsub fork digest as fork metadata."""
        assert LstarSpec.GOSSIP_DIGEST == "12345678"

    def test_previous_is_none(self) -> None:
        """LstarSpec is the root of the upgrade chain."""
        assert LstarSpec.previous is None

    def test_is_fork_protocol(self) -> None:
        """LstarSpec is a ForkProtocol instance."""
        assert isinstance(LstarSpec(), ForkProtocol)

    def test_binds_container_types(self) -> None:
        """LstarSpec exposes State, Block, and Store as ClassVars."""
        assert LstarSpec.state_class is State
        assert LstarSpec.block_class is Block

    def test_generate_genesis(self) -> None:
        """LstarSpec generates a valid genesis state via its State class."""
        fork = LstarSpec()
        validators = make_validators(4)
        state = fork.generate_genesis(Uint64(0), validators)
        assert isinstance(state, State)
        assert state.slot == Slot(0)
        assert len(state.validators) == 4

    def test_upgrade_state_is_identity(self) -> None:
        """Lstar is the root fork: upgrade_state returns the input unchanged."""
        fork = LstarSpec()
        validators = make_validators(4)
        state = fork.generate_genesis(Uint64(0), validators)
        assert fork.upgrade_state(state) is state


def test_genesis_block_hash_comparison(spec: LstarSpec) -> None:
    """Test that genesis block hashes are deterministic and differ with different inputs."""
    # Create first genesis state with 3 validators
    # Fill public_keys with different values (1, 2, 3)
    pubkeys1 = [Bytes52(bytes([i + 1] * 52)) for i in range(3)]
    validators1 = Validators(
        data=[
            Validator(
                attestation_public_key=public_key,
                proposal_public_key=public_key,
                index=ValidatorIndex(i),
            )
            for i, public_key in enumerate(pubkeys1)
        ]
    )

    genesis_state1 = spec.generate_genesis(
        genesis_time=Uint64(1000),
        validators=validators1,
    )

    # Generate genesis block from first state
    genesis_block1 = Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state1),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    # Compute hash of first genesis block
    genesis_block_hash1 = hash_tree_root(genesis_block1)

    # Create a second genesis state with same config but regenerated (should produce same hash)
    genesis_state1_copy = spec.generate_genesis(
        genesis_time=Uint64(1000),
        validators=validators1,
    )

    genesis_block1_copy = Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state1_copy),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    genesis_block_hash1_copy = hash_tree_root(genesis_block1_copy)

    # Same genesis spec should produce same hash
    assert genesis_block_hash1 == genesis_block_hash1_copy

    # Create second genesis state with different validators
    # Fill public_keys with different values (10, 11, 12)
    pubkeys2 = [Bytes52(bytes([i + 10] * 52)) for i in range(3)]
    validators2 = Validators(
        data=[
            Validator(
                attestation_public_key=public_key,
                proposal_public_key=public_key,
                index=ValidatorIndex(i),
            )
            for i, public_key in enumerate(pubkeys2)
        ]
    )

    genesis_state2 = spec.generate_genesis(
        genesis_time=Uint64(1000),  # Same genesis_time but different validators
        validators=validators2,
    )

    genesis_block2 = Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state2),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    genesis_block_hash2 = hash_tree_root(genesis_block2)

    # Different validators should produce different genesis block hash
    assert genesis_block_hash1 != genesis_block_hash2

    # Create third genesis state with same validators but different genesis_time
    # Same as pubkeys1
    pubkeys3 = [Bytes52(bytes([i + 1] * 52)) for i in range(3)]
    validators3 = Validators(
        data=[
            Validator(
                attestation_public_key=public_key,
                proposal_public_key=public_key,
                index=ValidatorIndex(i),
            )
            for i, public_key in enumerate(pubkeys3)
        ]
    )

    genesis_state3 = spec.generate_genesis(
        genesis_time=Uint64(2000),  # Different genesis_time but same validators
        validators=validators3,
    )

    genesis_block3 = Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state3),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    genesis_block_hash3 = hash_tree_root(genesis_block3)

    # Different genesis_time should produce different genesis block hash
    assert genesis_block_hash1 != genesis_block_hash3

    # Compare genesis block hashes with expected hex values
    hash1_hex = f"0x{genesis_block_hash1.hex()}"
    assert hash1_hex == "0xf84d547a47ca863fac7cda4619d3a93a2d3e7f2afdeeb5e4571b393554e19c0d"

    hash2_hex = f"0x{genesis_block_hash2.hex()}"
    assert hash2_hex == "0x7b90004279c32942009320f284a92c8ec5914e9c4deb7a9c50e17dc22a7c6ce9"

    hash3_hex = f"0x{genesis_block_hash3.hex()}"
    assert hash3_hex == "0xb66cb6371bde0209ffd63063f89d216feeb1f03328400cb083429d8aead481ff"
