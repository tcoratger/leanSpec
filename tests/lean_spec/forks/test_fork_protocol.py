"""Tests for the multi-fork architecture."""

import ast

import pytest

from lean_spec.forks import (
    DEFAULT_REGISTRY,
    FORK_SEQUENCE,
    Devnet4Spec,
    Devnet5Spec,
    ForkProtocol,
    ForkRegistry,
    protocol,
)
from lean_spec.forks.devnet4.containers.block import Block
from lean_spec.forks.devnet4.containers.slot import Slot
from lean_spec.forks.devnet4.containers.state import State
from lean_spec.types import Uint64
from tests.lean_spec.helpers.builders import make_validators


class TestForkProtocolGeneric:
    """ForkProtocol must not hard-reference any devnet."""

    def test_cannot_instantiate_directly(self) -> None:
        """ForkProtocol is abstract; concrete forks must implement upgrade_state."""
        with pytest.raises(TypeError, match="abstract"):
            ForkProtocol()  # type: ignore[abstract]

    def test_protocol_module_imports_no_devnet_package(self) -> None:
        """The protocol module must not import any devnet package."""
        source = protocol.__file__
        assert source is not None
        tree = ast.parse(open(source).read())

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert "devnet" not in mod, f"Forbidden import from {mod}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert "devnet" not in alias.name, f"Forbidden import of {alias.name}"


class TestDevnet4Spec:
    """Tests for the Devnet4Spec fork implementation."""

    def test_identity(self) -> None:
        """Devnet4Spec reports stable name and version."""
        assert Devnet4Spec.NAME == "devnet4"
        assert Devnet4Spec.VERSION == 4

    def test_gossip_digest(self) -> None:
        """Devnet4Spec carries the gossipsub fork digest as fork metadata."""
        assert Devnet4Spec.GOSSIP_DIGEST == "devnet0"

    def test_previous_is_none(self) -> None:
        """Devnet4Spec is the root of the upgrade chain."""
        assert Devnet4Spec.previous is None

    def test_is_fork_protocol(self) -> None:
        """Devnet4Spec is a ForkProtocol instance."""
        assert isinstance(Devnet4Spec(), ForkProtocol)

    def test_binds_container_types(self) -> None:
        """Devnet4Spec exposes State, Block, and Store as ClassVars."""
        assert Devnet4Spec.state_class is State
        assert Devnet4Spec.block_class is Block

    def test_generate_genesis(self) -> None:
        """Devnet4Spec generates a valid genesis state via its State class."""
        fork = Devnet4Spec()
        validators = make_validators(4)
        state = fork.generate_genesis(Uint64(0), validators)
        assert state.slot == Slot(0)
        assert len(state.validators) == 4

    def test_upgrade_state_is_identity(self) -> None:
        """Devnet4 is the root fork: upgrade_state returns the input unchanged."""
        fork = Devnet4Spec()
        validators = make_validators(4)
        state = fork.generate_genesis(Uint64(0), validators)
        assert fork.upgrade_state(state) is state


class TestDevnet5Spec:
    """Devnet5 is registered and ready to diverge."""

    def test_identity(self) -> None:
        """Devnet5Spec has its own name and strictly greater version."""
        assert Devnet5Spec.NAME == "devnet5"
        assert Devnet5Spec.VERSION == 5
        assert Devnet5Spec.VERSION > Devnet4Spec.VERSION

    def test_inherits_devnet4_behavior(self) -> None:
        """Devnet5Spec reuses devnet4 method logic until divergence lands."""
        assert issubclass(Devnet5Spec, Devnet4Spec)

    def test_previous_links_to_devnet4(self) -> None:
        """Devnet5Spec.previous points back to its predecessor."""
        assert Devnet5Spec.previous is Devnet4Spec

    def test_gossip_digest_inherited(self) -> None:
        """Devnet5Spec inherits the network's gossipsub digest until it diverges."""
        assert Devnet5Spec.GOSSIP_DIGEST == "devnet0"

    def test_binds_its_own_container_classes(self) -> None:
        """Devnet5Spec routes state/store construction through its own bindings."""
        assert Devnet5Spec.state_class is not None
        assert Devnet5Spec.store_class is not None

    def test_generate_genesis(self) -> None:
        """Devnet5Spec produces a genesis state via its bound State class."""
        fork = Devnet5Spec()
        validators = make_validators(4)
        state = fork.generate_genesis(Uint64(0), validators)
        assert state.slot == Slot(0)


class TestForkRegistry:
    """Tests for the ForkRegistry."""

    def test_default_registry_holds_registered_forks(self) -> None:
        """DEFAULT_REGISTRY reflects FORK_SEQUENCE."""
        assert DEFAULT_REGISTRY.current.NAME == FORK_SEQUENCE[-1].NAME

    def test_current_returns_latest(self) -> None:
        """ForkRegistry.current returns the highest-VERSION fork."""
        registry = ForkRegistry([Devnet4Spec(), Devnet5Spec()])
        assert registry.current.NAME == "devnet5"

    def test_get_fork_by_name(self) -> None:
        """ForkRegistry.get_fork looks up by fork NAME."""
        registry = ForkRegistry([Devnet4Spec(), Devnet5Spec()])
        assert registry.get_fork("devnet4").NAME == "devnet4"
        assert registry.get_fork("devnet5").NAME == "devnet5"

    def test_get_fork_unknown_raises(self) -> None:
        """ForkRegistry.get_fork raises KeyError for unknown forks."""
        registry = ForkRegistry([Devnet4Spec()])
        with pytest.raises(KeyError, match="Unknown fork: 'devnet99'"):
            registry.get_fork("devnet99")

    def test_empty_forks_raises(self) -> None:
        """ForkRegistry requires at least one fork."""
        with pytest.raises(ValueError, match="at least one fork"):
            ForkRegistry([])

    def test_non_monotonic_version_rejected(self) -> None:
        """ForkRegistry rejects forks whose versions do not strictly increase."""
        with pytest.raises(ValueError, match="strictly increasing VERSION"):
            ForkRegistry([Devnet5Spec(), Devnet4Spec()])

    def test_duplicate_version_rejected(self) -> None:
        """ForkRegistry rejects two forks sharing a VERSION."""

        class ShadowSpec(Devnet4Spec):
            NAME = "shadow"
            VERSION = 4

        with pytest.raises(ValueError, match="strictly increasing VERSION"):
            ForkRegistry([Devnet4Spec(), ShadowSpec()])

    def test_duplicate_name_rejected(self) -> None:
        """ForkRegistry rejects two forks sharing a NAME."""

        class TwinSpec(Devnet4Spec):
            NAME = "devnet4"
            VERSION = 6

        with pytest.raises(ValueError, match="names must be unique"):
            ForkRegistry([Devnet4Spec(), TwinSpec()])
