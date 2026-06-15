"""Tests for the fork registry validation rules."""

from __future__ import annotations

from typing import Any

import pytest

from lean_spec.spec.forks.lstar.containers import ValidatorIndex
from lean_spec.spec.forks.protocol import ForkProtocol, SpecBlockType, SpecStateType, SpecStoreType
from lean_spec.spec.forks.registry import ForkRegistry
from lean_spec.spec.ssz import SSZList, Uint64


class StubFork(ForkProtocol):
    """Minimal fork double exposing only the NAME and VERSION the registry validates."""

    def generate_genesis(self, genesis_time: Uint64, validators: SSZList[Any]) -> SpecStateType:
        """Unused by registry validation; never invoked in these tests."""
        raise NotImplementedError

    def create_store(
        self,
        state: SpecStateType,
        anchor_block: SpecBlockType,
        validator_index: ValidatorIndex | None,
    ) -> SpecStoreType:
        """Unused by registry validation; never invoked in these tests."""
        raise NotImplementedError


def make_fork(name: str, version: int) -> StubFork:
    """Build a stub fork whose NAME and VERSION class vars carry the given identity."""
    fork_class = type(f"StubFork_{name}_{version}", (StubFork,), {"NAME": name, "VERSION": version})
    return fork_class()


class TestForkRegistryValidation:
    """Tests for the three ForkRegistry rejection branches."""

    def test_init_rejects_empty_fork_list(self) -> None:
        """An empty fork list raises with the no-fork message."""
        with pytest.raises(ValueError) as exception_info:
            ForkRegistry([])
        assert str(exception_info.value) == "ForkRegistry requires at least one fork"

    def test_init_rejects_equal_consecutive_versions(self) -> None:
        """Two forks sharing a version are not strictly increasing and are rejected."""
        with pytest.raises(ValueError) as exception_info:
            ForkRegistry([make_fork("alpha", 1), make_fork("beta", 1)])
        assert str(exception_info.value) == (
            "Forks must be ordered by strictly increasing VERSION: [1, 1]"
        )

    def test_init_rejects_descending_versions(self) -> None:
        """A later fork with a lower version is not strictly increasing and is rejected."""
        with pytest.raises(ValueError) as exception_info:
            ForkRegistry([make_fork("alpha", 2), make_fork("beta", 1)])
        assert str(exception_info.value) == (
            "Forks must be ordered by strictly increasing VERSION: [2, 1]"
        )

    def test_init_rejects_duplicate_names(self) -> None:
        """Strictly increasing versions but colliding names are rejected on the name check."""
        with pytest.raises(ValueError) as exception_info:
            ForkRegistry([make_fork("alpha", 1), make_fork("alpha", 2)])
        assert str(exception_info.value) == "Fork names must be unique: ['alpha', 'alpha']"

    def test_current_returns_highest_version_fork(self) -> None:
        """A valid registry exposes its last, highest-version fork as the current one."""
        newest_fork = make_fork("beta", 2)
        registry = ForkRegistry([make_fork("alpha", 1), newest_fork])
        assert registry.current is newest_fork
