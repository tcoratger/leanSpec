"""Tests for the fork registry."""

from typing import ClassVar

import pytest

from lean_spec.spec.forks import (
    DEFAULT_REGISTRY,
    FORK_SEQUENCE,
    ForkProtocol,
    ForkRegistry,
    LstarSpec,
)


class _NextSpec(LstarSpec):
    """Synthetic successor fork. Used only by registry tests."""

    NAME: ClassVar[str] = "next"
    VERSION: ClassVar[int] = LstarSpec.VERSION + 1
    previous: ClassVar[type[ForkProtocol] | None] = LstarSpec


class TestForkRegistry:
    """Tests for the ForkRegistry."""

    def test_default_registry_holds_registered_forks(self) -> None:
        """DEFAULT_REGISTRY reflects FORK_SEQUENCE."""
        assert DEFAULT_REGISTRY.current.NAME == FORK_SEQUENCE[-1].NAME

    def test_current_returns_latest(self) -> None:
        """ForkRegistry.current returns the highest-VERSION fork."""
        registry = ForkRegistry([LstarSpec(), _NextSpec()])
        assert registry.current.NAME == _NextSpec.NAME

    def test_empty_forks_raises(self) -> None:
        """ForkRegistry requires at least one fork."""
        with pytest.raises(ValueError, match="at least one fork"):
            ForkRegistry([])

    def test_non_monotonic_version_rejected(self) -> None:
        """ForkRegistry rejects forks whose versions do not strictly increase."""
        with pytest.raises(ValueError, match="strictly increasing VERSION"):
            ForkRegistry([_NextSpec(), LstarSpec()])

    def test_duplicate_version_rejected(self) -> None:
        """ForkRegistry rejects two forks sharing a VERSION."""

        class ShadowSpec(LstarSpec):
            NAME = "shadow"
            VERSION = LstarSpec.VERSION

        with pytest.raises(ValueError, match="strictly increasing VERSION"):
            ForkRegistry([LstarSpec(), ShadowSpec()])

    def test_duplicate_name_rejected(self) -> None:
        """ForkRegistry rejects two forks sharing a NAME."""

        class TwinSpec(LstarSpec):
            NAME = LstarSpec.NAME
            VERSION = LstarSpec.VERSION + 10

        with pytest.raises(ValueError, match="names must be unique"):
            ForkRegistry([LstarSpec(), TwinSpec()])
