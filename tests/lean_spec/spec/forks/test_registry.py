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
        with pytest.raises(ValueError) as exception_info:
            ForkRegistry([])
        assert str(exception_info.value) == "ForkRegistry requires at least one fork"

    def test_non_monotonic_version_rejected(self) -> None:
        """ForkRegistry rejects forks whose versions do not strictly increase."""
        with pytest.raises(ValueError) as exception_info:
            ForkRegistry([_NextSpec(), LstarSpec()])
        assert str(exception_info.value) == (
            "Forks must be ordered by strictly increasing VERSION: "
            f"[{_NextSpec.VERSION}, {LstarSpec.VERSION}]"
        )

    def test_duplicate_version_rejected(self) -> None:
        """ForkRegistry rejects two forks sharing a VERSION."""

        class ShadowSpec(LstarSpec):
            NAME = "shadow"
            VERSION = LstarSpec.VERSION

        with pytest.raises(ValueError) as exception_info:
            ForkRegistry([LstarSpec(), ShadowSpec()])
        assert str(exception_info.value) == (
            "Forks must be ordered by strictly increasing VERSION: "
            f"[{LstarSpec.VERSION}, {ShadowSpec.VERSION}]"
        )

    def test_duplicate_name_rejected(self) -> None:
        """ForkRegistry rejects two forks sharing a NAME."""

        class TwinSpec(LstarSpec):
            NAME = LstarSpec.NAME
            VERSION = LstarSpec.VERSION + 10

        with pytest.raises(ValueError) as exception_info:
            ForkRegistry([LstarSpec(), TwinSpec()])
        assert str(exception_info.value) == (
            f"Fork names must be unique: [{LstarSpec.NAME!r}, {TwinSpec.NAME!r}]"
        )
