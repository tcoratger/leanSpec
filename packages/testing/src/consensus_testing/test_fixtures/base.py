"""Base fixture definitions for consensus test formats."""

from typing import Any, ClassVar

from framework.test_fixtures import BaseFixture
from pydantic import field_serializer


class BaseConsensusFixture(BaseFixture):
    """
    Base class for all consensus test fixtures.

    Inherits shared functionality from framework.fixtures.BaseFixture
    and adds consensus-specific behavior if needed.
    """

    # Class-level registry of all consensus fixture formats
    # Override parent's formats to maintain a separate registry
    formats: ClassVar[dict[str, type["BaseConsensusFixture"]]] = {}  # type: ignore[assignment]

    expect_exception: type[Exception] | None = None
    """
    Expected exception type for invalid tests.

    If set, the fixture expects this exception during processing.
    The test passes only if the exception is raised.
    """

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        """
        Auto-register consensus fixture formats when subclasses are defined.

        Overrides parent to register in BaseConsensusFixture.formats instead
        of BaseFixture.formats.
        """
        super().__pydantic_init_subclass__(**kwargs)
        if cls.format_name:
            BaseConsensusFixture.formats[cls.format_name] = cls

    @field_serializer("expect_exception", when_used="json")
    def serialize_exception(self, value: type[Exception] | None) -> str | None:
        """Serialize exception type to its class name for JSON output."""
        if value is None:
            return None
        return value.__name__
