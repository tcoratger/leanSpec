"""Tests for the SSZ exception hierarchy."""

from __future__ import annotations

from lean_spec.spec.ssz.exceptions import (
    SSZError,
    SSZSerializationError,
    SSZTypeError,
    SSZValueError,
)


class TestSSZExceptionHierarchy:
    """Tests for the inheritance structure of SSZ exceptions."""

    def test_base_error_subclasses_only_exception(self) -> None:
        """The base SSZ error derives from the builtin Exception and nothing else."""
        assert SSZError.__bases__ == (Exception,)

    def test_type_error_subclasses_base_error(self) -> None:
        """The type error derives directly from the SSZ base error."""
        assert SSZTypeError.__bases__ == (SSZError,)

    def test_value_error_subclasses_base_error(self) -> None:
        """The value error derives directly from the SSZ base error."""
        assert SSZValueError.__bases__ == (SSZError,)

    def test_serialization_error_subclasses_base_error(self) -> None:
        """The serialization error derives directly from the SSZ base error."""
        assert SSZSerializationError.__bases__ == (SSZError,)

    def test_every_specific_error_is_catchable_as_base_error(self) -> None:
        """Each specific SSZ error is reachable through the common base type."""
        assert issubclass(SSZTypeError, SSZError)
        assert issubclass(SSZValueError, SSZError)
        assert issubclass(SSZSerializationError, SSZError)


class TestSSZExceptionPydanticCompatibility:
    """Tests guarding the deliberate non-inheritance from builtin error types."""

    def test_base_error_is_not_a_builtin_value_or_type_error(self) -> None:
        """The SSZ base error must not derive from the builtin ValueError or TypeError."""
        assert not issubclass(SSZError, ValueError)
        assert not issubclass(SSZError, TypeError)

    def test_type_error_is_not_a_builtin_type_error(self) -> None:
        """The SSZ type error must not derive from the builtin TypeError."""
        assert not issubclass(SSZTypeError, TypeError)

    def test_value_error_is_not_a_builtin_value_error(self) -> None:
        """The SSZ value error must not derive from the builtin ValueError."""
        assert not issubclass(SSZValueError, ValueError)

    def test_serialization_error_is_not_a_builtin_value_error(self) -> None:
        """The SSZ serialization error must not derive from the builtin ValueError."""
        assert not issubclass(SSZSerializationError, ValueError)


class TestSSZExceptionMessages:
    """Tests for message handling on SSZ exceptions."""

    def test_type_error_reports_its_message(self) -> None:
        """The type error reports the exact message it was raised with."""
        raised = SSZTypeError("cannot coerce list into Uint64")
        assert str(raised) == "cannot coerce list into Uint64"

    def test_value_error_reports_its_message(self) -> None:
        """The value error reports the exact message it was raised with."""
        raised = SSZValueError("value 256 overflows Uint8")
        assert str(raised) == "value 256 overflows Uint8"

    def test_serialization_error_reports_its_message(self) -> None:
        """The serialization error reports the exact message it was raised with."""
        raised = SSZSerializationError("unexpected end of stream")
        assert str(raised) == "unexpected end of stream"
