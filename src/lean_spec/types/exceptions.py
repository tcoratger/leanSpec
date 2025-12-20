"""Exception hierarchy for the SSZ type system."""

from __future__ import annotations

from typing import Any


class SSZError(Exception):
    """
    Base exception for all SSZ-related errors.

    Attributes:
        message: Human-readable error description.
    """

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.message!r})"


class SSZTypeError(SSZError):
    """Base class for type-related errors."""


class SSZTypeDefinitionError(SSZTypeError):
    """
    Raised when an SSZ type class is incorrectly defined.

    Attributes:
        type_name: The name of the type with the definition error.
        missing_attr: The missing or invalid attribute name.
        detail: Additional context about the error.
    """

    def __init__(
        self,
        type_name: str,
        *,
        missing_attr: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.type_name = type_name
        self.missing_attr = missing_attr
        self.detail = detail

        if missing_attr:
            msg = f"{type_name} must define {missing_attr}"
        elif detail:
            msg = f"{type_name}: {detail}"
        else:
            msg = f"{type_name} has an invalid type definition"

        super().__init__(msg)


class SSZTypeCoercionError(SSZTypeError):
    """
    Raised when a value cannot be coerced to the expected SSZ type.

    Attributes:
        expected_type: The type that was expected.
        actual_type: The actual type of the value.
        value: The value that couldn't be coerced (may be truncated for display).
    """

    def __init__(
        self,
        expected_type: str,
        actual_type: str,
        value: Any = None,
    ) -> None:
        self.expected_type = expected_type
        self.actual_type = actual_type
        self.value = value

        msg = f"Expected {expected_type}, got {actual_type}"
        if value is not None:
            value_repr = repr(value)
            if len(value_repr) > 50:
                value_repr = value_repr[:47] + "..."
            msg = f"{msg}: {value_repr}"

        super().__init__(msg)


class SSZValueError(SSZError):
    """
    Base class for value-related errors.

    Raised when a value is invalid for an SSZ operation, even if the type is correct.
    """


class SSZOverflowError(SSZValueError):
    """
    Raised when a numeric value is outside the valid range.

    Attributes:
        value: The value that caused the overflow.
        type_name: The SSZ type that couldn't hold the value.
        min_value: The minimum allowed value (inclusive).
        max_value: The maximum allowed value (inclusive).
    """

    def __init__(
        self,
        value: int,
        type_name: str,
        *,
        min_value: int = 0,
        max_value: int,
    ) -> None:
        self.value = value
        self.type_name = type_name
        self.min_value = min_value
        self.max_value = max_value

        super().__init__(
            f"{value} is out of range for {type_name} (valid range: [{min_value}, {max_value}])"
        )


class SSZLengthError(SSZValueError):
    """
    Raised when a sequence has incorrect length.

    Attributes:
        type_name: The SSZ type with the length constraint.
        expected: The expected length (exact for vectors, max for lists).
        actual: The actual length received.
        is_limit: True if expected is a maximum limit, False if exact.
    """

    def __init__(
        self,
        type_name: str,
        *,
        expected: int,
        actual: int,
        is_limit: bool = False,
    ) -> None:
        self.type_name = type_name
        self.expected = expected
        self.actual = actual
        self.is_limit = is_limit

        if is_limit:
            msg = f"{type_name} cannot exceed {expected} elements, got {actual}"
        else:
            msg = f"{type_name} requires exactly {expected} elements, got {actual}"

        super().__init__(msg)


class SSZSerializationError(SSZError):
    """Base class for serialization-related errors."""


class SSZDecodeError(SSZSerializationError):
    """
    Raised when decoding SSZ bytes to a value fails.

    Attributes:
        type_name: The type being decoded.
        detail: Description of what went wrong.
        offset: The byte offset where the error occurred (if known).
    """

    def __init__(
        self,
        type_name: str,
        detail: str,
        *,
        offset: int | None = None,
    ) -> None:
        self.type_name = type_name
        self.detail = detail
        self.offset = offset

        msg = f"Failed to decode {type_name}: {detail}"
        if offset is not None:
            msg = f"{msg} (at byte offset {offset})"

        super().__init__(msg)


class SSZStreamError(SSZSerializationError):
    """
    Raised when a stream/IO error occurs during SSZ operations.

    Attributes:
        type_name: The type being processed when the error occurred.
        operation: The operation being performed (e.g., "read", "decode").
        expected_bytes: Number of bytes expected (if applicable).
        actual_bytes: Number of bytes received (if applicable).
    """

    def __init__(
        self,
        type_name: str,
        operation: str,
        *,
        expected_bytes: int | None = None,
        actual_bytes: int | None = None,
    ) -> None:
        self.type_name = type_name
        self.operation = operation
        self.expected_bytes = expected_bytes
        self.actual_bytes = actual_bytes

        if expected_bytes is not None and actual_bytes is not None:
            msg = (
                f"Stream error while {operation} {type_name}: "
                f"expected {expected_bytes} bytes, got {actual_bytes}"
            )
        elif expected_bytes is not None:
            msg = (
                f"Stream ended prematurely while {operation} {type_name}: "
                f"needed {expected_bytes} bytes"
            )
        else:
            msg = f"Stream error while {operation} {type_name}"

        super().__init__(msg)


class SSZOffsetError(SSZDecodeError):
    """
    Raised when SSZ offset parsing fails during variable-size decoding.

    Attributes:
        type_name: The container or collection type being decoded.
        field_name: The field with the invalid offset (if applicable).
        start_offset: The start offset value.
        end_offset: The end offset value.
    """

    def __init__(
        self,
        type_name: str,
        *,
        field_name: str | None = None,
        start_offset: int | None = None,
        end_offset: int | None = None,
    ) -> None:
        self.field_name = field_name
        self.start_offset = start_offset
        self.end_offset = end_offset

        if field_name and start_offset is not None and end_offset is not None:
            detail = (
                f"invalid offsets for field '{field_name}' (start={start_offset}, end={end_offset})"
            )
        elif field_name:
            detail = f"invalid offset for field '{field_name}'"
        elif start_offset is not None and end_offset is not None:
            detail = f"invalid offsets: start={start_offset} > end={end_offset}"
        else:
            detail = "invalid offset structure"

        super().__init__(type_name, detail)


class SSZSelectorError(SSZDecodeError):
    """
    Raised when a Union selector is invalid.

    Attributes:
        type_name: The Union type being decoded.
        selector: The invalid selector value.
        num_options: The number of valid options.
    """

    def __init__(
        self,
        type_name: str,
        selector: int,
        num_options: int,
    ) -> None:
        self.selector = selector
        self.num_options = num_options

        detail = f"selector {selector} out of range for {num_options} options"
        super().__init__(type_name, detail)
