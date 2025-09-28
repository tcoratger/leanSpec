"""SSZ Union type."""

from __future__ import annotations

import io
from typing import (
    IO,
    Any,
    ClassVar,
    Final,
    Tuple,
    Type,
    cast,
)

from pydantic import Field, field_validator
from typing_extensions import Self

from .ssz_base import SSZModel, SSZType

# Constants for Union implementation
MAX_UNION_OPTIONS: Final[int] = 128
"""Maximum number of options allowed in a Union (uint8 selector range)."""

SELECTOR_BYTE_SIZE: Final[int] = 1
"""Size in bytes of the selector field in SSZ encoding."""


class SSZUnion(SSZModel):
    """
    Base class for SSZ Union types using clean inheritance pattern.

    Union types represent tagged sum types (discriminated unions) that hold exactly
    one value from a predefined set of SSZ types. This implementation uses clean
    inheritance patterns similar to SSZVector and SSZList.

    ## Creating Union Types

    Inherit from SSZUnion and define the OPTIONS class variable:

    ```python
    class MyUnion(SSZUnion):
        \"\"\"Union of numeric types.\"\"\"
        OPTIONS = (Uint16, Uint32, Uint64)

    class OptionalUnion(SSZUnion):
        \"\"\"Optional union with None variant.\"\"\"
        OPTIONS = (None, MyContainer)
    ```

    ## Instance Creation

    Create instances using selector and value:

    ```python
    # Direct instantiation
    instance = MyUnion(selector=1, value=Uint32(42))

    # Using data tuple (internal format)
    instance = MyUnion(data=(1, Uint32(42)))

    # Pydantic-style creation
    instance = MyUnion.model_validate({"selector": 1, "value": 42})
    ```

    ## Data Access

    Access union data through properties:

    ```python
    assert instance.selector == 1
    assert instance.selected_type == Uint32
    assert instance.value == Uint32(42)
    ```

    ## Type Safety

    - OPTIONS must be tuple of SSZType classes (or None at index 0)
    - Selector must be valid index into OPTIONS tuple
    - Values are validated and coerced to selected type
    - Comprehensive error messages for invalid configurations
    """

    OPTIONS: ClassVar[Tuple[Type[SSZType] | None, ...]]
    """Tuple of possible types for this Union.

    Each position corresponds to a selector index. Only index 0 may be None.
    All non-None options must implement the SSZType protocol.

    Example:
        OPTIONS = (None, Uint16, Uint32) allows:
        - selector=0 -> None (null variant)
        - selector=1 -> Uint16 values
        - selector=2 -> Uint32 values
    """

    data: Tuple[int, Any] = Field(default_factory=lambda: (0, None))
    """The union data stored as (selector, value) tuple.

    This is the internal storage format. Use selector/value properties
    or the constructor parameters for external access.
    """

    @field_validator("data", mode="before")
    @classmethod
    def _validate_union_data(cls, v: Any) -> Tuple[int, Any]:
        """Validate and convert union data to (selector, value) tuple."""
        # Check required class attributes
        if not hasattr(cls, "OPTIONS") or not isinstance(cls.OPTIONS, tuple):
            raise TypeError(f"{cls.__name__} must define OPTIONS as a tuple of SSZ types")

        options = cls.OPTIONS
        options_count = len(options)

        # Validate OPTIONS constraints
        if options_count == 0:
            raise TypeError(f"{cls.__name__} OPTIONS cannot be empty")
        if options_count > MAX_UNION_OPTIONS:
            raise TypeError(
                f"{cls.__name__} has {options_count} options, but maximum is {MAX_UNION_OPTIONS}"
            )
        if options[0] is None and options_count == 1:
            raise TypeError(f"{cls.__name__} cannot have None as the only option")

        # Validate None placement (only at index 0) and types
        for i, opt in enumerate(options):
            if opt is None and i != 0:
                raise TypeError(f"{cls.__name__} can only have None at index 0, found at index {i}")
            elif opt is not None and not isinstance(opt, type):
                raise TypeError(f"{cls.__name__} option {i} must be a type, got {type(opt)}")

        # Normalize input to (selector, value) tuple
        if not isinstance(v, tuple) or len(v) != 2:
            raise ValueError(
                f"{cls.__name__} data must be a (selector, value) tuple, got {type(v)}"
            )

        selector, value = v

        # Validate selector
        if not isinstance(selector, int):
            raise ValueError(f"Selector must be int, got {type(selector)}")
        if not 0 <= selector < options_count:
            raise ValueError(f"Invalid selector {selector} for {options_count} options")

        # Validate and coerce value for selected option
        selected_type = options[selector]

        if selected_type is None:
            # None option - value must be None
            if value is not None:
                raise TypeError("Selected option is None, therefore value must be None")
            return (selector, None)

        # Non-None option - validate and coerce value
        if isinstance(value, selected_type):
            return (selector, value)

        try:
            coerced_value = cast(Any, selected_type)(value)
            return (selector, coerced_value)
        except Exception as e:
            raise TypeError(
                f"Cannot coerce {type(value).__name__} to {selected_type.__name__}: {e}"
            ) from e

    @property
    def selector(self) -> int:
        """The 0-based index of the currently selected option."""
        return self.data[0]

    @property
    def value(self) -> Any:
        """The value currently stored in this Union."""
        return self.data[1]

    @property
    def selected_type(self) -> Type[SSZType] | None:
        """The type class of the currently selected option."""
        return self.OPTIONS[self.selector]

    @classmethod
    def options(cls) -> Tuple[Type[SSZType] | None, ...]:
        """Get the tuple of possible types for this Union."""
        return cls.OPTIONS

    @classmethod
    def is_fixed_size(cls) -> bool:
        """Union types are always variable-size in SSZ."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """Union types are variable-size and don't have fixed length."""
        raise TypeError(f"{cls.__name__} is variable-size")

    def serialize(self, stream: IO[bytes]) -> int:
        """Serialize this Union to a byte stream in SSZ format."""
        # Write selector byte and return early for None
        stream.write(self.selector.to_bytes(SELECTOR_BYTE_SIZE, byteorder="little"))
        return SELECTOR_BYTE_SIZE + (
            cast(SSZType, self.value).serialize(stream) if self.selected_type is not None else 0
        )

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Deserialize a Union from a byte stream using SSZ format."""
        # Validate scope for selector byte
        if scope < SELECTOR_BYTE_SIZE:
            raise ValueError("Scope too small for Union selector")

        # Read selector byte
        selector_bytes = stream.read(SELECTOR_BYTE_SIZE)
        if len(selector_bytes) != SELECTOR_BYTE_SIZE:
            raise IOError("Stream ended reading Union selector")

        selector = int.from_bytes(selector_bytes, byteorder="little")
        remaining_bytes = scope - SELECTOR_BYTE_SIZE

        # Validate selector range
        if not 0 <= selector < len(cls.OPTIONS):
            raise ValueError(f"Selector {selector} out of range for {len(cls.OPTIONS)} options")

        selected_type = cls.OPTIONS[selector]

        # Handle None option
        if selected_type is None:
            if remaining_bytes != 0:
                raise ValueError("Invalid encoding: None arm must have no payload bytes")
            return cls(data=(selector, None))

        # Handle non-None option
        if selected_type.is_fixed_size() and hasattr(selected_type, "get_byte_length"):
            required_bytes = selected_type.get_byte_length()
            if remaining_bytes < required_bytes:
                raise IOError(f"Need {required_bytes} bytes, got {remaining_bytes}")

        # Deserialize value
        try:
            value = selected_type.deserialize(stream, remaining_bytes)
            return cls(data=(selector, value))
        except Exception as e:
            raise IOError(f"Failed to deserialize {selected_type.__name__}: {e}") from e

    def encode_bytes(self) -> bytes:
        """Encode this Union to bytes."""
        with io.BytesIO() as stream:
            self.serialize(stream)
            return stream.getvalue()

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Decode a Union from bytes."""
        return cls.deserialize(io.BytesIO(data), len(data))

    def __repr__(self) -> str:
        """Return a readable string representation of this Union."""
        return f"{type(self).__name__}(selector={self.selector}, value={self.value!r})"
