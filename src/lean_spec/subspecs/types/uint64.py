"""Unsigned 64-bit Integer Type Specification."""

from pydantic import Field
from typing_extensions import Annotated

# The maximum value for an unsigned 64-bit integer (2**64).
UINT64_MAX = 2**64

# A type alias to represent a uint64.
uint64 = Annotated[int, Field(ge=0, lt=UINT64_MAX)]
