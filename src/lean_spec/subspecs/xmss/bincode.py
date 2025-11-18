"""Bincode-compatible serialization for XMSS structures."""

from typing import Callable, List, Tuple, TypeVar

T = TypeVar("T")


def encode_varint_u64(value: int) -> bytes:
    """
    Encode an unsigned 64-bit integer as a bincode varint.

    Args:
        value: The integer to encode (0 <= value < 2^64).

    Returns:
        Varint-encoded bytes.

    Raises:
        ValueError: If value is negative or too large.
    """
    if value < 0:
        raise ValueError(f"Cannot encode negative value as varint: {value}")
    if value >= 2**64:
        raise ValueError(f"Value too large for u64 varint: {value}")

    if value < 251:
        return bytes([value])
    elif value < 2**16:
        return bytes([251]) + value.to_bytes(2, "little")
    elif value < 2**32:
        return bytes([252]) + value.to_bytes(4, "little")
    else:
        return bytes([253]) + value.to_bytes(8, "little")


def decode_varint_u64(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Decode a bincode varint from bytes.

    Args:
        data: The bytes to decode from.
        offset: Starting position in data.

    Returns:
        A tuple of (decoded_value, bytes_consumed).

    Raises:
        ValueError: If data is too short or invalid.
    """
    if offset >= len(data):
        raise ValueError("Not enough data to decode varint")

    marker = data[offset]

    if marker < 251:
        return (marker, 1)
    elif marker == 251:
        if offset + 3 > len(data):
            raise ValueError("Not enough data for u16 varint")
        value = int.from_bytes(data[offset + 1 : offset + 3], "little")
        return (value, 3)
    elif marker == 252:
        if offset + 5 > len(data):
            raise ValueError("Not enough data for u32 varint")
        value = int.from_bytes(data[offset + 1 : offset + 5], "little")
        return (value, 5)
    elif marker == 253:
        if offset + 9 > len(data):
            raise ValueError("Not enough data for u64 varint")
        value = int.from_bytes(data[offset + 1 : offset + 9], "little")
        return (value, 9)
    else:
        raise ValueError(f"Invalid varint marker: {marker}")


def serialize_vec(items: List[T], item_serializer: Callable[[T], bytes]) -> bytes:
    """
    Serialize a vector (Vec<T>) with bincode-compatible format.

    The format is: varint length + serialized items concatenated.

    Args:
        items: The list of items to serialize.
        item_serializer: Function to serialize each item to bytes.

    Returns:
        Bincode-formatted bytes.
    """
    length_bytes = encode_varint_u64(len(items))
    items_bytes = b"".join(item_serializer(item) for item in items)
    return length_bytes + items_bytes


def deserialize_vec(
    data: bytes,
    offset: int,
    item_deserializer: Callable[[bytes, int], Tuple[T, int]],
) -> Tuple[List[T], int]:
    """
    Deserialize a bincode-encoded vector.

    Args:
        data: The bytes to deserialize from.
        offset: Starting position in data.
        item_deserializer: Function that takes (data, offset) and returns (item, bytes_consumed).

    Returns:
        A tuple of (list_of_items, total_bytes_consumed).

    Raises:
        ValueError: If data is invalid.
    """
    # Read length
    length, length_bytes = decode_varint_u64(data, offset)
    current_offset = offset + length_bytes

    # Read items
    items: List[T] = []
    for _ in range(length):
        item, item_bytes = item_deserializer(data, current_offset)
        items.append(item)
        current_offset += item_bytes

    total_consumed = current_offset - offset
    return (items, total_consumed)
