"""SSZ conformance test vectors for all non-container types."""

from typing import ClassVar

import pytest

from consensus_testing import SSZTestFiller
from lean_spec.node.networking.enr.eth2 import AttestationSubnets
from lean_spec.spec.crypto.koalabear import Fp, P
from lean_spec.spec.ssz import (
    BaseBitlist,
    BaseBitvector,
    Boolean,
    ByteList512KiB,
    Bytes4,
    Bytes32,
    Bytes52,
    Bytes64,
    SSZList,
    SSZVector,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
)

pytestmark = pytest.mark.valid_until("Lstar")


# --- Test helper types ---


class SampleBitvector8(BaseBitvector):
    """8-bit bitvector. Fits exactly in one byte of SSZ encoding."""

    LENGTH: ClassVar[int] = 8


class SampleBitvector64(BaseBitvector):
    """64-bit bitvector. Spans multiple 32-byte Merkle chunks."""

    LENGTH: ClassVar[int] = 64


class SampleBitlist16(BaseBitlist):
    """Bitlist allowing up to 16 bits. Exercises the length-delimiting sentinel bit."""

    LIMIT: ClassVar[int] = 16


class SampleUint16Vector3(SSZVector[Uint16]):
    """Fixed-length vector of 3 two-byte elements (6 bytes total)."""

    LENGTH: ClassVar[int] = 3


class SampleUint64Vector4(SSZVector[Uint64]):
    """Fixed-length vector of 4 eight-byte elements (32 bytes, one full chunk)."""

    LENGTH: ClassVar[int] = 4


class SampleUint32List16(SSZList[Uint32]):
    """Variable-length list of up to 16 four-byte elements."""

    LIMIT: ClassVar[int] = 16
    ELEMENT_TYPE = Uint32


class SampleBytes32List8(SSZList[Bytes32]):
    """Variable-length list of up to 8 fixed-size 32-byte elements."""

    LIMIT: ClassVar[int] = 8
    ELEMENT_TYPE = Bytes32


# --- Boolean ---


def test_boolean_false(ssz_test: SSZTestFiller) -> None:
    """Boolean false encodes as 0x00."""
    ssz_test(type_name="Boolean", value=Boolean(False))


def test_boolean_true(ssz_test: SSZTestFiller) -> None:
    """Boolean true encodes as 0x01."""
    ssz_test(type_name="Boolean", value=Boolean(True))


# --- Uint8 ---


def test_uint8_zero(ssz_test: SSZTestFiller) -> None:
    """Uint8 lower bound (0)."""
    ssz_test(type_name="Uint8", value=Uint8(0))


def test_uint8_one(ssz_test: SSZTestFiller) -> None:
    """Uint8 smallest nonzero value (1)."""
    ssz_test(type_name="Uint8", value=Uint8(1))


def test_uint8_mid(ssz_test: SSZTestFiller) -> None:
    """Uint8 midpoint with high bit set (128)."""
    ssz_test(type_name="Uint8", value=Uint8(128))


def test_uint8_max(ssz_test: SSZTestFiller) -> None:
    """Uint8 upper bound (255)."""
    ssz_test(type_name="Uint8", value=Uint8(2**8 - 1))


# --- Uint16 ---


def test_uint16_zero(ssz_test: SSZTestFiller) -> None:
    """Uint16 lower bound (0)."""
    ssz_test(type_name="Uint16", value=Uint16(0))


def test_uint16_one(ssz_test: SSZTestFiller) -> None:
    """Uint16 smallest nonzero value (1)."""
    ssz_test(type_name="Uint16", value=Uint16(1))


def test_uint16_mid(ssz_test: SSZTestFiller) -> None:
    """Uint16 midpoint with high bit set (32768). Tests little-endian byte order."""
    ssz_test(type_name="Uint16", value=Uint16(32768))


def test_uint16_max(ssz_test: SSZTestFiller) -> None:
    """Uint16 upper bound (65535)."""
    ssz_test(type_name="Uint16", value=Uint16(2**16 - 1))


# --- Uint32 ---


def test_uint32_zero(ssz_test: SSZTestFiller) -> None:
    """Uint32 lower bound (0)."""
    ssz_test(type_name="Uint32", value=Uint32(0))


def test_uint32_one(ssz_test: SSZTestFiller) -> None:
    """Uint32 smallest nonzero value (1)."""
    ssz_test(type_name="Uint32", value=Uint32(1))


def test_uint32_mid(ssz_test: SSZTestFiller) -> None:
    """Uint32 midpoint with high bit set (2^31). Tests 4-byte little-endian layout."""
    ssz_test(type_name="Uint32", value=Uint32(2147483648))


def test_uint32_max(ssz_test: SSZTestFiller) -> None:
    """Uint32 upper bound (2^32 - 1)."""
    ssz_test(type_name="Uint32", value=Uint32(2**32 - 1))


# --- Uint64 ---


def test_uint64_zero(ssz_test: SSZTestFiller) -> None:
    """Uint64 lower bound (0)."""
    ssz_test(type_name="Uint64", value=Uint64(0))


def test_uint64_one(ssz_test: SSZTestFiller) -> None:
    """Uint64 smallest nonzero value (1)."""
    ssz_test(type_name="Uint64", value=Uint64(1))


def test_uint64_mid(ssz_test: SSZTestFiller) -> None:
    """Uint64 midpoint with high bit set (2^63). Tests 8-byte little-endian layout."""
    ssz_test(type_name="Uint64", value=Uint64(2**63))


def test_uint64_max(ssz_test: SSZTestFiller) -> None:
    """Uint64 upper bound (2^64 - 1). All bytes 0xFF."""
    ssz_test(type_name="Uint64", value=Uint64(2**64 - 1))


# --- Bytes4 ---


def test_bytes4_zero(ssz_test: SSZTestFiller) -> None:
    """Bytes4 all zeros. Minimal content, still pads to 32-byte chunk."""
    ssz_test(type_name="Bytes4", value=Bytes4(b"\x00" * 4))


def test_bytes4_typical(ssz_test: SSZTestFiller) -> None:
    """Bytes4 with nonzero content (0xDEADBEEF)."""
    ssz_test(type_name="Bytes4", value=Bytes4(b"\xde\xad\xbe\xef"))


# --- Bytes32 ---


def test_bytes32_zero(ssz_test: SSZTestFiller) -> None:
    """Bytes32 all zeros. One full chunk of zero bytes."""
    ssz_test(type_name="Bytes32", value=Bytes32.zero())


def test_bytes32_typical(ssz_test: SSZTestFiller) -> None:
    """Bytes32 with uniform nonzero content (0xAB repeated)."""
    ssz_test(type_name="Bytes32", value=Bytes32(b"\xab" * 32))


def test_bytes32_incremental(ssz_test: SSZTestFiller) -> None:
    """Bytes32 with every byte distinct (0x00..0x1F). Catches byte-swap errors."""
    ssz_test(type_name="Bytes32", value=Bytes32(bytes(range(32))))


# --- Bytes52 ---


def test_bytes52_zero(ssz_test: SSZTestFiller) -> None:
    """Bytes52 all zeros. Two chunks, second chunk partially zero-padded."""
    ssz_test(type_name="Bytes52", value=Bytes52.zero())


def test_bytes52_typical(ssz_test: SSZTestFiller) -> None:
    """Bytes52 with uniform nonzero content (0xCD repeated)."""
    ssz_test(type_name="Bytes52", value=Bytes52(b"\xcd" * 52))


# --- Bytes64 ---


def test_bytes64_zero(ssz_test: SSZTestFiller) -> None:
    """Bytes64 all zeros. Two full chunks of zero bytes."""
    ssz_test(type_name="Bytes64", value=Bytes64.zero())


def test_bytes64_typical(ssz_test: SSZTestFiller) -> None:
    """Bytes64 with uniform nonzero content (0xEF repeated)."""
    ssz_test(type_name="Bytes64", value=Bytes64(b"\xef" * 64))


# --- ByteList512KiB ---


def test_bytelist_empty(ssz_test: SSZTestFiller) -> None:
    """Empty byte list. Zero-length content with length mix-in of zero."""
    ssz_test(type_name="ByteList512KiB", value=ByteList512KiB(data=b""))


def test_bytelist_small(ssz_test: SSZTestFiller) -> None:
    """Byte list with 4 bytes. Fits within a single 32-byte chunk."""
    ssz_test(type_name="ByteList512KiB", value=ByteList512KiB(data=b"\x01\x02\x03\x04"))


def test_bytelist_medium(ssz_test: SSZTestFiller) -> None:
    """Byte list with 256 bytes. Spans 8 full chunks."""
    ssz_test(type_name="ByteList512KiB", value=ByteList512KiB(data=bytes(range(256))))


# --- Bitvector ---


def test_bitvector8_all_zero(ssz_test: SSZTestFiller) -> None:
    """8-bit bitvector, all bits clear (0x00)."""
    ssz_test(
        type_name="SampleBitvector8",
        value=SampleBitvector8(data=[Boolean(False)] * 8),
    )


def test_bitvector8_all_one(ssz_test: SSZTestFiller) -> None:
    """8-bit bitvector, all bits set (0xFF)."""
    ssz_test(
        type_name="SampleBitvector8",
        value=SampleBitvector8(data=[Boolean(True)] * 8),
    )


def test_bitvector8_mixed(ssz_test: SSZTestFiller) -> None:
    """8-bit bitvector, alternating bits (0x55). Tests per-bit placement."""
    ssz_test(
        type_name="SampleBitvector8",
        value=SampleBitvector8(
            data=[
                Boolean(True),
                Boolean(False),
                Boolean(True),
                Boolean(False),
                Boolean(True),
                Boolean(False),
                Boolean(True),
                Boolean(False),
            ]
        ),
    )


def test_bitvector64_all_zero(ssz_test: SSZTestFiller) -> None:
    """64-bit bitvector, all bits clear. 8 zero bytes."""
    ssz_test(
        type_name="SampleBitvector64",
        value=SampleBitvector64(data=[Boolean(False)] * 64),
    )


def test_bitvector64_all_one(ssz_test: SSZTestFiller) -> None:
    """64-bit bitvector, all bits set. 8 bytes of 0xFF."""
    ssz_test(
        type_name="SampleBitvector64",
        value=SampleBitvector64(data=[Boolean(True)] * 64),
    )


def test_bitvector64_mixed(ssz_test: SSZTestFiller) -> None:
    """64-bit bitvector, alternating bits. Tests bit ordering across byte boundaries."""
    ssz_test(
        type_name="SampleBitvector64",
        value=SampleBitvector64(data=[Boolean(i % 2 == 0) for i in range(64)]),
    )


# --- Bitlist ---


def test_bitlist_empty(ssz_test: SSZTestFiller) -> None:
    """Empty bitlist. Sentinel-only encoding (0x01)."""
    ssz_test(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[]),
    )


def test_bitlist_single_true(ssz_test: SSZTestFiller) -> None:
    """Bitlist with one set bit. Sentinel immediately follows the data bit."""
    ssz_test(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[Boolean(True)]),
    )


def test_bitlist_single_false(ssz_test: SSZTestFiller) -> None:
    """Bitlist with one clear bit. The sentinel is the only set bit in the byte."""
    ssz_test(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[Boolean(False)]),
    )


def test_bitlist_at_limit(ssz_test: SSZTestFiller) -> None:
    """Bitlist filled to its 16-bit limit. Sentinel lands in a new byte."""
    ssz_test(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[Boolean(True)] * 16),
    )


def test_bitlist_mixed(ssz_test: SSZTestFiller) -> None:
    """Bitlist with 5 mixed bits. Partial fill below the 16-bit limit."""
    ssz_test(
        type_name="SampleBitlist16",
        value=SampleBitlist16(
            data=[
                Boolean(True),
                Boolean(False),
                Boolean(True),
                Boolean(True),
                Boolean(False),
            ]
        ),
    )


# --- SSZVector ---


def test_uint16_vector3_zero(ssz_test: SSZTestFiller) -> None:
    """3-element Uint16 vector, all zeros. 6 bytes total, padded to one chunk."""
    ssz_test(
        type_name="SampleUint16Vector3",
        value=SampleUint16Vector3(data=[Uint16(0), Uint16(0), Uint16(0)]),
    )


def test_uint16_vector3_typical(ssz_test: SSZTestFiller) -> None:
    """3-element Uint16 vector with mixed values, including the maximum (65535)."""
    ssz_test(
        type_name="SampleUint16Vector3",
        value=SampleUint16Vector3(data=[Uint16(100), Uint16(200), Uint16(65535)]),
    )


def test_uint64_vector4_zero(ssz_test: SSZTestFiller) -> None:
    """4-element Uint64 vector, all zeros. Fills exactly one 32-byte chunk."""
    ssz_test(
        type_name="SampleUint64Vector4",
        value=SampleUint64Vector4(data=[Uint64(0), Uint64(0), Uint64(0), Uint64(0)]),
    )


def test_uint64_vector4_typical(ssz_test: SSZTestFiller) -> None:
    """4-element Uint64 vector spanning the full value range per element."""
    ssz_test(
        type_name="SampleUint64Vector4",
        value=SampleUint64Vector4(
            data=[
                Uint64(1),
                Uint64(2**32),
                Uint64(2**63),
                Uint64(2**64 - 1),
            ]
        ),
    )


# --- SSZList ---


def test_uint32_list_empty(ssz_test: SSZTestFiller) -> None:
    """Empty Uint32 list. Length mix-in is zero, data tree is all-zero."""
    ssz_test(
        type_name="SampleUint32List16",
        value=SampleUint32List16(data=[]),
    )


def test_uint32_list_single(ssz_test: SSZTestFiller) -> None:
    """Uint32 list with one element. Minimal non-empty list."""
    ssz_test(
        type_name="SampleUint32List16",
        value=SampleUint32List16(data=[Uint32(42)]),
    )


def test_uint32_list_multiple(ssz_test: SSZTestFiller) -> None:
    """Uint32 list with three elements spanning the full value range."""
    ssz_test(
        type_name="SampleUint32List16",
        value=SampleUint32List16(data=[Uint32(0), Uint32(100), Uint32(2**32 - 1)]),
    )


def test_bytes32_list_empty(ssz_test: SSZTestFiller) -> None:
    """Empty Bytes32 list. Each element would occupy one full chunk."""
    ssz_test(
        type_name="SampleBytes32List8",
        value=SampleBytes32List8(data=[]),
    )


def test_bytes32_list_single(ssz_test: SSZTestFiller) -> None:
    """Bytes32 list with one element. Single chunk plus length mix-in."""
    ssz_test(
        type_name="SampleBytes32List8",
        value=SampleBytes32List8(data=[Bytes32(b"\xaa" * 32)]),
    )


def test_bytes32_list_multiple(ssz_test: SSZTestFiller) -> None:
    """Bytes32 list with three elements. Tests multi-chunk Merkle tree with mix-in."""
    ssz_test(
        type_name="SampleBytes32List8",
        value=SampleBytes32List8(
            data=[
                Bytes32(b"\x01" * 32),
                Bytes32(b"\x02" * 32),
                Bytes32.zero(),
            ]
        ),
    )


# --- Fp ---


def test_fp_zero(ssz_test: SSZTestFiller) -> None:
    """Field element zero. The additive identity."""
    ssz_test(type_name="Fp", value=Fp(0))


def test_fp_one(ssz_test: SSZTestFiller) -> None:
    """Field element one. The multiplicative identity."""
    ssz_test(type_name="Fp", value=Fp(1))


def test_fp_max(ssz_test: SSZTestFiller) -> None:
    """Field element p-1. The largest valid element in the field."""
    ssz_test(type_name="Fp", value=Fp(P - 1))


# --- Domain Bitvectors ---


def test_attestation_subnets_none(ssz_test: SSZTestFiller) -> None:
    """Attestation subnets with no subscriptions (all 64 bits clear)."""
    ssz_test(type_name="AttestationSubnets", value=AttestationSubnets.none())


def test_attestation_subnets_all(ssz_test: SSZTestFiller) -> None:
    """Attestation subnets with all 64 subscriptions active."""
    ssz_test(type_name="AttestationSubnets", value=AttestationSubnets.all())


def test_attestation_subnets_partial(ssz_test: SSZTestFiller) -> None:
    """Attestation subnets with 5 selected IDs spanning the full 64-bit range."""
    ssz_test(
        type_name="AttestationSubnets",
        value=AttestationSubnets.from_subnet_ids([0, 7, 15, 31, 63]),
    )
