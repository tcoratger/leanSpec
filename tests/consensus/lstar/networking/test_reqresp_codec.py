"""Test vectors for req/resp wire format encoding."""

import pytest

from consensus_testing import (
    NetworkingCodecTestFiller,
    ReqRespRequestRoundtrip,
    ReqRespResponseRoundtrip,
)

pytestmark = pytest.mark.valid_until("Lstar")


# --- Request encoding ---


def test_request_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Request with empty SSZ payload. Varint prefix is 0x00."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x"),
    )


def test_request_small(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Request with 4-byte SSZ payload."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x01020304"),
    )


def test_request_varint_one_byte_max(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Request with 127-byte payload. Largest single-byte varint prefix."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "ab" * 127),
    )


def test_request_varint_two_byte_min(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Request with 128-byte payload. Smallest two-byte varint prefix."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "cd" * 128),
    )


def test_request_compressible(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Request with 1 KB of repeated data. Exercises Snappy copy tags."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "deadbeef" * 256),
    )


def test_request_sequential(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Request with 256 sequential bytes. Low compression ratio."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + bytes(range(256)).hex()),
    )


def test_request_all_zeros(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Request with 32 zero bytes. Tests CRC32C on uniform input."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "00" * 32),
    )


# --- Response encoding ---


def test_response_success_small(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """SUCCESS response with 4-byte SSZ payload."""
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data="0x01020304"),
    )


def test_response_success_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """SUCCESS response with empty payload."""
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data="0x"),
    )


def test_response_invalid_request(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """INVALID_REQUEST response with UTF-8 error message."""
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=1, ssz_data="0x" + b"bad request".hex()),
    )


def test_response_server_error(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """SERVER_ERROR response with UTF-8 error message."""
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=2, ssz_data="0x" + b"internal error".hex()),
    )


def test_response_resource_unavailable(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """RESOURCE_UNAVAILABLE response with UTF-8 error message."""
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=3, ssz_data="0x" + b"block not found".hex()),
    )


def test_response_success_sequential(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """SUCCESS response with 256 sequential bytes."""
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data="0x" + bytes(range(256)).hex()),
    )


def test_response_success_compressible(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """SUCCESS response with 1 KB of repeated data."""
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data="0x" + "cafebabe" * 256),
    )


def test_response_success_all_ff(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """SUCCESS response with 32 bytes of 0xFF."""
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data="0x" + "ff" * 32),
    )


# --- End-to-end protocol messages ---
#
# Full stack: SSZ container → wire encode → wire decode → SSZ decode.
# These use the actual Lean consensus message types, not arbitrary bytes.

STATUS_SSZ = (
    "0x01010101010101010101010101010101010101010101010101010101010101016400"
    "000000000000020202020202020202020202020202020202020202020202020202020202"
    "02020296000000000000"
)
"""Status(finalized=Checkpoint(0x01..01, slot=100), head=Checkpoint(0x02..02, slot=150))."""

BLOCKS_BY_ROOT_SSZ = (
    "0x04000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)
"""BlocksByRootRequest with two roots (0xaa..aa, 0xbb..bb)."""

BLOCKS_BY_ROOT_EMPTY_SSZ = "0x04000000"
"""BlocksByRootRequest with empty root list (4-byte SSZ offset only)."""


def test_request_status(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Status request through the full wire pipeline. Protocol: /leanconsensus/req/status/1."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data=STATUS_SSZ),
    )


def test_response_status(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Status SUCCESS response through the full wire pipeline."""
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data=STATUS_SSZ),
    )


def test_request_blocks_by_root(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """BlocksByRoot request with two roots. Protocol: /leanconsensus/req/blocks_by_root/1."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data=BLOCKS_BY_ROOT_SSZ),
    )


def test_request_blocks_by_root_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """BlocksByRoot request with empty root list. Minimal 4-byte SSZ payload."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data=BLOCKS_BY_ROOT_EMPTY_SSZ),
    )


def test_request_snappy_chunk_boundary(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Request at Snappy chunk boundary (65536 bytes). Exercises multi-chunk framing."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "ab" * 65536),
    )


def test_request_multi_chunk(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Request spanning 2+ Snappy chunks (65537 bytes)."""
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "cd" * 65537),
    )
