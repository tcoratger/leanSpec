"""Test vectors for req/resp wire format encoding."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Devnet")


# --- Request encoding ---


def test_request_empty(networking_codec: NetworkingCodecTestFiller) -> None:
    """Request with empty SSZ payload. Varint prefix is 0x00."""
    networking_codec(codec_name="reqresp_request", input={"sszData": "0x"})


def test_request_small(networking_codec: NetworkingCodecTestFiller) -> None:
    """Request with 4-byte SSZ payload."""
    networking_codec(codec_name="reqresp_request", input={"sszData": "0x01020304"})


def test_request_varint_one_byte_max(networking_codec: NetworkingCodecTestFiller) -> None:
    """Request with 127-byte payload. Largest single-byte varint prefix."""
    networking_codec(
        codec_name="reqresp_request",
        input={"sszData": "0x" + "ab" * 127},
    )


def test_request_varint_two_byte_min(networking_codec: NetworkingCodecTestFiller) -> None:
    """Request with 128-byte payload. Smallest two-byte varint prefix."""
    networking_codec(
        codec_name="reqresp_request",
        input={"sszData": "0x" + "cd" * 128},
    )


def test_request_compressible(networking_codec: NetworkingCodecTestFiller) -> None:
    """Request with 1 KB of repeated data. Exercises Snappy copy tags."""
    networking_codec(
        codec_name="reqresp_request",
        input={"sszData": "0x" + "deadbeef" * 256},
    )


def test_request_sequential(networking_codec: NetworkingCodecTestFiller) -> None:
    """Request with 256 sequential bytes. Low compression ratio."""
    networking_codec(
        codec_name="reqresp_request",
        input={"sszData": "0x" + bytes(range(256)).hex()},
    )


def test_request_all_zeros(networking_codec: NetworkingCodecTestFiller) -> None:
    """Request with 32 zero bytes. Tests CRC32C on uniform input."""
    networking_codec(
        codec_name="reqresp_request",
        input={"sszData": "0x" + "00" * 32},
    )


# --- Response encoding ---


def test_response_success_small(networking_codec: NetworkingCodecTestFiller) -> None:
    """SUCCESS response with 4-byte SSZ payload."""
    networking_codec(
        codec_name="reqresp_response",
        input={"responseCode": 0, "sszData": "0x01020304"},
    )


def test_response_success_empty(networking_codec: NetworkingCodecTestFiller) -> None:
    """SUCCESS response with empty payload."""
    networking_codec(
        codec_name="reqresp_response",
        input={"responseCode": 0, "sszData": "0x"},
    )


def test_response_invalid_request(networking_codec: NetworkingCodecTestFiller) -> None:
    """INVALID_REQUEST response with UTF-8 error message."""
    networking_codec(
        codec_name="reqresp_response",
        input={"responseCode": 1, "sszData": "0x" + b"bad request".hex()},
    )


def test_response_server_error(networking_codec: NetworkingCodecTestFiller) -> None:
    """SERVER_ERROR response with UTF-8 error message."""
    networking_codec(
        codec_name="reqresp_response",
        input={"responseCode": 2, "sszData": "0x" + b"internal error".hex()},
    )


def test_response_resource_unavailable(networking_codec: NetworkingCodecTestFiller) -> None:
    """RESOURCE_UNAVAILABLE response with UTF-8 error message."""
    networking_codec(
        codec_name="reqresp_response",
        input={"responseCode": 3, "sszData": "0x" + b"block not found".hex()},
    )


def test_response_success_sequential(networking_codec: NetworkingCodecTestFiller) -> None:
    """SUCCESS response with 256 sequential bytes."""
    networking_codec(
        codec_name="reqresp_response",
        input={"responseCode": 0, "sszData": "0x" + bytes(range(256)).hex()},
    )


def test_response_success_compressible(networking_codec: NetworkingCodecTestFiller) -> None:
    """SUCCESS response with 1 KB of repeated data."""
    networking_codec(
        codec_name="reqresp_response",
        input={"responseCode": 0, "sszData": "0x" + "cafebabe" * 256},
    )


def test_response_success_all_ff(networking_codec: NetworkingCodecTestFiller) -> None:
    """SUCCESS response with 32 bytes of 0xFF."""
    networking_codec(
        codec_name="reqresp_response",
        input={"responseCode": 0, "sszData": "0x" + "ff" * 32},
    )
