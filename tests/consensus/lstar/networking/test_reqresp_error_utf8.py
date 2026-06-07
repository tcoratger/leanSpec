"""Req/resp error-response payload roundtrip at size and UTF-8 boundaries."""

import pytest

from consensus_testing import NetworkingCodecTestFiller, ReqRespResponseRoundtrip

pytestmark = pytest.mark.valid_until("Lstar")


def test_reqresp_error_at_max_error_message_size(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    Error response carrying a payload at the maximum error-message size roundtrips.

    The handler truncates server-side error strings to 256 bytes before
    encoding. A payload at that boundary exercises the exact wire shape
    clients may receive and must be able to decode back to the same
    bytes without loss.
    """
    payload = b"e" * 256
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=1, ssz_data="0x" + payload.hex()),
    )


def test_reqresp_error_with_multi_byte_utf8(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    Error response carrying multi-byte UTF-8 text roundtrips byte-for-byte.

    The codec treats the payload as opaque bytes. A multi-byte UTF-8
    payload verifies that compression, length framing, and decode
    preserve the original bytes even when they are not ASCII-only.
    """
    payload = "errür😀fail".encode()
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=2, ssz_data="0x" + payload.hex()),
    )


def test_reqresp_error_resource_unavailable_with_informational_text(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    Error code 3 response carrying a short descriptive message roundtrips.

    Pins the wire shape for the common peer-observed case of an
    informational error string alongside the RESOURCE_UNAVAILABLE code.
    """
    payload = b"block not found"
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=3, ssz_data="0x" + payload.hex()),
    )
