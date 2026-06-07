"""
Smoke test for the networking_codec fixture's decode_failure dispatcher.

Exercises the new `decode_failure` codec so the framework change is covered
independently of later negative-path content PRs.
"""

import pytest

from consensus_testing import DecodeFailure, ExpectedRejection, NetworkingCodecTestFiller
from lean_spec.spec.forks import RejectionReason

pytestmark = pytest.mark.valid_until("Lstar")


def test_decode_failure_varint_truncated(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A truncated varint (continuation bit set on the final byte) must fail to decode.

    Pins the new `decode_failure` codec dispatch path on the
    networking_codec fixture.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="varint", raw_bytes="0x80"),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )
