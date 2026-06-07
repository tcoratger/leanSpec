"""
Smoke test for the ssz fixture's decode-failure mode.

Exercises the new `raw_bytes` + `expected_rejection` path so the framework
change is covered independently of later negative-path content PRs.
"""

from typing import ClassVar

import pytest

from consensus_testing import ExpectedRejection, SSZTestFiller
from lean_spec.spec.forks import RejectionReason
from lean_spec.spec.ssz import BaseBitlist, Boolean

pytestmark = pytest.mark.valid_until("Lstar")


class SmokeBitlist8(BaseBitlist):
    """Small bitlist with an 8-bit limit, used only by the decode-failure smoke test."""

    LIMIT: ClassVar[int] = 8


def test_ssz_decode_failure_bitlist_exceeds_limit(ssz_test: SSZTestFiller) -> None:
    """
    Decoding a bitlist whose contents imply a length above its LIMIT raises.

    The payload `0x0010` encodes 16 bits before the sentinel. The `LIMIT`
    on the decoder type is 8, so SSZ decode must reject. This pins the new
    `raw_bytes` + `expected_rejection` path on the ssz fixture.
    """
    ssz_test(
        type_name="SmokeBitlist8",
        value=SmokeBitlist8(data=[Boolean(False)]),
        raw_bytes="0x0010",
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )
