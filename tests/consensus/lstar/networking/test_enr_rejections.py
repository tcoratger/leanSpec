"""ENR RLP decoder: malformed-input rejection vectors."""

import pytest

from consensus_testing import ExpectedRejection, NetworkingCodecTestFiller
from lean_spec.spec.forks import RejectionReason

pytestmark = pytest.mark.valid_until("Lstar")


def test_enr_decode_rejects_oversize_payload(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    An ENR RLP payload above the 300-byte cap is rejected.

    EIP-778 caps the encoded ENR at 300 bytes so records can travel
    comfortably through DNS TXT records. A 301-byte input must be
    rejected before any RLP parsing runs.
    """
    oversize = "0x" + "ff" * 301
    networking_codec_test(
        codec_name="decode_failure",
        input={"decoder": "enr", "bytes": oversize},
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_enr_decode_rejects_malformed_rlp(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    An input that cannot be parsed as an RLP list is rejected.

    The byte 0x00 is valid RLP for the single byte value 0x00, not for a
    list structure. The ENR decoder requires a list header, so the parse
    fails and the error surfaces as a ValueError on the ENR API.
    """
    networking_codec_test(
        codec_name="decode_failure",
        input={"decoder": "enr", "bytes": "0x00"},
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )
