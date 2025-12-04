from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Checkpoint,
    SignedAttestation,
)
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss.constants import PROD_CONFIG
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.types import HashDigestList, HashTreeOpening, Randomness
from lean_spec.types import Bytes32, Uint64


def test_encode_decode_signed_attestation_roundtrip() -> None:
    signed_attestation = SignedAttestation(
        message=Attestation(
            validator_id=Uint64(0),
            data=AttestationData(
                slot=0,
                head=Checkpoint(root=Bytes32.zero(), slot=0),
                target=Checkpoint(root=Bytes32.zero(), slot=0),
                source=Checkpoint(root=Bytes32.zero(), slot=0),
            ),
        ),
        signature=Signature(
            path=HashTreeOpening(siblings=HashDigestList(data=[])),
            rho=Randomness(data=[Fp(0) for _ in range(PROD_CONFIG.RAND_LEN_FE)]),
            hashes=HashDigestList(data=[]),
        ),
    )

    # Test that encoding produces the expected hardcoded value
    encode = signed_attestation.encode_bytes()
    expected_value = (
        "000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000008c00000024000000000000000000"
        "000000000000000000000000000000000000000000002800000004000000"
    )
    assert encode.hex() == expected_value, "Encoded value must match hardcoded expected value"

    # Test that decoding round-trips correctly
    decoded = SignedAttestation.decode_bytes(encode)
    assert decoded == signed_attestation
