"""
Tests for the Poseidon2 permutation for widths 16 and 24.
"""

from typing import List

import pytest

from lean_spec.subspecs.koalabear.field import Fp
from lean_spec.subspecs.poseidon2.permutation import (
    PARAMS_16,
    PARAMS_24,
    Poseidon2Params,
    permute,
)

# --- Test Vectors ---

# Input vector for width 16
INPUT_16 = [
    Fp(value=894848333),
    Fp(value=1437655012),
    Fp(value=1200606629),
    Fp(value=1690012884),
    Fp(value=71131202),
    Fp(value=1749206695),
    Fp(value=1717947831),
    Fp(value=120589055),
    Fp(value=19776022),
    Fp(value=42382981),
    Fp(value=1831865506),
    Fp(value=724844064),
    Fp(value=171220207),
    Fp(value=1299207443),
    Fp(value=227047920),
    Fp(value=1783754913),
]
# Expected output for width 16.
EXPECTED_16 = [
    Fp(value=675842289),
    Fp(value=66192714),
    Fp(value=579861851),
    Fp(value=1465025982),
    Fp(value=810227449),
    Fp(value=1161478289),
    Fp(value=1411410716),
    Fp(value=1917188212),
    Fp(value=80707562),
    Fp(value=1051450322),
    Fp(value=1441355554),
    Fp(value=1096596517),
    Fp(value=1967136522),
    Fp(value=1656393635),
    Fp(value=1897269296),
    Fp(value=218235760),
]

# Input vector for width 24
INPUT_24 = [
    Fp(value=886409618),
    Fp(value=1327899896),
    Fp(value=1902407911),
    Fp(value=591953491),
    Fp(value=648428576),
    Fp(value=1844789031),
    Fp(value=1198336108),
    Fp(value=355597330),
    Fp(value=1799586834),
    Fp(value=59617783),
    Fp(value=790334801),
    Fp(value=1968791836),
    Fp(value=559272107),
    Fp(value=31054313),
    Fp(value=1042221543),
    Fp(value=474748436),
    Fp(value=135686258),
    Fp(value=263665994),
    Fp(value=1962340735),
    Fp(value=1741539604),
    Fp(value=2026927696),
    Fp(value=449439011),
    Fp(value=1131357108),
    Fp(value=50869465),
]
# Expected output for width 24.
EXPECTED_24 = [
    Fp(value=545335348),
    Fp(value=483654611),
    Fp(value=76149348),
    Fp(value=1039423716),
    Fp(value=273226798),
    Fp(value=1112250891),
    Fp(value=1803002062),
    Fp(value=283727456),
    Fp(value=1270538134),
    Fp(value=740691354),
    Fp(value=824972956),
    Fp(value=1586235276),
    Fp(value=1576922813),
    Fp(value=300527652),
    Fp(value=1319772393),
    Fp(value=1464054027),
    Fp(value=624250646),
    Fp(value=2110444609),
    Fp(value=213054218),
    Fp(value=830776390),
    Fp(value=257630621),
    Fp(value=1575823798),
    Fp(value=546963080),
    Fp(value=850531490),
]


@pytest.mark.parametrize(
    "params, input_state, expected_output",
    [
        (PARAMS_16, INPUT_16, EXPECTED_16),
        (PARAMS_24, INPUT_24, EXPECTED_24),
    ],
    ids=["width_16", "width_24"],
)
def test_permutation_vector(
    params: Poseidon2Params, input_state: List[Fp], expected_output: List[Fp]
) -> None:
    """
    Tests the Poseidon2 permutation against known answer vectors.

    This serves as a regression test to ensure the logic is consistent.
    """
    # Run the permutation
    output_state = permute(input_state, params)

    # Verify the output
    assert len(output_state) == params.width
    assert output_state == expected_output, (
        f"Permutation output for width {params.width} did not match."
    )
