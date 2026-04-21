"""XMSS target-sum encoder: acceptance and digit-sum vectors.

Pins the outcome of the Winternitz target-sum check for a small set of
(parameter, epoch, rho, message) inputs. Clients must agree both on
whether a given input produces an acceptable codeword and on the
digits themselves.
"""

import pytest
from consensus_testing import XmssTargetSumTestFiller

pytestmark = pytest.mark.valid_until("Devnet")


PARAMETER_ZEROS = ["0", "0", "0", "0", "0"]
"""Zero parameter (length PARAMETER_LEN = 5)."""

RHO_ZEROS = ["0"] * 7
"""Zero randomness (length RAND_LEN_FE = 7)."""

RHO_INCREMENT = ["1", "2", "3", "4", "5", "6", "7"]
"""Incremental randomness exercising per-slot placement."""

MESSAGE_ZERO = "0x" + "00" * 32
"""All-zero 32-byte message."""

MESSAGE_INCREMENT = "0x" + "".join(f"{i:02x}" for i in range(32))
"""Message with byte i at position i."""


def test_target_sum_zero_inputs(
    xmss_target_sum: XmssTargetSumTestFiller,
) -> None:
    """Target-sum check at zero parameter, zero rho, zero message, epoch zero.

    Pins the simplest point in the encoder input space, along with the
    digit sum and its comparison to TARGET_SUM, so clients see the exact
    acceptance contract at a known baseline.
    """
    xmss_target_sum(
        mode="test",
        input={
            "parameter": PARAMETER_ZEROS,
            "epoch": "0",
            "rho": RHO_ZEROS,
            "message": MESSAGE_ZERO,
        },
    )


def test_target_sum_incremental_rho_with_zero_message(
    xmss_target_sum: XmssTargetSumTestFiller,
) -> None:
    """Incremental rho under a zero message and epoch.

    Exercises a second point in the encoder space where rho varies
    per-slot but message and parameter stay zero. Pins the response to
    rho alone.
    """
    xmss_target_sum(
        mode="test",
        input={
            "parameter": PARAMETER_ZEROS,
            "epoch": "0",
            "rho": RHO_INCREMENT,
            "message": MESSAGE_ZERO,
        },
    )


def test_target_sum_incremental_message_with_zero_rho(
    xmss_target_sum: XmssTargetSumTestFiller,
) -> None:
    """Incremental-byte message under zero rho and non-zero epoch.

    Pins the per-message acceptance outcome with a distinct-byte message
    so any little-endian packing drift surfaces through the verdict.
    """
    xmss_target_sum(
        mode="test",
        input={
            "parameter": PARAMETER_ZEROS,
            "epoch": "2",
            "rho": RHO_ZEROS,
            "message": MESSAGE_INCREMENT,
        },
    )


def test_target_sum_distinct_parameter_rho_and_message(
    xmss_target_sum: XmssTargetSumTestFiller,
) -> None:
    """All encoder inputs carry distinct per-slot or per-byte content.

    Combines distinct parameter entries, incremental rho, non-zero
    epoch, and incremental message. Pins the acceptance outcome under a
    fully varied input.
    """
    xmss_target_sum(
        mode="test",
        input={
            "parameter": ["1", "2", "3", "4", "5"],
            "epoch": "3",
            "rho": RHO_INCREMENT,
            "message": MESSAGE_INCREMENT,
        },
    )
