"""XMSS message hash: aborting hypercube encoding known-answer vectors.

Pins the codeword that XMSS derives from a 32-byte message under a
given parameter, epoch, and randomness. Clients must reproduce
identical digit sequences or the same abort decision.
"""

import pytest
from consensus_testing import MessageHashTestFiller

pytestmark = pytest.mark.valid_until("Devnet")


PARAMETER_ZEROS = ["0", "0", "0", "0", "0"]
"""Zero parameter (length PARAMETER_LEN = 5)."""

RHO_ZEROS = ["0"] * 7
"""Zero randomness (length RAND_LEN_FE = 7 in both test and prod configs)."""

RHO_INCREMENT = ["1", "2", "3", "4", "5", "6", "7"]
"""Incremental randomness exercising per-slot placement."""

MESSAGE_ZERO = "0x" + "00" * 32
"""All-zero 32-byte message."""

MESSAGE_INCREMENT = "0x" + "".join(f"{i:02x}" for i in range(32))
"""Message with byte i at position i."""

MESSAGE_HIGH = "0x" + "ff" * 32
"""All-ones 32-byte message."""


def test_message_hash_zero_message_zero_parameter_zero_rho(
    message_hash: MessageHashTestFiller,
) -> None:
    """Minimal input: zero parameter, zero randomness, zero message, epoch zero.

    Pins the simplest point in the encoding's input space. Any drift in
    field-element packing, epoch encoding, or Poseidon dispatch shifts
    the output codeword.
    """
    message_hash(
        mode="test",
        input={
            "parameter": PARAMETER_ZEROS,
            "epoch": "0",
            "rho": RHO_ZEROS,
            "message": MESSAGE_ZERO,
        },
    )


def test_message_hash_incremental_message_with_zero_context(
    message_hash: MessageHashTestFiller,
) -> None:
    """32-byte message with byte i at position i, under zero context.

    A message with distinct bytes per position exposes any off-by-one in
    the little-endian packing used to encode the message into field
    elements.
    """
    message_hash(
        mode="test",
        input={
            "parameter": PARAMETER_ZEROS,
            "epoch": "0",
            "rho": RHO_ZEROS,
            "message": MESSAGE_INCREMENT,
        },
    )


def test_message_hash_high_message_incremental_rho(
    message_hash: MessageHashTestFiller,
) -> None:
    """All-ones message, incremental randomness, non-zero epoch.

    Stresses the widest representable message integer against a varied
    randomness vector. Pins the interaction between message decomposition
    and randomness packing in the Poseidon call.
    """
    message_hash(
        mode="test",
        input={
            "parameter": PARAMETER_ZEROS,
            "epoch": "42",
            "rho": RHO_INCREMENT,
            "message": MESSAGE_HIGH,
        },
    )


def test_message_hash_incremental_parameter_and_rho(
    message_hash: MessageHashTestFiller,
) -> None:
    """Distinct parameter entries combined with distinct randomness entries.

    Every slot of parameter and rho differs from its neighbours. Pins
    that no slot is silently ignored or duplicated during the Poseidon
    input assembly.
    """
    message_hash(
        mode="test",
        input={
            "parameter": ["1", "2", "3", "4", "5"],
            "epoch": "1",
            "rho": RHO_INCREMENT,
            "message": MESSAGE_ZERO,
        },
    )
