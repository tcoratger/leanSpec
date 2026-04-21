"""XMSS PRF: deterministic key-schedule known-answer vectors.

Pins the SHAKE128-based PRF outputs for the two roles used by the XMSS
signature scheme: deriving hash-chain starting digests and deriving
signing randomness. Clients must reproduce these outputs bit-for-bit
so the deterministic key schedule agrees across implementations.
"""

import pytest
from consensus_testing import XmssPrfTestFiller

pytestmark = pytest.mark.valid_until("Devnet")


KEY_ZEROS = "0x" + "00" * 32
"""32-byte PRF key of all zeros."""

KEY_INCREMENT = "0x" + "".join(f"{i:02x}" for i in range(32))
"""32-byte PRF key with byte i at position i."""

MESSAGE_ZERO = "0x" + "00" * 32
"""All-zero 32-byte message for randomness derivation."""

MESSAGE_INCREMENT = "0x" + "".join(f"{i:02x}" for i in range(32))
"""Incremental 32-byte message."""


def test_prf_chain_start_zero_key_epoch_zero(
    xmss_prf: XmssPrfTestFiller,
) -> None:
    """Chain-start PRF at the minimal input: zero key, epoch 0, chain index 0.

    Pins the smallest point in the chain-start PRF input space so any
    drift in domain separator bytes or SHAKE128 output shifts every
    downstream hash-chain seed.
    """
    xmss_prf(
        mode="test",
        role="chain_start",
        input={"key": KEY_ZEROS, "epoch": "0", "chainIndex": "0"},
    )


def test_prf_chain_start_distinct_epoch_and_chain(
    xmss_prf: XmssPrfTestFiller,
) -> None:
    """Chain-start PRF with a non-zero incremental key, epoch, and chain index.

    Distinct bytes in every input component check that the PRF packs
    key, epoch, and chain index without silently dropping any field.
    """
    xmss_prf(
        mode="test",
        role="chain_start",
        input={"key": KEY_INCREMENT, "epoch": "7", "chainIndex": "3"},
    )


def test_prf_chain_start_changing_chain_index_changes_output(
    xmss_prf: XmssPrfTestFiller,
) -> None:
    """Same key and epoch, different chain index must produce a different digest.

    Pins independence of sibling hash chains under the PRF so client
    implementations do not accidentally reuse a chain-start seed across
    two different chain indices.
    """
    xmss_prf(
        mode="test",
        role="chain_start",
        input={"key": KEY_ZEROS, "epoch": "0", "chainIndex": "1"},
    )


def test_prf_randomness_zero_inputs(
    xmss_prf: XmssPrfTestFiller,
) -> None:
    """Randomness PRF at zero key, epoch, message, counter.

    Pins the randomness role's smallest input point to guard the
    domain-separator byte (0x01) and the message-length slot.
    """
    xmss_prf(
        mode="test",
        role="randomness",
        input={
            "key": KEY_ZEROS,
            "epoch": "0",
            "message": MESSAGE_ZERO,
            "counter": "0",
        },
    )


def test_prf_randomness_non_zero_counter(
    xmss_prf: XmssPrfTestFiller,
) -> None:
    """Randomness PRF with an incremental key and message, and counter = 1.

    Exercises the retry path in message encoding: a non-zero counter
    must yield a different randomness vector than counter zero under
    otherwise identical inputs.
    """
    xmss_prf(
        mode="test",
        role="randomness",
        input={
            "key": KEY_INCREMENT,
            "epoch": "3",
            "message": MESSAGE_INCREMENT,
            "counter": "1",
        },
    )
