"""XMSS WOTS+ hash chain: known-answer vectors.

Pins the digest produced by iterating the tweakable hash from a given
starting digest across a sequence of chain steps. Clients must
reproduce the same intermediate and end-of-chain digests so chain
traversal agrees across implementations.
"""

import pytest
from consensus_testing import XmssChainTestFiller

pytestmark = pytest.mark.valid_until("Devnet")


PARAMETER_ZEROS = ["0", "0", "0", "0", "0"]
"""Zero parameter (length PARAMETER_LEN = 5)."""

DIGEST_ZEROS = ["0"] * 8
"""Zero starting digest (length HASH_LEN_FE = 8)."""

DIGEST_INCREMENT = ["1", "2", "3", "4", "5", "6", "7", "8"]
"""Incremental starting digest exposing per-slot chain arithmetic."""


def test_chain_zero_steps_is_identity(
    xmss_chain: XmssChainTestFiller,
) -> None:
    """Zero steps must return the start digest unchanged.

    The hash_chain helper loops num_steps times and returns the current
    digest. With num_steps = 0 the loop body never runs, so the output
    must equal the input. Pins the identity boundary of the iteration.
    """
    xmss_chain(
        mode="test",
        input={
            "parameter": PARAMETER_ZEROS,
            "epoch": "0",
            "chainIndex": 0,
            "startStep": 0,
            "numSteps": 0,
            "startDigest": DIGEST_ZEROS,
        },
    )


def test_chain_single_step_from_zero(
    xmss_chain: XmssChainTestFiller,
) -> None:
    """One chain step from the zero digest at epoch 0, chain 0, start step 0.

    Corresponds to applying the tweakable hash once with ChainTweak
    (epoch=0, chain_index=0, step=1). Pins the first step of the simplest
    chain.
    """
    xmss_chain(
        mode="test",
        input={
            "parameter": PARAMETER_ZEROS,
            "epoch": "0",
            "chainIndex": 0,
            "startStep": 0,
            "numSteps": 1,
            "startDigest": DIGEST_ZEROS,
        },
    )


def test_chain_full_traversal_test_base_minus_one(
    xmss_chain: XmssChainTestFiller,
) -> None:
    """Traverse BASE - 1 steps at test-mode base (7) from the incremental digest.

    A full chain covers every non-zero digit in base-BASE. For test mode
    (BASE = 8) that is seven steps. The resulting digest pins the
    end-of-chain value clients must agree on.
    """
    xmss_chain(
        mode="test",
        input={
            "parameter": PARAMETER_ZEROS,
            "epoch": "0",
            "chainIndex": 0,
            "startStep": 0,
            "numSteps": 7,
            "startDigest": DIGEST_INCREMENT,
        },
    )


def test_chain_mid_range_step_and_index(
    xmss_chain: XmssChainTestFiller,
) -> None:
    """Start at mid-chain with a non-zero chain index and a small positive epoch.

    Pins the interaction between start_step and chain_index in the
    ChainTweak. A mistake in the step offset or chain-index packing
    shifts the resulting digest.
    """
    xmss_chain(
        mode="test",
        input={
            "parameter": PARAMETER_ZEROS,
            "epoch": "3",
            "chainIndex": 2,
            "startStep": 2,
            "numSteps": 3,
            "startDigest": DIGEST_INCREMENT,
        },
    )
