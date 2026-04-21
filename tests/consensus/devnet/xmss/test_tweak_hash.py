"""XMSS tweakable hash: known-answer vectors.

Pins the output digest of the XMSS tweakable hash for a small set of
structurally distinct tweak contexts. Clients must reproduce these
digests bit-for-bit so that every XMSS chain step, Merkle tree node,
and Merkle leaf agrees across implementations.
"""

import pytest
from consensus_testing import TweakHashTestFiller

pytestmark = pytest.mark.valid_until("Devnet")


PARAMETER_ZEROS = ["0", "0", "0", "0", "0"]
"""Parameter vector of all zeros. Minimal public parameter for KAT inputs."""

PARAMETER_INCREMENT = ["1", "2", "3", "4", "5"]
"""Distinct-per-slot parameter that exposes off-by-one in parameter packing."""

DIGEST_ZEROS = ["0"] * 8
"""Single HashDigest of all zeros (length HASH_LEN_FE = 8)."""

DIGEST_INCREMENT = ["1", "2", "3", "4", "5", "6", "7", "8"]
"""Single HashDigest with distinct per-slot entries."""


def test_tweak_hash_chain_epoch_zero_step_one(
    tweak_hash: TweakHashTestFiller,
) -> None:
    """Chain tweak at the first step of the first epoch.

    Pins the smallest ChainTweak context and a single zero-digest message.
    Any drift in the tweak encoding or the width-16 compression path
    shifts the output.
    """
    tweak_hash(
        mode="test",
        tweak_type="chain",
        tweak={"epoch": "0", "chainIndex": 0, "step": 1},
        input={"parameter": PARAMETER_ZEROS, "messageParts": [DIGEST_ZEROS]},
    )


def test_tweak_hash_chain_epoch_max_step_base_minus_one(
    tweak_hash: TweakHashTestFiller,
) -> None:
    """Chain tweak at epoch and step at their widest test-config values.

    Combined with an incremental parameter and an incremental digest, the
    vector stresses the packing and compression at the high end of the
    ChainTweak integer range.
    """
    tweak_hash(
        mode="test",
        tweak_type="chain",
        tweak={"epoch": str(2**32 - 1), "chainIndex": 255, "step": 7},
        input={"parameter": PARAMETER_INCREMENT, "messageParts": [DIGEST_INCREMENT]},
    )


def test_tweak_hash_tree_level_zero_index_zero(
    tweak_hash: TweakHashTestFiller,
) -> None:
    """Tree tweak at the leaf layer, index zero, with two zero-digest children.

    Uses the width-24 compression path of TweakHasher.apply, distinct from
    the width-16 path exercised by the chain tweaks above.
    """
    tweak_hash(
        mode="test",
        tweak_type="tree",
        tweak={"level": 0, "index": "0"},
        input={
            "parameter": PARAMETER_ZEROS,
            "messageParts": [DIGEST_ZEROS, DIGEST_ZEROS],
        },
    )


def test_tweak_hash_tree_level_top_index_one(
    tweak_hash: TweakHashTestFiller,
) -> None:
    """Tree tweak at a high Merkle layer, non-zero index, distinct child digests.

    Pins the Merkle-node hashing path for a node whose two child digests
    differ and whose index is non-zero, testing both position fields of
    the TreeTweak encoding.
    """
    tweak_hash(
        mode="test",
        tweak_type="tree",
        tweak={"level": 8, "index": "1"},
        input={
            "parameter": PARAMETER_INCREMENT,
            "messageParts": [DIGEST_ZEROS, DIGEST_INCREMENT],
        },
    )


def test_tweak_hash_tree_same_input_different_tweak_gives_different_digest(
    tweak_hash: TweakHashTestFiller,
) -> None:
    """Same parameter and message parts under a distinct tree tweak must produce a different digest.

    Pins the domain separation property of the tweakable hash: moving
    only the level field of the TreeTweak must yield a different digest.
    """
    tweak_hash(
        mode="test",
        tweak_type="tree",
        tweak={"level": 5, "index": "0"},
        input={
            "parameter": PARAMETER_ZEROS,
            "messageParts": [DIGEST_ZEROS, DIGEST_ZEROS],
        },
    )
