"""Tests for the sparse Merkle tree implementation."""

import pytest

from lean_spec.subspecs.xmss.constants import PROD_CONFIG, XmssConfig
from lean_spec.subspecs.xmss.field import random_domain, random_parameter
from lean_spec.subspecs.xmss.merkle import HashSubTree, verify_path
from lean_spec.subspecs.xmss.poseidon import PROD_POSEIDON, PoseidonXmss
from lean_spec.subspecs.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    TreeTweak,
)
from lean_spec.types import Uint64
from lean_spec.types.exceptions import SSZValueError


def _run_commit_open_verify_roundtrip(
    poseidon: PoseidonXmss,
    config: XmssConfig,
    num_leaves: int,
    depth: int,
    start_index: int,
    leaf_parts_len: int,
) -> None:
    """
    A helper function to perform a full Merkle tree roundtrip test.

    The process is as follows:
    1.  Generate random leaf data.
    2.  Hash the leaves to create layer 0 of the tree.
    3.  Build the full Merkle tree and get its root (commit).
    4.  For each leaf, generate an authentication path (open).
    5.  Verify that each path is valid for its corresponding leaf and root.

    Args:
        poseidon: Cached Poseidon1 engine.
        config: Active XMSS configuration.
        num_leaves: The number of active leaves in the tree.
        depth: The total depth of the Merkle tree.
        start_index: The starting index of the first active leaf.
        leaf_parts_len: The number of digests that constitute a single leaf.
    """
    # SETUP: Generate a random parameter and the raw leaf data.
    parameter = random_parameter(config)
    leaves: list[list[HashDigestVector]] = [
        [random_domain(config) for _ in range(leaf_parts_len)] for _ in range(num_leaves)
    ]

    # HASH LEAVES: Compute the layer 0 nodes by hashing the leaf parts.
    leaf_hashes: list[HashDigestVector] = [
        poseidon.tweak_hash(
            config,
            parameter,
            TreeTweak(level=0, index=Uint64(start_index + i)),
            leaf_parts,
        )
        for i, leaf_parts in enumerate(leaves)
    ]

    # COMMIT: Build the Merkle tree from the leaf hashes.
    tree = HashSubTree.new(
        poseidon=poseidon,
        config=config,
        lowest_layer=Uint64(0),
        depth=Uint64(depth),
        start_index=Uint64(start_index),
        parameter=parameter,
        lowest_layer_nodes=leaf_hashes,
    )
    root = tree.root()

    # OPEN & VERIFY: For each leaf, generate and verify its path.
    for i, leaf_parts in enumerate(leaves):
        position = Uint64(start_index + i)
        opening = tree.path(position)
        is_valid = verify_path(
            poseidon=poseidon,
            config=config,
            parameter=parameter,
            root=root,
            position=position,
            leaf_parts=leaf_parts,
            opening=opening,
        )
        assert is_valid, f"Verification failed for leaf at position {position}"


@pytest.mark.parametrize(
    "num_leaves, depth, start_index, leaf_parts_len",
    [
        pytest.param(16, 4, 0, 3, id="Full tree (depth 4)", marks=pytest.mark.slow),
        pytest.param(12, 5, 0, 5, id="Half tree, left-aligned (depth 5)", marks=pytest.mark.slow),
        pytest.param(16, 5, 16, 2, id="Half tree, right-aligned (depth 5)"),
        pytest.param(22, 6, 13, 3, id="Sparse, non-aligned tree (depth 6)", marks=pytest.mark.slow),
        pytest.param(2, 2, 2, 6, id="Half tree, right-aligned (small)"),
        pytest.param(1, 1, 0, 1, id="Tree with a single leaf at the start"),
        pytest.param(1, 1, 1, 1, id="Tree with a single leaf at an odd index"),
        pytest.param(16, 5, 7, 2, id="Small sparse tree starting at an odd index"),
    ],
)
def test_commit_open_verify_roundtrip(
    num_leaves: int,
    depth: int,
    start_index: int,
    leaf_parts_len: int,
) -> None:
    """Tests the Merkle tree logic for various configurations."""
    # Ensure the test case parameters are valid for the specified tree depth.
    assert start_index + num_leaves <= (1 << depth)

    _run_commit_open_verify_roundtrip(
        PROD_POSEIDON, PROD_CONFIG, num_leaves, depth, start_index, leaf_parts_len
    )


class TestVerifyPathSecurityBounds:
    """
    Security tests for verify_path input validation.

    Verification functions must return False (not raise) on attacker-controlled invalid input.
    This prevents denial-of-service via malformed signatures.
    """

    def test_ssz_validation_rejects_excessive_depth(self) -> None:
        """
        SSZ type system rejects openings with depth > 32.

        HashDigestList has a LIMIT of 32, so the type system prevents
        creating malformed openings at the SSZ level. The check in
        verify_path is defense-in-depth for deserialized data.
        """
        # Attempting to create a list with 33 siblings raises at the type level.
        excessive_siblings = [random_domain(PROD_CONFIG) for _ in range(33)]
        with pytest.raises(SSZValueError):
            HashDigestList(data=excessive_siblings)

    def test_rejects_position_exceeding_tree_capacity(self) -> None:
        """verify_path returns False when position >= 2^depth."""
        parameter = random_parameter(PROD_CONFIG)

        root = random_domain(PROD_CONFIG)
        leaf_parts = [random_domain(PROD_CONFIG)]

        # Create an opening with depth=4 (supports positions 0-15).
        siblings = [random_domain(PROD_CONFIG) for _ in range(4)]
        opening = HashTreeOpening(siblings=HashDigestList(data=siblings))

        # Position 16 is out of bounds for depth 4 (capacity = 2^4 = 16).
        result = verify_path(
            poseidon=PROD_POSEIDON,
            config=PROD_CONFIG,
            parameter=parameter,
            root=root,
            position=Uint64(16),
            leaf_parts=leaf_parts,
            opening=opening,
        )
        assert result is False

        # Position 100 is also out of bounds.
        result = verify_path(
            poseidon=PROD_POSEIDON,
            config=PROD_CONFIG,
            parameter=parameter,
            root=root,
            position=Uint64(100),
            leaf_parts=leaf_parts,
            opening=opening,
        )
        assert result is False

    def test_valid_position_at_boundary(self) -> None:
        """verify_path accepts position at maximum valid value (2^depth - 1)."""
        parameter = random_parameter(PROD_CONFIG)

        root = random_domain(PROD_CONFIG)
        leaf_parts = [random_domain(PROD_CONFIG)]

        # Create an opening with depth=4.
        siblings = [random_domain(PROD_CONFIG) for _ in range(4)]
        opening = HashTreeOpening(siblings=HashDigestList(data=siblings))

        # Position 15 is the maximum valid position for depth 4.
        # This should not return False due to bounds check (may still fail root check).
        result = verify_path(
            poseidon=PROD_POSEIDON,
            config=PROD_CONFIG,
            parameter=parameter,
            root=root,
            position=Uint64(15),
            leaf_parts=leaf_parts,
            opening=opening,
        )
        # Result may be False due to wrong root, but importantly it didn't raise.
        assert isinstance(result, bool)
