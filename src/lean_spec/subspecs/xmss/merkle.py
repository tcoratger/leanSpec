"""Sparse Merkle subtrees for top-bottom XMSS traversal.

The XMSS lifetime tree is split into one top tree and many bottom trees.
Each bottom tree covers sqrt(LIFETIME) consecutive slots.
The signer keeps the full top tree plus two adjacent bottom trees resident,
forming a sliding window of 2*sqrt(LIFETIME) signable slots.

This bounds the secret-key memory at O(sqrt(LIFETIME)) instead of O(LIFETIME).
"""

from itertools import batched
from typing import Self

from lean_spec.types import Uint64
from lean_spec.types.container import Container

from .constants import XmssConfig
from .field import random_domain
from .poseidon import PoseidonXmss
from .prf import prf_apply
from .types import (
    HashDigestList,
    HashDigestVector,
    HashTreeLayer,
    HashTreeLayers,
    HashTreeOpening,
    Parameter,
    PRFKey,
    TreeTweak,
)


def _padded_layer(
    config: XmssConfig,
    nodes: list[HashDigestVector],
    start_index: Uint64,
) -> HashTreeLayer:
    """Pad a layer so every node has a sibling and parent generation has no edge cases.

    Invariant: the padded layer starts at an even index and ends at an odd index.
    A single-node layer is allowed when the layer is the root.
    """
    nodes_with_padding: list[HashDigestVector] = []
    end_index = start_index + Uint64(len(nodes)) - Uint64(1)

    # Prepend one random sibling when the layer begins on an odd index.
    if start_index % Uint64(2) == Uint64(1):
        nodes_with_padding.append(random_domain(config))

    # The padded layer always starts on the even index at or before start_index.
    actual_start_index = start_index - (start_index % Uint64(2))

    nodes_with_padding.extend(nodes)

    # Append one random sibling when the layer ends on an even index.
    if end_index % Uint64(2) == Uint64(0):
        nodes_with_padding.append(random_domain(config))

    return HashTreeLayer(
        start_index=actual_start_index,
        nodes=HashDigestList(data=nodes_with_padding),
    )


class HashSubTree(Container):
    """Sparse Merkle subtree of an XMSS lifetime tree.

    Stores layers from lowest_layer up to the subtree root.
    A bottom tree has lowest_layer = 0 and covers a window of leaves.
    A top tree has lowest_layer = LOG_LIFETIME/2 and covers the bottom-tree roots.

    Layout invariant: every active layer starts on an even index and ends on
    an odd index except for the single-node root layer.
    """

    depth: Uint64
    """Depth of the full lifetime tree this subtree belongs to.
    A subtree starting at layer k stores depth - k layers."""

    lowest_layer: Uint64
    """Lowest layer included in this subtree.
    Zero for bottom trees, LOG_LIFETIME/2 for top trees."""

    layers: HashTreeLayers
    """Layers stored from lowest_layer up to the subtree root.
    The last entry holds a single node, the subtree root."""

    @classmethod
    def new(
        cls,
        poseidon: PoseidonXmss,
        config: XmssConfig,
        lowest_layer: Uint64,
        depth: Uint64,
        start_index: Uint64,
        parameter: Parameter,
        lowest_layer_nodes: list[HashDigestVector],
        highest_layer: Uint64 | None = None,
    ) -> Self:
        """Build a subtree from its lowest layer up to a bounding layer.

        Phase 1: pad the input layer to the alignment invariant.
        Phase 2: hash each sibling pair to produce the next layer up.
        Phase 3: pad each new layer and continue to the bounding layer.

        Args:
            poseidon: Cached Poseidon1 engine.
            config: Active XMSS configuration.
            lowest_layer: Starting layer for this subtree.
            depth: Total depth of the full lifetime tree.
            start_index: Absolute index of the first input node.
            parameter: Public parameter for the hash function.
            lowest_layer_nodes: Active nodes at the lowest layer.
            highest_layer: Layer to stop building at, defaulting to the full depth.

        Returns:
            A subtree containing every layer from lowest_layer up to highest_layer.
        """
        # Build to the global root unless a lower bounding layer is requested.
        highest_layer = depth if highest_layer is None else highest_layer

        # The input nodes must fit in the layer they belong to.
        max_positions = 1 << int(depth - lowest_layer)
        if int(start_index) + len(lowest_layer_nodes) > max_positions:
            raise ValueError(
                f"Overflow at layer {lowest_layer}: "
                f"start={start_index}, count={len(lowest_layer_nodes)}, max={max_positions}"
            )

        # Phase 1: pad the input layer.
        layers: list[HashTreeLayer] = []
        current = _padded_layer(config, lowest_layer_nodes, start_index)
        layers.append(current)

        # Phases 2 + 3: hash sibling pairs, pad, repeat.
        for level in range(lowest_layer, highest_layer):
            parent_start = current.start_index // Uint64(2)
            parents = [
                poseidon.tweak_hash(
                    config,
                    parameter,
                    TreeTweak(level=level + 1, index=parent_start + Uint64(i)),
                    [left, right],
                )
                for i, (left, right) in enumerate(batched(current.nodes, 2))
            ]
            current = _padded_layer(config, parents, parent_start)
            layers.append(current)

        return cls(
            depth=depth,
            lowest_layer=lowest_layer,
            layers=HashTreeLayers(data=layers),
        )

    @classmethod
    def new_top_tree(
        cls,
        poseidon: PoseidonXmss,
        config: XmssConfig,
        depth: int,
        start_bottom_tree_index: Uint64,
        parameter: Parameter,
        bottom_tree_roots: list[HashDigestVector],
    ) -> Self:
        """Build the top tree from bottom-tree roots up to the global root.

        The top tree starts at layer depth/2 and treats bottom-tree roots as its leaves.

        Args:
            poseidon: Cached Poseidon1 engine.
            config: Active XMSS configuration.
            depth: Total depth of the full lifetime tree.
            start_bottom_tree_index: Index of the first bottom tree in the range.
            parameter: Public parameter for the hash function.
            bottom_tree_roots: Roots of all bottom trees in the range, in order.

        Returns:
            A top tree whose root is the global Merkle root.

        Raises:
            ValueError: When depth is odd.
        """
        # Top-bottom split requires an even depth.
        if depth % 2 != 0:
            raise ValueError(f"Depth must be even for top-bottom split, got {depth}.")

        return cls.new(
            poseidon=poseidon,
            config=config,
            lowest_layer=Uint64(depth // 2),
            depth=Uint64(depth),
            start_index=start_bottom_tree_index,
            parameter=parameter,
            lowest_layer_nodes=bottom_tree_roots,
        )

    @classmethod
    def new_bottom_tree(
        cls,
        poseidon: PoseidonXmss,
        config: XmssConfig,
        depth: int,
        bottom_tree_index: Uint64,
        parameter: Parameter,
        leaves: list[HashDigestVector],
    ) -> Self:
        """Build one bottom tree from leaf hashes up to its standalone root.

        Phase 1: build the layers from 0 up to the bottom-tree root layer.
        Phase 2: replace that padded top layer with its single-node root.

        Args:
            poseidon: Cached Poseidon1 engine.
            config: Active XMSS configuration.
            depth: Total depth of the full lifetime tree.
            bottom_tree_index: Index of this bottom tree.
            parameter: Public parameter for the hash function.
            leaves: Pre-hashed one-time public keys for this bottom tree's slots.

        Returns:
            A subtree with layers 0 through depth/2 ending in the bottom-tree root.

        Raises:
            ValueError: When depth is odd or the leaf count does not match sqrt(LIFETIME).
        """
        if depth % 2 != 0:
            raise ValueError(f"Depth must be even for top-bottom split, got {depth}.")

        # Each bottom tree spans exactly sqrt(LIFETIME) leaves.
        leaves_per_tree = 1 << (depth // 2)
        if len(leaves) != leaves_per_tree:
            raise ValueError(
                f"Expected {leaves_per_tree} leaves for depth={depth}, got {len(leaves)}."
            )

        # Phase 1: build only layers 0 through depth/2, the bottom tree's own height.
        subtree = cls.new(
            poseidon=poseidon,
            config=config,
            lowest_layer=Uint64(0),
            depth=Uint64(depth),
            start_index=bottom_tree_index * Uint64(leaves_per_tree),
            parameter=parameter,
            lowest_layer_nodes=leaves,
            highest_layer=Uint64(depth // 2),
        )

        # Phase 2: the top built layer is padded to a sibling pair.
        # The real root is the node at this tree's index, not always position zero.
        # An odd index leaves a random pad at position zero, so select by absolute index.
        top = subtree.layers[-1]
        root_idx = int(bottom_tree_index - top.start_index)
        root_layer = HashTreeLayer(
            start_index=bottom_tree_index,
            nodes=HashDigestList(data=[top.nodes[root_idx]]),
        )
        return cls(
            depth=Uint64(depth),
            lowest_layer=Uint64(0),
            layers=HashTreeLayers(data=list(subtree.layers[:-1]) + [root_layer]),
        )

    @classmethod
    def from_prf_key(
        cls,
        poseidon: PoseidonXmss,
        config: XmssConfig,
        prf_key: PRFKey,
        bottom_tree_index: Uint64,
        parameter: Parameter,
    ) -> Self:
        """Regenerate one bottom tree on demand from the master PRF key.

        Phase 1: for every epoch in the bottom tree, derive chain starts via PRF.
        Phase 2: hash each chain for BASE - 1 steps to obtain the chain endpoints.
        Phase 3: hash chain endpoints into a leaf, then build the bottom tree.

        Args:
            poseidon: Cached Poseidon1 engine.
            config: Active XMSS configuration.
            prf_key: Master secret seed.
            bottom_tree_index: Index of the bottom tree to regenerate.
            parameter: Public parameter for the hash function.

        Returns:
            The requested bottom tree.
        """
        # Each bottom tree covers sqrt(LIFETIME) consecutive epochs.
        leaves_per_bottom_tree = config.LEAVES_PER_BOTTOM_TREE
        start_epoch = bottom_tree_index * Uint64(leaves_per_bottom_tree)
        end_epoch = start_epoch + Uint64(leaves_per_bottom_tree)

        leaf_hashes: list[HashDigestVector] = []
        for epoch in range(start_epoch, end_epoch):
            # Phases 1 + 2: derive each chain start, then walk it to the public endpoint.
            chain_ends: list[HashDigestVector] = []
            for chain_index in range(config.DIMENSION):
                start_digest = prf_apply(config, prf_key, Uint64(epoch), Uint64(chain_index))
                end_digest = poseidon.hash_chain(
                    config=config,
                    parameter=parameter,
                    epoch=Uint64(epoch),
                    chain_index=chain_index,
                    start_step=0,
                    num_steps=config.BASE - 1,
                    start_digest=start_digest,
                )
                chain_ends.append(end_digest)

            # Phase 3: hash all chain endpoints into the leaf for this epoch.
            leaf_tweak = TreeTweak(level=0, index=Uint64(epoch))
            leaf_hash = poseidon.tweak_hash(config, parameter, leaf_tweak, chain_ends)
            leaf_hashes.append(leaf_hash)

        return cls.new_bottom_tree(
            poseidon=poseidon,
            config=config,
            depth=config.LOG_LIFETIME,
            bottom_tree_index=bottom_tree_index,
            parameter=parameter,
            leaves=leaf_hashes,
        )

    def root(self) -> HashDigestVector:
        """Return the single node in the highest stored layer.

        Raises:
            ValueError: When the subtree is empty or the highest layer has no nodes.
        """
        if not self.layers:
            raise ValueError("Empty subtree has no root.")
        if not self.layers[-1].nodes:
            raise ValueError("Top layer is empty.")
        return self.layers[-1].nodes[0]

    def path(self, position: Uint64) -> HashTreeOpening:
        """Build the authentication path from a leaf up to the subtree root.

        For a subtree covering layers L through H, the opening contains H - L siblings,
        one per layer between L and H - 1.

        Args:
            position: Absolute index of the leaf in the full tree coordinate system.

        Returns:
            An opening of sibling hashes from bottom to top.

        Raises:
            ValueError: When the subtree is empty or the position is out of bounds.
        """
        if not self.layers:
            raise ValueError("Empty subtree.")

        first = self.layers[0]
        if not (first.start_index <= position < first.start_index + Uint64(len(first.nodes))):
            raise ValueError(f"Position {position} out of bounds.")

        siblings: list[HashDigestVector] = []
        pos = int(position)

        # Stop one short of the root layer.
        # The root has no sibling.
        for layer in self.layers[:-1]:
            # The sibling sits at the position with the last bit flipped, then we
            # rebase by the layer's start_index because the layer is sparse.
            sibling_idx = (pos ^ 1) - int(layer.start_index)
            if not (0 <= sibling_idx < len(layer.nodes)):
                raise ValueError(f"Sibling index {sibling_idx} out of bounds.")
            siblings.append(layer.nodes[sibling_idx])
            pos //= 2

        return HashTreeOpening(siblings=HashDigestList(data=siblings))


def combined_path(
    top_tree: HashSubTree,
    bottom_tree: HashSubTree,
    position: Uint64,
) -> HashTreeOpening:
    """Concatenate the bottom-tree and top-tree openings for one leaf.

    A signature must authenticate the leaf against the global root.
    The bottom opening proves leaf membership in its bottom tree.
    The top opening proves the bottom-tree root sits under the global root.

    Args:
        top_tree: The top tree containing the global root.
        bottom_tree: The bottom tree containing the leaf.
        position: Absolute index of the leaf.

    Returns:
        An opening with depth siblings authenticating the leaf against the global root.

    Raises:
        ValueError: When tree depths mismatch, depth is odd, or position is out
            of bounds for the supplied bottom tree.
    """
    if top_tree.depth != bottom_tree.depth:
        raise ValueError(f"Depth mismatch: top={top_tree.depth}, bottom={bottom_tree.depth}.")

    depth = int(top_tree.depth)
    if depth % 2 != 0:
        raise ValueError(f"Depth must be even, got {depth}.")

    # The position must belong to the supplied bottom tree, not a sibling one.
    leaves_per_tree = Uint64(1 << (depth // 2))
    expected_start = (position // leaves_per_tree) * leaves_per_tree
    if bottom_tree.layers[0].start_index != expected_start:
        raise ValueError(
            f"Wrong bottom tree: position {position} needs start {expected_start}, "
            f"got {bottom_tree.layers[0].start_index}."
        )

    # Bottom path proves leaf -> bottom-tree root.
    # Top path proves bottom root -> global root.
    bottom_path = bottom_tree.path(position)
    top_path = top_tree.path(position // leaves_per_tree)
    combined = tuple(bottom_path.siblings.data) + tuple(top_path.siblings.data)

    return HashTreeOpening(siblings=HashDigestList(data=combined))


def verify_path(
    poseidon: PoseidonXmss,
    config: XmssConfig,
    parameter: Parameter,
    root: HashDigestVector,
    position: Uint64,
    leaf_parts: list[HashDigestVector],
    opening: HashTreeOpening,
) -> bool:
    """Verify a Merkle opening against a trusted root.

    Phase 1: hash leaf_parts into the leaf digest.
    Phase 2: walk the opening, hashing the current node with each sibling.
    Phase 3: compare the reconstructed root with the trusted one.

    Returns False on attacker-controlled invalid input instead of raising.

    Args:
        poseidon: Cached Poseidon1 engine.
        config: Active XMSS configuration.
        parameter: Public parameter for the hash function.
        root: Trusted root taken from the public key.
        position: Absolute index of the leaf being verified.
        leaf_parts: Digests that constitute the original leaf.
        opening: Sibling path from leaf to root.

    Returns:
        True when the path reconstructs the root, False otherwise.
    """
    # Guard against malformed openings.
    # The opening list caps at 32 entries.
    # A depth greater than 32 would overflow the position bound check below.
    depth = len(opening.siblings)
    if depth > 32:
        return False
    if int(position) >= (1 << depth):
        return False

    # Phase 1: hash the leaf parts to derive the starting node.
    current = poseidon.tweak_hash(
        config,
        parameter,
        TreeTweak(level=0, index=Uint64(position)),
        leaf_parts,
    )
    pos = int(position)

    # Phase 2: hash with each sibling, climbing one layer per iteration.
    for level, sibling in enumerate(opening.siblings):
        # The current node sits on the left when its position is even.
        left, right = (current, sibling) if pos % 2 == 0 else (sibling, current)
        pos //= 2
        current = poseidon.tweak_hash(
            config,
            parameter,
            TreeTweak(level=level + 1, index=Uint64(pos)),
            [left, right],
        )

    # Phase 3: compare against the trusted root.
    return current == root
