"""
Implements the sparse Merkle tree used in the Generalized XMSS scheme.

### Usage of Merkle Trees in XMSS scheme: Aggregating Keys

A Merkle tree is a cryptographic data structure that allows for the efficient
aggregation and verification of large sets of data. In XMSS, its role is to
aggregate **one-time public keys** (the leaves of the tree) into a single,
compact **master public key** (the root of the tree).

A verifier who knows only the root can be given a small proof (an "authentication
path") to efficiently verify that a specific one-time public key is a legitimate
part of the overall scheme.

### Key Optimizations for XMSS

This implementation includes two important features tailored for this use case:

1.  **Sparsity**: A key pair might have a massive theoretical lifetime (e.g., 2^32 epochs),
    but in practice, a signer only needs to generate and store the keys for a
    much smaller, active range (e.g., 2^20 epochs). This implementation builds a
    "sparse" tree, only computing and storing the nodes and branches relevant to
    this active range of leaves, leading to enormous savings in computation and memory.

2.  **Random Padding**: To simplify the algorithm that builds the tree, each active
    layer is padded with random hash values. This ensures that every node can
    always be paired with a sibling, eliminating complex edge-case logic for
    "orphan" nodes at the boundaries of the sparse region.
"""

from __future__ import annotations

from typing import List

from lean_spec.types import Uint64

from .constants import (
    PROD_CONFIG,
    TEST_CONFIG,
    XmssConfig,
)
from .containers import (
    HashDigest,
    HashSubTree,
    HashTree,
    HashTreeLayer,
    HashTreeOpening,
    Parameter,
)
from .tweak_hash import (
    PROD_TWEAK_HASHER,
    TEST_TWEAK_HASHER,
    TreeTweak,
    TweakHasher,
)
from .utils import PROD_RAND, TEST_RAND, Rand


class MerkleTree:
    """An instance of the Merkle Tree handler for a given config."""

    def __init__(self, config: XmssConfig, hasher: TweakHasher, rand: Rand):
        """Initializes with a config, a hasher, and a random generator."""
        self.config = config
        self.hasher = hasher
        self.rand = rand

    def _get_padded_layer(self, nodes: List[HashDigest], start_index: int) -> HashTreeLayer:
        """
        Pads a layer of nodes with random hashes to simplify tree construction.

        This helper enforces a crucial invariant: every active layer must start at an
        even index and end at an odd index. This guarantees that every node within
        the layer can be neatly paired with a sibling (a left child with a right
        child), which dramatically simplifies the parent generation logic by
        removing the need to handle edge cases.

        Args:
            nodes: The list of active nodes for the current layer.
            start_index: The starting index of the first node in `nodes`.

        Returns:
            A new `HashTreeLayer` with the necessary padding applied.
        """
        nodes_with_padding: List[HashDigest] = []
        end_index = start_index + len(nodes) - 1

        # Prepend random padding if the layer starts at an odd index.
        if start_index % 2 == 1:
            nodes_with_padding.append(self.rand.domain())

        # The actual start index of the padded layer is always the even
        # number at or immediately before the original start_index.
        actual_start_index = start_index - (start_index % 2)

        # Add the actual node content.
        nodes_with_padding.extend(nodes)

        # Append random padding if the layer ends at an even index.
        if end_index % 2 == 0:
            nodes_with_padding.append(self.rand.domain())

        return HashTreeLayer(start_index=actual_start_index, nodes=nodes_with_padding)

    def build(
        self,
        depth: int,
        start_index: Uint64,
        parameter: Parameter,
        leaf_hashes: List[HashDigest],
    ) -> HashTree:
        """
        Builds a new sparse Merkle tree from a contiguous range of leaf hashes.

        ### Construction Algorithm

        1.  **Initialization**: The process starts with the provided `leaf_hashes`
            at the bottom of the tree (level 0). This layer is padded.

        2.  **Bottom-Up Iteration**: The tree is built level by level, from the
            leaves towards the root.

        3.  **Parent Generation**: In each level, the current layer's nodes are
            grouped into pairs (left child, right child). Each pair is then
            hashed together (using a level- and index-specific tweak) to create
            a parent node in the level above.

        4.  **Padding**: The new list of parent nodes is padded to prepare for the
            next iteration, ensuring the sibling-pairing logic remains simple.

        5.  **Termination**: This process repeats until a layer with a single
            node is produced. This final node is the tree's root.

        Args:
            depth: The total depth of the tree (e.g., 32 for a 2^32 leaf space).
            start_index: The absolute index of the first leaf in `leaf_hashes`.
            parameter: The public parameter `P` for the hash function.
            leaf_hashes: The list of pre-hashed leaf nodes.

        Returns:
            The fully constructed `HashTree` object containing all computed layers.
        """
        # Check there is enough space for the leafs in the tree.
        if int(start_index) + len(leaf_hashes) > 2**depth:
            raise ValueError("Not enough space for leafs in the tree.")

        # Start with the leaf hashes and apply the initial padding.
        layers: List[HashTreeLayer] = []
        current_layer = self._get_padded_layer(leaf_hashes, int(start_index))
        layers.append(current_layer)

        # Iterate from the leaf layer (level 0) up to the root.
        for level in range(depth):
            parents: List[HashDigest] = []
            # Group the current layer's nodes into pairs of (left, right) siblings.
            #
            # The padding guarantees this works perfectly without leaving orphan nodes.
            for i, children in enumerate(
                zip(
                    current_layer.nodes[0::2],
                    current_layer.nodes[1::2],
                    strict=False,
                )
            ):
                # Calculate the position of the parent node in the next level up.
                parent_index = (current_layer.start_index // 2) + i
                # Create the tweak for hashing these two children.
                tweak = TreeTweak(level=level + 1, index=parent_index)
                # Hash the left and right children to get their parent.
                parent_node = self.hasher.apply(parameter, tweak, list(children))
                parents.append(parent_node)

            # Pad the new list of parents to prepare for the next iteration.
            new_start_index = current_layer.start_index // 2
            current_layer = self._get_padded_layer(parents, new_start_index)
            layers.append(current_layer)

        # Return the completed tree containing all computed layers.
        return HashTree(depth=depth, layers=layers)

    def root(self, tree: HashTree) -> HashDigest:
        """
        Extracts the root digest from a constructed Merkle tree.

        The root is the single node in the final, highest layer of the `HashTree`
        and serves as the primary component of the master public key.
        """
        # The root is the single node in the final layer.
        return tree.layers[-1].nodes[0]

    def path(self, tree: HashTree, position: Uint64) -> HashTreeOpening:
        """
        Computes the authentication path for a leaf.

        The path is the minimal set of sibling nodes a verifier needs to reconstruct
        the root from a given leaf. This `O(log N)` proof is what makes Merkle
        tree verification highly efficient.

        ### Path Generation Algorithm
        The algorithm "climbs" the tree from the leaf level to the root. At each
        level, it identifies the sibling of the current node on the path and adds
        it to the `co_path`. It then moves up to the parent's position for the
        next level.

        Args:
            tree: The `HashTree` from which to extract the path.
            position: The absolute index of the leaf whose path is needed.

        Returns:
            A `HashTreeOpening` object containing the list of sibling hashes.
        """
        # Check that there is at least one layer in the tree.
        if len(tree.layers) == 0:
            raise ValueError("Cannot generate path for empty tree.")

        # Check that the position is within the tree's range.
        if int(position) < tree.layers[0].start_index:
            raise ValueError("Position (before start) is invalid.")

        if int(position) >= tree.layers[0].start_index + len(tree.layers[0].nodes):
            raise ValueError("Position (after end) is invalid.")

        co_path: List[HashDigest] = []
        current_position = int(position)

        # Iterate from the leaf layer (level 0) up to the layer below the root.
        for level in range(tree.depth):
            # Determine the sibling's position by flipping the last bit (XOR with 1).
            sibling_position = current_position ^ 1
            # Find the sibling's index within our sparsely stored `nodes` vector.
            layer = tree.layers[level]
            sibling_index_in_vec = sibling_position - layer.start_index
            # Add the sibling's hash to the co-path.
            co_path.append(layer.nodes[sibling_index_in_vec])
            # Move up to the parent's position for the next iteration.
            current_position //= 2

        return HashTreeOpening(siblings=co_path)

    def verify_path(
        self,
        parameter: Parameter,
        root: HashDigest,
        position: Uint64,
        leaf_parts: List[HashDigest],
        opening: HashTreeOpening,
    ) -> bool:
        """
        Verifies a Merkle authentication path against a known, trusted root.

        This function is the final check in signature verification. It proves that the
        one-time public key used for the signature (represented by `leaf_parts`) is a
        legitimate member of the set committed to by the Merkle `root`.

        ### Verification Algorithm

        1.  **Leaf Computation**: The process begins at the bottom. The verifier first
            hashes the `leaf_parts` to compute the actual leaf digest. This becomes the
            starting `current_node` for the climb up the tree.

        2.  **Bottom-Up Reconstruction**: The verifier iterates through the `opening.siblings`
            path. At each `level`, it takes the `current_node` and the `sibling_node`
            from the path.

        3.  **Parent Calculation**: It determines if the `current_node` is a left or
            right child based on its `position`. The two nodes are placed in the
            correct `(left, right)` order and hashed (with the correct `TreeTweak`)
            to compute the parent. This parent becomes the `current_node` for the
            next level.

        4.  **Final Comparison**: After all siblings are used, the final `current_node`
            is the candidate root. The path is valid if and only if it matches the trusted `root`.

        Args:
            parameter: The public parameter `P` for the hash function.
            root: The known, trusted Merkle root from the public key.
            position: The absolute index of the leaf being verified.
            leaf_parts: The list of digests that constitute the original leaf.
            opening: The `HashTreeOpening` object containing the sibling path.

        Returns:
            `True` if the path is valid and reconstructs the root, `False` otherwise.
        """
        # Compute the depth
        depth = len(opening.siblings)
        # Compute the number of leafs in the tree
        num_leafs = 2**depth
        # Check that the tree depth is at most 32.
        if len(opening.siblings) > 32:
            raise ValueError("Tree depth must be at most 32.")
        # Check that the position and path length match.
        if int(position) >= num_leafs:
            raise ValueError("Position and path length do not match.")

        # The first step is to hash the constituent parts of the leaf to get
        # the actual node at layer 0 of the tree.
        leaf_tweak = TreeTweak(level=0, index=int(position))
        current_node = self.hasher.apply(parameter, leaf_tweak, leaf_parts)

        # Iterate up the tree, hashing the current node with its sibling from
        # the path at each level.
        current_position = int(position)
        for level, sibling_node in enumerate(opening.siblings):
            # Determine if the current node is a left or right child.
            if current_position % 2 == 0:
                # Current node is a left child; sibling is on the right.
                children = [current_node, sibling_node]
            else:
                # Current node is a right child; sibling is on the left.
                children = [sibling_node, current_node]

            # Move up to the parent's position for the next iteration.
            current_position //= 2
            # Create the tweak for the parent's level and position.
            parent_tweak = TreeTweak(level=level + 1, index=current_position)
            # Hash the children to compute the parent node.
            current_node = self.hasher.apply(parameter, parent_tweak, children)

        # After iterating through the entire path, the final computed node
        # should be the root of the tree.
        return current_node == root

    def subtree_root(self, subtree: HashSubTree) -> HashDigest:
        """
        Extracts the root digest from a subtree.

        For top-bottom tree traversal, a subtree's root is the single node
        in its highest layer.

        Args:
            subtree: The subtree whose root to extract.

        Returns:
            The root hash digest of the subtree.

        Raises:
            ValueError: If the subtree has no layers or the highest layer is empty.
        """
        if len(subtree.layers) == 0:
            raise ValueError("Cannot get root of empty subtree.")

        highest_layer = subtree.layers[-1]
        if len(highest_layer.nodes) == 0:
            raise ValueError("Highest layer of subtree is empty.")

        # The root is the only node in the highest layer for proper subtrees.
        # For top trees and bottom trees, the highest layer should have exactly one node.
        return highest_layer.nodes[0]

    def subtree_path(self, subtree: HashSubTree, position: Uint64) -> HashTreeOpening:
        """
        Computes the authentication path for a leaf within a subtree.

        This is similar to `path()` but works with subtrees that may not start
        from layer 0. The path is computed from the specified position up to
        (but not including) the subtree's root.

        For a subtree covering layers L through H (where H is the highest/root layer),
        this generates H - L siblings: one for each layer from L to H-1.

        Args:
            subtree: The subtree from which to extract the path.
            position: The absolute index of the leaf in the full tree coordinate system.

        Returns:
            A `HashTreeOpening` containing the sibling hashes for the path.

        Raises:
            ValueError: If the subtree is empty or the position is out of bounds.
        """
        if len(subtree.layers) == 0:
            raise ValueError("Cannot generate path for empty subtree.")

        lowest_layer = subtree.layers[0]
        if int(position) < lowest_layer.start_index:
            raise ValueError("Position is before the subtree's start index.")

        if int(position) >= lowest_layer.start_index + len(lowest_layer.nodes):
            raise ValueError("Position is beyond the subtree's range.")

        co_path: List[HashDigest] = []
        current_position = int(position)

        # Iterate through layers from lowest to highest, EXCLUDING the final root layer.
        # The root layer doesn't contribute a sibling to the authentication path.
        # subtree.layers[:-1] gives all layers except the last (root) layer.
        for layer in subtree.layers[:-1]:
            # Determine the sibling's position by flipping the last bit.
            sibling_position = current_position ^ 1
            sibling_index = sibling_position - layer.start_index

            # Ensure the sibling exists in this layer
            if sibling_index < 0 or sibling_index >= len(layer.nodes):
                raise ValueError(
                    f"Sibling index {sibling_index} out of bounds for layer "
                    f"with {len(layer.nodes)} nodes"
                )

            # Add the sibling's hash to the co-path.
            co_path.append(layer.nodes[sibling_index])

            # Move to the parent's position for the next iteration.
            current_position //= 2

        return HashTreeOpening(siblings=co_path)

    def new_subtree(
        self,
        lowest_layer: int,
        depth: int,
        start_index: int,
        parameter: Parameter,
        lowest_layer_nodes: List[HashDigest],
    ) -> HashSubTree:
        """
        Builds a new sparse Merkle subtree starting from a specified layer.

        This is the general constructor for subtrees and is used internally by
        `new_top_tree()` and `new_bottom_tree()`. A subtree can start from any
        layer, not just layer 0 (leaves).

        ### Construction Algorithm

        1.  **Initialization**: Start with the provided nodes at `lowest_layer`,
            apply padding to ensure even alignment.

        2.  **Bottom-Up Iteration**: Build the tree layer by layer, from the
            lowest layer towards the root.

        3.  **Parent Generation**: At each level, group nodes into pairs
            (left, right) and hash them to create parent nodes.

        4.  **Padding**: Apply padding to each new layer to maintain the
            even-alignment invariant.

        5.  **Termination**: Continue until reaching the root or the desired
            highest layer.

        Args:
            lowest_layer: The starting layer for this subtree (0 for full trees).
            depth: The total depth of the full tree (e.g., 32 for 2^32 leaves).
            start_index: The absolute index at `lowest_layer` where this subtree begins.
            parameter: The public parameter `P` for the hash function.
            lowest_layer_nodes: The hash nodes at `lowest_layer` to build from.

        Returns:
            A `HashSubTree` containing all computed layers from `lowest_layer` to root.
        """
        # Validate that we have enough space in the tree for these nodes.
        # At layer `lowest_layer`, there are 2^(depth - lowest_layer) possible positions.
        max_index_at_layer = 1 << (depth - lowest_layer)
        if start_index + len(lowest_layer_nodes) > max_index_at_layer:
            raise ValueError(
                f"Not enough space at layer {lowest_layer}: "
                f"start_index={start_index}, nodes={len(lowest_layer_nodes)}, "
                f"max={max_index_at_layer}"
            )

        # Start with the lowest layer nodes and apply initial padding.
        layers: List[HashTreeLayer] = []
        current_layer = self._get_padded_layer(lowest_layer_nodes, start_index)
        layers.append(current_layer)

        # Build the tree layer by layer from lowest_layer up to the root.
        for level in range(lowest_layer, depth):
            parents: List[HashDigest] = []

            # Group current layer's nodes into pairs of (left, right) siblings.
            # The padding guarantees this works perfectly without orphan nodes.
            for i, children in enumerate(
                zip(
                    current_layer.nodes[0::2],
                    current_layer.nodes[1::2],
                    strict=False,
                )
            ):
                # Calculate the position of the parent node in the next level up.
                parent_index = (current_layer.start_index // 2) + i
                # Create the tweak for hashing these two children.
                tweak = TreeTweak(level=level + 1, index=parent_index)
                # Hash the left and right children to get their parent.
                parent_node = self.hasher.apply(parameter, tweak, list(children))
                parents.append(parent_node)

            # Pad the new list of parents to prepare for the next iteration.
            new_start_index = current_layer.start_index // 2
            current_layer = self._get_padded_layer(parents, new_start_index)
            layers.append(current_layer)

        # Return the completed subtree.
        return HashSubTree(depth=depth, lowest_layer=lowest_layer, layers=layers)

    def new_top_tree(
        self,
        depth: int,
        start_bottom_tree_index: int,
        parameter: Parameter,
        bottom_tree_roots: List[HashDigest],
    ) -> HashSubTree:
        """
        Constructs a top tree from the roots of bottom trees.

        For top-bottom tree traversal, the full Merkle tree is split into:
        - **Top tree**: Contains root and top `LOG_LIFETIME/2` layers
        - **Bottom trees**: Each contains `sqrt(LIFETIME)` leaves

        The top tree's lowest layer contains the roots of all bottom trees,
        and it is built upward from there to the global root.

        ### Algorithm

        1.  **Determine lowest layer**: For a tree of depth `d`, the top tree
            starts at layer `d/2` (the middle of the tree).

        2.  **Build upward**: Use `new_subtree()` to build from the bottom tree
            roots up to the global root.

        Args:
            depth: The total depth of the full tree (must be even for top-bottom split).
            start_bottom_tree_index: The index of the first bottom tree in the range.
            parameter: The public parameter `P` for the hash function.
            bottom_tree_roots: The list of roots from all bottom trees in order.

        Returns:
            A `HashSubTree` representing the top tree with `lowest_layer = depth/2`.

        Raises:
            ValueError: If depth is odd (top-bottom split requires even depth).
        """
        if depth % 2 != 0:
            raise ValueError(
                f"Top-bottom tree split requires even depth, got {depth}. "
                f"The top tree must start at depth/2, which must be an integer."
            )

        # The top tree starts at the middle layer.
        lowest_layer = depth // 2

        # Build the top tree using the bottom tree roots as the lowest layer.
        return self.new_subtree(
            lowest_layer=lowest_layer,
            depth=depth,
            start_index=start_bottom_tree_index,
            parameter=parameter,
            lowest_layer_nodes=bottom_tree_roots,
        )

    def new_bottom_tree(
        self,
        depth: int,
        bottom_tree_index: int,
        parameter: Parameter,
        leaves: List[HashDigest],
    ) -> HashSubTree:
        """
        Constructs a single bottom tree from leaf hashes.

        A bottom tree covers `sqrt(LIFETIME)` consecutive epochs. For a tree with
        `LOG_LIFETIME = 32`, each bottom tree covers 2^16 = 65536 epochs.

        Bottom trees are numbered 0, 1, 2, ... where tree `i` covers epochs
        `[i * sqrt(LIFETIME), (i+1) * sqrt(LIFETIME))`.

        ### Algorithm

        1.  **Build full tree**: First, build a complete subtree from layer 0
            using the provided leaves.

        2.  **Truncate incompatible top layers**: The full tree computation adds
            padding nodes in upper layers that would be incompatible with other
            bottom trees. We remove these layers.

        3.  **Replace with standalone root**: Extract the root at layer `depth/2`
            and make it the highest layer of this bottom tree.

        Args:
            depth: The total depth of the full tree (must be even).
            bottom_tree_index: The index of this bottom tree (0, 1, 2, ...).
            parameter: The public parameter `P` for the hash function.
            leaves: The pre-hashed leaf nodes (one-time public keys).

        Returns:
            A `HashSubTree` with layers 0 through `depth/2`, where the highest
            layer contains only the bottom tree's root.

        Raises:
            ValueError: If depth is odd or leaves count doesn't match `sqrt(LIFETIME)`.
        """
        if depth % 2 != 0:
            raise ValueError(
                f"Top-bottom tree split requires even depth, got {depth}. "
                f"Bottom trees must span exactly depth/2 layers."
            )

        leafs_per_bottom_tree = 1 << (depth // 2)
        if len(leaves) != leafs_per_bottom_tree:
            raise ValueError(
                f"Bottom tree must have exactly {leafs_per_bottom_tree} leaves "
                f"(sqrt(LIFETIME) for depth={depth}), got {len(leaves)}"
            )

        # Calculate the starting index for this bottom tree's leaves.
        start_index = bottom_tree_index * leafs_per_bottom_tree

        # Build a full subtree from layer 0 using the leaves.
        full_tree = self.new_subtree(
            lowest_layer=0,
            depth=depth,
            start_index=start_index,
            parameter=parameter,
            lowest_layer_nodes=leaves,
        )

        # Truncate to remove upper layers that would be incompatible with the top tree.
        # We keep layers 0 through depth/2 (inclusive).
        #
        # Extract the root at layer depth/2. The root's index in that layer is either
        # the bottom_tree_index (if it's the left child of its parent in the top tree)
        # or bottom_tree_index (if it's the right child). Since we're at layer depth/2,
        # the position is simply bottom_tree_index.
        middle_layer = full_tree.layers[depth // 2]

        # The root is at position (start_index >> (depth // 2)) = bottom_tree_index
        # within the middle layer. We need to find it in the stored nodes.
        root_position_in_layer = bottom_tree_index - middle_layer.start_index
        root = middle_layer.nodes[root_position_in_layer]

        # Truncate layers to keep only 0 through depth/2 - 1.
        truncated_layers = full_tree.layers[: (depth // 2)]

        # Add a final layer containing just the root.
        truncated_layers.append(HashTreeLayer(start_index=bottom_tree_index, nodes=[root]))

        return HashSubTree(depth=depth, lowest_layer=0, layers=truncated_layers)

    def combined_path(
        self, top_tree: HashSubTree, bottom_tree: HashSubTree, position: Uint64
    ) -> HashTreeOpening:
        """
        Generates a combined authentication path spanning top and bottom trees.

        For top-bottom tree traversal, a signature's authentication path must prove
        that a leaf is part of the global Merkle root. This requires two proofs:

        1.  **Bottom tree path**: Proves the leaf is part of its bottom tree's root
        2.  **Top tree path**: Proves the bottom tree's root is part of the global root

        This function combines both paths into a single `HashTreeOpening` that can
        be used for verification.

        ### Algorithm

        1.  **Determine which bottom tree**: Calculate which bottom tree contains
            the specified position.

        2.  **Get bottom tree path**: Extract the authentication path from the leaf
            up to the bottom tree's root (depth/2 siblings).

        3.  **Get top tree path**: Extract the authentication path from the bottom
            tree's root up to the global root (depth/2 siblings).

        4.  **Concatenate**: Combine both paths into a single path with `depth` siblings.

        Args:
            top_tree: The top tree containing the global root.
            bottom_tree: The bottom tree containing the specified position.
            position: The absolute epoch/leaf index to generate a path for.

        Returns:
            A `HashTreeOpening` with `depth` siblings that authenticates the leaf
            against the global root.

        Raises:
            ValueError: If trees have mismatched depths, odd depth, or position is
                       out of bounds for the bottom tree.
        """
        # Validate that both trees have the same depth.
        if top_tree.depth != bottom_tree.depth:
            raise ValueError(
                f"Top and bottom trees must have same depth: "
                f"top={top_tree.depth}, bottom={bottom_tree.depth}"
            )

        depth = top_tree.depth

        # Validate even depth (required for top-bottom split).
        if depth % 2 != 0:
            raise ValueError(
                f"Top-bottom tree traversal requires even depth, got {depth}. "
                f"Cannot split tree into equal top and bottom halves."
            )

        # Calculate parameters for bottom trees.
        leafs_per_bottom_tree = 1 << (depth // 2)

        # Determine which bottom tree this position belongs to.
        #
        # Bottom tree index = floor(position / sqrt(LIFETIME))
        bottom_tree_index = int(position) // leafs_per_bottom_tree

        # Verify that the provided bottom_tree actually corresponds to this position.
        # The bottom tree's lowest layer starts at bottom_tree_index * leafs_per_bottom_tree.
        expected_start = bottom_tree_index * leafs_per_bottom_tree
        actual_start = bottom_tree.layers[0].start_index

        if actual_start != expected_start:
            raise ValueError(
                f"Bottom tree mismatch: position {position} belongs to "
                f"bottom tree {bottom_tree_index} (should start at {expected_start}), "
                f"but provided bottom tree starts at {actual_start}"
            )

        # Get the authentication path within the bottom tree (from leaf to bottom tree root).
        bottom_path = self.subtree_path(bottom_tree, position)

        # Get the authentication path within the top tree (from bottom tree root to global root).
        # The bottom tree's root is at position `bottom_tree_index` in the top tree's lowest layer.
        top_path = self.subtree_path(top_tree, Uint64(bottom_tree_index))

        # Concatenate the two paths: bottom siblings first, then top siblings.
        # This creates a complete path from leaf to global root.
        combined_siblings = bottom_path.siblings + top_path.siblings

        return HashTreeOpening(siblings=combined_siblings)


PROD_MERKLE_TREE = MerkleTree(PROD_CONFIG, PROD_TWEAK_HASHER, PROD_RAND)
"""An instance configured for production-level parameters."""

TEST_MERKLE_TREE = MerkleTree(TEST_CONFIG, TEST_TWEAK_HASHER, TEST_RAND)
"""A lightweight instance for test environments."""
