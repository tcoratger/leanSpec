"""
Defines the core interface for the Generalized XMSS signature scheme.

Specification for the high-level functions (`key_gen`, `sign`, `verify`).

This constitutes the public API of the signature scheme.
"""

from __future__ import annotations

from typing import List, Tuple

from lean_spec.subspecs.xmss.target_sum import (
    PROD_TARGET_SUM_ENCODER,
    TEST_TARGET_SUM_ENCODER,
    TargetSumEncoder,
)
from lean_spec.types.uint import Uint64

from ..koalabear import Fp
from .constants import (
    PROD_CONFIG,
    TEST_CONFIG,
    XmssConfig,
)
from .containers import HashDigest, HashSubTree, PublicKey, SecretKey, Signature
from .merkle_tree import (
    PROD_MERKLE_TREE,
    TEST_MERKLE_TREE,
    MerkleTree,
)
from .prf import PROD_PRF, TEST_PRF, Prf
from .tweak_hash import (
    PROD_TWEAK_HASHER,
    TEST_TWEAK_HASHER,
    TreeTweak,
    TweakHasher,
)
from .utils import PROD_RAND, TEST_RAND, Rand


def _expand_activation_time(
    log_lifetime: int, desired_activation_epoch: int, desired_num_active_epochs: int
) -> tuple[int, int]:
    """
    Expands and aligns the activation time to top-bottom tree boundaries.

    For efficient top-bottom tree traversal, activation intervals must be aligned to
    `sqrt(LIFETIME)` boundaries. This function takes the user's desired activation
    interval and expands it to meet the following requirements:

    1.  **Start alignment**: Start epoch is rounded down to a multiple of `sqrt(LIFETIME)`
    2.  **End alignment**: End epoch is rounded up to a multiple of `sqrt(LIFETIME)`
    3.  **Minimum duration**: At least `2 * sqrt(LIFETIME)` epochs (two bottom trees)
    4.  **Lifetime bounds**: Clamped to `[0, LIFETIME)`

    ### Algorithm

    Let `C = 2^(LOG_LIFETIME/2) = sqrt(LIFETIME)`

    1.  Align start downward: `start = desired_start & c_mask` where `c_mask = ~(C - 1)`
    2.  Round end upward: `end = (desired_end + C - 1) & c_mask`
    3.  Enforce minimum: `if end - start < 2*C: end = start + 2*C`
    4.  Clamp to bounds: Adjust if end exceeds `C^2 = LIFETIME`

    ### Example

    For `LOG_LIFETIME = 32` (LIFETIME = 2^32, C = 2^16 = 65536):
    - Request: epochs [10000, 80000) → 70000 epochs
    - Aligned: epochs [0, 131072) → 131072 epochs = 2 bottom trees

    Args:
        log_lifetime: The logarithm (base 2) of the total lifetime.
        desired_activation_epoch: The user's requested first epoch.
        desired_num_active_epochs: The user's requested number of epochs.

    Returns:
        A tuple `(start_bottom_tree_index, end_bottom_tree_index)` where:
        - `start_bottom_tree_index`: Index of the first bottom tree (0, 1, 2, ...)
        - `end_bottom_tree_index`: Index past the last bottom tree (exclusive)
        - Actual epochs: `[start_index * C, end_index * C)`
    """
    # Calculate sqrt(LIFETIME) and the alignment mask.
    c = 1 << (log_lifetime // 2)  # C = 2^(LOG_LIFETIME/2)
    c_mask = ~(c - 1)  # Mask for rounding to multiples of C

    # Calculate the desired end epoch.
    desired_end_epoch = desired_activation_epoch + desired_num_active_epochs

    # Step 1: Align start downward to a multiple of C.
    start = desired_activation_epoch & c_mask

    # Step 2: Round end upward to a multiple of C.
    end = (desired_end_epoch + c - 1) & c_mask

    # Step 3: Enforce minimum duration of 2*C.
    if end - start < 2 * c:
        end = start + 2 * c

    # Step 4: Clamp to lifetime bounds [0, C^2).
    lifetime = c * c  # LIFETIME = C^2 = 2^LOG_LIFETIME
    if end > lifetime:
        # If the expanded interval exceeds the lifetime, try to fit it at the end.
        duration = end - start

        if duration > lifetime:
            # The expanded interval is larger than the entire lifetime.
            # Use the entire lifetime.
            start = 0
            end = lifetime
        else:
            # Shift the interval to end at the lifetime boundary.
            end = lifetime
            start = (lifetime - duration) & c_mask  # Keep alignment

    # Convert to bottom tree indices.
    # Bottom tree i covers epochs [i*C, (i+1)*C).
    start_bottom_tree_index = start // c
    end_bottom_tree_index = end // c

    return (start_bottom_tree_index, end_bottom_tree_index)


def _bottom_tree_from_prf_key(
    prf: Prf,
    hasher: TweakHasher,
    merkle_tree: MerkleTree,
    config: XmssConfig,
    prf_key: bytes,
    bottom_tree_index: int,
    parameter: List[Fp],
) -> HashSubTree:
    """
    Generates a single bottom tree on-demand from the PRF key.

    This is a key component of the top-bottom tree approach: instead of storing all
    one-time secret keys, we regenerate them on-demand using the PRF. This enables
    O(sqrt(LIFETIME)) memory usage.

    ### Algorithm

    1.  **Determine epoch range**: Bottom tree `i` covers epochs
        `[i * sqrt(LIFETIME), (i+1) * sqrt(LIFETIME))`

    2.  **Generate leaves**: For each epoch in parallel:
        - For each chain (0 to DIMENSION-1):
          - Derive secret start: `PRF(prf_key, epoch, chain_index)`
          - Compute public end: hash chain for `BASE - 1` steps
        - Hash all chain ends to get the leaf

    3.  **Build bottom tree**: Construct the bottom tree from the leaves

    Args:
        prf: The PRF instance for key derivation.
        hasher: The tweakable hash instance.
        merkle_tree: The Merkle tree instance for tree construction.
        config: The XMSS configuration.
        prf_key: The master PRF secret key.
        bottom_tree_index: The index of the bottom tree to generate (0, 1, 2, ...).
        parameter: The public parameter `P` for the hash function.

    Returns:
        A `HashSubTree` representing the requested bottom tree.
    """
    # Calculate the number of leaves per bottom tree: sqrt(LIFETIME).
    leafs_per_bottom_tree = 1 << (config.LOG_LIFETIME // 2)

    # Determine the epoch range for this bottom tree.
    start_epoch = bottom_tree_index * leafs_per_bottom_tree
    end_epoch = start_epoch + leafs_per_bottom_tree

    # Generate leaf hashes for all epochs in this bottom tree.
    leaf_hashes: List[HashDigest] = []

    for epoch in range(start_epoch, end_epoch):
        # For each epoch, compute the one-time public key (chain endpoints).
        chain_ends: List[HashDigest] = []

        for chain_index in range(config.DIMENSION):
            # Derive the secret start of the chain from the PRF key.
            start_digest = prf.apply(prf_key, Uint64(epoch), Uint64(chain_index))

            # Compute the public end by hashing BASE - 1 times.
            end_digest = hasher.hash_chain(
                parameter=parameter,
                epoch=Uint64(epoch),
                chain_index=chain_index,
                start_step=0,
                num_steps=config.BASE - 1,
                start_digest=start_digest,
            )
            chain_ends.append(end_digest)

        # Hash the chain ends to get the leaf for this epoch.
        leaf_tweak = TreeTweak(level=0, index=epoch)
        leaf_hash = hasher.apply(parameter, leaf_tweak, chain_ends)
        leaf_hashes.append(leaf_hash)

    # Build the bottom tree from the leaf hashes.
    return merkle_tree.new_bottom_tree(
        depth=config.LOG_LIFETIME,
        bottom_tree_index=bottom_tree_index,
        parameter=parameter,
        leaves=leaf_hashes,
    )


class GeneralizedXmssScheme:
    """Instance of the Generalized XMSS signature scheme for a given config."""

    def __init__(
        self,
        config: XmssConfig,
        prf: Prf,
        hasher: TweakHasher,
        merkle_tree: MerkleTree,
        encoder: TargetSumEncoder,
        rand: Rand,
    ):
        """Initializes the scheme with a specific parameter set."""
        self.config = config
        self.prf = prf
        self.hasher = hasher
        self.merkle_tree = merkle_tree
        self.encoder = encoder
        self.rand = rand

    def key_gen(
        self, activation_epoch: Uint64, num_active_epochs: Uint64
    ) -> Tuple[PublicKey, SecretKey]:
        """
        Generates a new cryptographic key pair for a specified range of epochs.

        This is a **randomized** algorithm that establishes a signer's identity using
        the memory-efficient Top-Bottom Tree Traversal approach.

        ### Key Generation Algorithm

        1.  **Expand Activation Time**: Align the requested activation interval to
            `sqrt(LIFETIME)` boundaries to enable efficient tree partitioning.
            This ensures the interval starts at a multiple of `sqrt(LIFETIME)` and
            has a minimum duration of `2 * sqrt(LIFETIME)` epochs.

        2.  **Generate Master Secrets**: Generate PRF key and public parameter `P`.
            The PRF key allows deterministic on-demand regeneration of one-time keys.

        3.  **Generate First Two Bottom Trees**: Create the first two bottom trees
            (covering the initial `2 * sqrt(LIFETIME)` epochs) and keep them in memory.
            Each bottom tree covers `sqrt(LIFETIME)` consecutive epochs.

        4.  **Generate Remaining Bottom Tree Roots**: For all other bottom trees in
            the range, generate only their roots (not the full trees). This saves
            memory since we only need the first two trees for the prepared window.

        5.  **Build Top Tree**: Construct the top tree from all bottom tree roots.
            The top tree's lowest layer contains the bottom tree roots, and it is
            built upward to the global Merkle root.

        ### Memory Efficiency

        Traditional approach: O(LIFETIME) memory
        Top-Bottom approach: O(sqrt(LIFETIME)) memory

        For LOG_LIFETIME=32 (2^32 epochs):
        - Traditional: ~hundreds of GiB
        - Top-Bottom: ~6-8 MB

        Args:
            activation_epoch: The starting epoch for which this key is valid.
                             Will be aligned downward to `sqrt(LIFETIME)` boundary.
            num_active_epochs: The number of consecutive epochs the key can be used for.
                              Will be rounded up to at least `2 * sqrt(LIFETIME)`.

        Returns:
            A tuple containing the `PublicKey` and `SecretKey`.

        Note:
            The actual activation epoch and num_active_epochs in the returned SecretKey
            may be larger than requested due to alignment requirements.

        For the formal specification of this process, please refer to:
        - "Hash-Based Multi-Signatures for Post-Quantum Ethereum": https://eprint.iacr.org/2025/055
        - "Technical Note: LeanSig for Post-Quantum Ethereum": https://eprint.iacr.org/2025/1332
        - The canonical Rust implementation: https://github.com/b-wagn/hash-sig
        """
        # Retrieve the scheme's configuration parameters.
        config = self.config

        # Ensure the requested activation range is within the scheme's total supported lifetime.
        if activation_epoch + num_active_epochs > config.LIFETIME:
            raise ValueError("Activation range exceeds the key's lifetime.")

        # Generate the random public parameter `P` and the master PRF key.
        # - `P` ensures hash function outputs are unique to this key pair.
        # - PRF key is the single master secret from which all one-time keys are derived.
        parameter = self.rand.parameter()
        prf_key = self.prf.key_gen()

        # Step 1: Expand and align activation time to sqrt(LIFETIME) boundaries.
        start_bottom_tree_index, end_bottom_tree_index = _expand_activation_time(
            config.LOG_LIFETIME, int(activation_epoch), int(num_active_epochs)
        )

        num_bottom_trees = end_bottom_tree_index - start_bottom_tree_index
        leafs_per_bottom_tree = 1 << (config.LOG_LIFETIME // 2)

        # Calculate the actual (expanded) activation epoch and count.
        actual_activation_epoch = start_bottom_tree_index * leafs_per_bottom_tree
        actual_num_active_epochs = num_bottom_trees * leafs_per_bottom_tree

        # Step 2: Generate the first two bottom trees (kept in memory).
        left_bottom_tree = _bottom_tree_from_prf_key(
            self.prf,
            self.hasher,
            self.merkle_tree,
            config,
            prf_key,
            start_bottom_tree_index,
            parameter,
        )
        right_bottom_tree = _bottom_tree_from_prf_key(
            self.prf,
            self.hasher,
            self.merkle_tree,
            config,
            prf_key,
            start_bottom_tree_index + 1,
            parameter,
        )

        # Collect roots for building the top tree.
        bottom_tree_roots: List[HashDigest] = [
            self.merkle_tree.subtree_root(left_bottom_tree),
            self.merkle_tree.subtree_root(right_bottom_tree),
        ]

        # Step 3: Generate remaining bottom trees (only their roots).
        for i in range(start_bottom_tree_index + 2, end_bottom_tree_index):
            tree = _bottom_tree_from_prf_key(
                self.prf,
                self.hasher,
                self.merkle_tree,
                config,
                prf_key,
                i,
                parameter,
            )
            root = self.merkle_tree.subtree_root(tree)
            bottom_tree_roots.append(root)

        # Step 4: Build the top tree from bottom tree roots.
        top_tree = self.merkle_tree.new_top_tree(
            depth=config.LOG_LIFETIME,
            start_bottom_tree_index=start_bottom_tree_index,
            parameter=parameter,
            bottom_tree_roots=bottom_tree_roots,
        )

        # Extract the global root.
        root = self.merkle_tree.subtree_root(top_tree)

        # Assemble and return the keys.
        pk = PublicKey(root=root, parameter=parameter)
        sk = SecretKey(
            prf_key=prf_key,
            parameter=parameter,
            activation_epoch=actual_activation_epoch,
            num_active_epochs=actual_num_active_epochs,
            top_tree=top_tree,
            left_bottom_tree_index=start_bottom_tree_index,
            left_bottom_tree=left_bottom_tree,
            right_bottom_tree=right_bottom_tree,
        )
        return pk, sk

    def sign(self, sk: SecretKey, epoch: Uint64, message: bytes) -> Signature:
        """
        Produces a digital signature for a given message at a specific epoch.

        This is a **randomized** algorithm.

        **CRITICAL SECURITY WARNING**: A secret key for a given epoch must **NEVER** be used
        to sign two different messages. Doing so would reveal parts of the secret key
        and allow an attacker to forge signatures. This is the fundamental security
        property of a synchronized (stateful) signature scheme.

        ### Signing Algorithm

        1.  **Message Encoding with Randomness (`rho`)**: The "Target Sum" scheme
            requires the message hash to be encoded into a `codeword` whose digits
            sum to a predefined target. A direct hash of the message is unlikely to
            satisfy this. Therefore, the algorithm repeatedly hashes the message
            combined with fresh randomness (`rho`) until a valid `codeword` is found.

        2.  **One-Time Signature**: The `codeword` dictates how the one-time signature is
            formed. For each digit `x_i` in the codeword, the signer reveals an intermediate
            hash value by applying the hash function `x_i` times to the secret start of the
            `i`-th hash chain.
            The collection of these intermediate hashes forms the one-time signature.

        3.  **Merkle Path**: The signer retrieves the Merkle authentication path for the leaf
            corresponding to the current `epoch`. This path proves that the one-time public key
            for this epoch is part of the main public key (the Merkle root).

        Args:
            sk: The secret key to use for signing.
            epoch: The epoch for which the signature is being created.
            message: The message to be signed.

        Returns:
            The resulting `Signature` object.

        For the formal specification of this process, please refer to:
        - "Hash-Based Multi-Signatures for Post-Quantum Ethereum": https://eprint.iacr.org/2025/055
        - "Technical Note: LeanSig for Post-Quantum Ethereum": https://eprint.iacr.org/2025/1332
        - The canonical Rust implementation: https://github.com/b-wagn/hash-sig
        """
        # Retrieve the scheme's configuration parameters.
        config = self.config

        # Verify that the secret key is currently active for the requested signing epoch.
        # Note: range() requires int, so we convert only for the range check
        activation_int = int(sk.activation_epoch)
        num_epochs_int = int(sk.num_active_epochs)
        active_range = range(activation_int, activation_int + num_epochs_int)
        if int(epoch) not in active_range:
            raise ValueError("Key is not active for the specified epoch.")

        # Find a valid message encoding.
        #
        # This loop repeatedly tries different randomness `rho` until the encoder
        # produces a valid codeword (i.e., one that meets the target sum constraint).
        for _ in range(config.MAX_TRIES):
            # Sample fresh randomness `rho`.
            rho = self.rand.rho()
            # Attempt to encode the message with the new `rho`.
            codeword = self.encoder.encode(sk.parameter, message, rho, epoch)
            # If encoding is successful, we've found our `rho` and `codeword`.
            #
            # We can exit the loop.
            if codeword is not None:
                break
        else:
            # This block executes only if the `for` loop completes without a `break`.
            #
            # This means that no valid encoding was found after the maximum number of tries.
            raise RuntimeError(
                f"Failed to find a valid message encoding after {config.MAX_TRIES} tries."
            )

        # Sanity check to ensure the encoder returned a codeword of the correct length.
        if len(codeword) != self.config.DIMENSION:
            raise RuntimeError("Encoding is broken: returned too many or too few chunks.")

        # Compute the one-time signature hashes based on the codeword.
        ots_hashes: List[HashDigest] = []
        for chain_index, steps in enumerate(codeword):
            # Derive the secret start of the current chain using the master PRF key.
            start_digest = self.prf.apply(sk.prf_key, epoch, Uint64(chain_index))
            # Walk the hash chain for the number of `steps` specified by the
            # corresponding digit in the codeword.
            #
            # The result is one component of the OTS.
            ots_digest = self.hasher.hash_chain(
                parameter=sk.parameter,
                epoch=epoch,
                chain_index=chain_index,
                start_step=0,
                num_steps=steps,
                start_digest=start_digest,
            )
            ots_hashes.append(ots_digest)

        # Retrieve the Merkle authentication path for the current epoch's leaf.
        # With top-bottom tree traversal, we use combined_path to merge paths from
        # the bottom tree and top tree.

        # Ensure we have the required top-bottom tree structures.
        if sk.top_tree is None or sk.left_bottom_tree_index is None:
            raise ValueError(
                "Secret key is missing top-bottom tree structures. "
                "This may be a legacy key format that is no longer supported."
            )

        # Determine which bottom tree contains this epoch.
        leafs_per_bottom_tree = 1 << (config.LOG_LIFETIME // 2)
        boundary = (sk.left_bottom_tree_index + 1) * leafs_per_bottom_tree

        if int(epoch) < boundary:
            # Use left bottom tree
            bottom_tree = sk.left_bottom_tree
        else:
            # Use right bottom tree
            bottom_tree = sk.right_bottom_tree

        # Ensure bottom tree exists
        if bottom_tree is None:
            raise ValueError(
                f"Epoch {epoch} requires bottom tree but it is not available. "
                f"Prepared interval may have been exceeded. Call advance_preparation() "
                f"to slide the window forward."
            )

        # Generate the combined authentication path
        path = self.merkle_tree.combined_path(sk.top_tree, bottom_tree, epoch)

        # Assemble and return the final signature, which contains:
        # - The OTS,
        # - The Merkle path,
        # - The randomness `rho` needed for verification.
        return Signature(path=path, rho=rho, hashes=ots_hashes)

    def verify(self, pk: PublicKey, epoch: Uint64, message: bytes, sig: Signature) -> bool:
        r"""
        Verifies a digital signature against a public key, message, and epoch.

        This is a **deterministic** algorithm.

        ### Verification Algorithm

        1.  **Re-encode Message**: The verifier uses the randomness `rho` from the
            signature to re-compute the codeword $x = (x_1, \dots, x_v)$ from the message `m`.
            If the encoding is invalid (e.g., does not meet the target sum), verification fails.

        2.  **Reconstruct One-Time Public Key**: For each intermediate hash $y_i$ in the
            signature's `hashes` field, the verifier completes the corresponding hash chain.
            Since $y_i$ was computed by hashing $x_i$ times, the verifier applies the
            hash function an additional `BASE - 1 - x_i` times to arrive at the
            chain's public endpoint, which is one component of the one-time public key.

        3.  **Compute Merkle Leaf**: The verifier hashes the full set of reconstructed
            chain endpoints to compute the expected Merkle leaf for the given `epoch`.

        4.  **Verify Merkle Path**: The verifier uses the authentication `path` from the
            signature to compute a candidate Merkle root, starting from the leaf computed
            in the previous step. Verification succeeds if and only if this candidate root
            matches the `root` stored in the `PublicKey`.

        Args:
            pk: The public key to verify against.
            epoch: The epoch the signature corresponds to.
            message: The message that was supposedly signed.
            sig: The signature object to be verified.

        Returns:
            `True` if the signature is valid, `False` otherwise.

        For the formal specification of this process, please refer to:
        - "Hash-Based Multi-Signatures for Post-Quantum Ethereum": https://eprint.iacr.org/2025/055
        - "Technical Note: LeanSig for Post-Quantum Ethereum": https://eprint.iacr.org/2025/1332
        - The canonical Rust implementation: https://github.com/b-wagn/hash-sig
        """
        # Retrieve the scheme's configuration parameters.
        config = self.config

        # A signature for an epoch beyond the scheme's lifetime is invalid.
        if epoch > self.config.LIFETIME:
            raise ValueError("The signature is for a future epoch.")

        # Re-encode the message using the randomness `rho` from the signature.
        #
        # If the encoding is invalid (e.g., fails the target sum check), the signature is invalid.
        codeword = self.encoder.encode(pk.parameter, message, sig.rho, epoch)
        if codeword is None:
            return False

        # Reconstruct the one-time public key (the list of chain endpoints).
        chain_ends: List[HashDigest] = []
        for chain_index, xi in enumerate(codeword):
            # The signature provides `start_digest`, which is the hash value after `xi` steps.
            start_digest = sig.hashes[chain_index]
            # We must perform the remaining `BASE - 1 - xi` hashing steps
            # to compute the public endpoint of the chain.
            num_steps_remaining = config.BASE - 1 - xi
            end_digest = self.hasher.hash_chain(
                parameter=pk.parameter,
                epoch=epoch,
                chain_index=chain_index,
                start_step=xi,
                num_steps=num_steps_remaining,
                start_digest=start_digest,
            )
            chain_ends.append(end_digest)

        # Verify the Merkle path.
        #
        # This function internally:
        # - Hashes the `chain_ends` to get the leaf node for the epoch,
        # - Uses the `opening` path from the signature to compute a candidate root.
        # - It returns true if and only if this candidate root matches the public key's root.
        return self.merkle_tree.verify_path(
            parameter=pk.parameter,
            root=pk.root,
            position=epoch,
            leaf_parts=chain_ends,
            opening=sig.path,
        )


PROD_SIGNATURE_SCHEME = GeneralizedXmssScheme(
    PROD_CONFIG,
    PROD_PRF,
    PROD_TWEAK_HASHER,
    PROD_MERKLE_TREE,
    PROD_TARGET_SUM_ENCODER,
    PROD_RAND,
)
"""An instance configured for production-level parameters."""

TEST_SIGNATURE_SCHEME = GeneralizedXmssScheme(
    TEST_CONFIG,
    TEST_PRF,
    TEST_TWEAK_HASHER,
    TEST_MERKLE_TREE,
    TEST_TARGET_SUM_ENCODER,
    TEST_RAND,
)
"""A lightweight instance for test environments."""

DEFAULT_SIGNATURE_SCHEME = PROD_SIGNATURE_SCHEME
"""The default signature scheme to use."""
