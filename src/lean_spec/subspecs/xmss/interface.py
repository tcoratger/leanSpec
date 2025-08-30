"""
Defines the core interface for the Generalized XMSS signature scheme.

Specification for the high-level functions (`key_gen`, `sign`, `verify`).

This constitutes the public API of the signature scheme.
"""

from __future__ import annotations

from typing import List, Tuple

from lean_spec.subspecs.xmss.target_sum import encode

from .constants import BASE, DIMENSION, LIFETIME, LOG_LIFETIME, MAX_TRIES
from .merkle_tree import build_tree, get_path, get_root, verify_path
from .prf import apply as apply_prf
from .prf import key_gen as prf_key_gen
from .structures import HashDigest, PublicKey, SecretKey, Signature
from .tweak_hash import (
    TreeTweak,
    hash_chain,
)
from .tweak_hash import (
    apply as apply_tweakable_hash,
)
from .utils import rand_parameter, rand_rho


def key_gen(
    activation_epoch: int, num_active_epochs: int
) -> Tuple[PublicKey, SecretKey]:
    """
    Generates a new cryptographic key pair. This is a **randomized** algorithm.

    This function executes the full key generation process:
    1.  Generates a master secret (PRF key) and a public hash parameter.
    2.  For each epoch in the active range, it uses the PRF to derive the
        secret starting points for all `DIMENSION` hash chains.
    3.  It computes the public endpoint of each chain by
        hashing `BASE - 1` times.
    4.  The list of all chain endpoints for an epoch forms the
        one-time public key.
        This one-time public key is hashed to create a single Merkle leaf.
    5.  A Merkle tree is built over all generated leaves, and its root becomes
        part of the final public key.

    Args:
        activation_epoch: The starting epoch for which this key is active.
        num_active_epochs: The number of consecutive epochs
        the key is active for.

    For the formal specification of this process, please refer to:
    - "Hash-Based Multi-Signatures for Post-Quantum Ethereum": https://eprint.iacr.org/2025/055
    - "Technical Note: LeanSig for Post-Quantum Ethereum": https://eprint.iacr.org/2025/1332
    - The canonical Rust implementation: https://github.com/b-wagn/hash-sig
    """
    # Validate the activation range against the scheme's total lifetime.
    if activation_epoch + num_active_epochs > LIFETIME:
        raise ValueError("Activation range exceeds the key's lifetime.")

    # Generate the random public parameter `P` and the master PRF key.
    parameter = rand_parameter()
    prf_key = prf_key_gen()

    # For each epoch, generate the corresponding Merkle leaf hash.
    leaf_hashes: List[HashDigest] = []
    for epoch in range(activation_epoch, activation_epoch + num_active_epochs):
        # For each epoch, we compute `DIMENSION` chain endpoints.
        chain_ends: List[HashDigest] = []
        for chain_index in range(DIMENSION):
            # Derive the secret start of the chain from the master key.
            start_digest = apply_prf(prf_key, epoch, chain_index)
            # Compute the public end of the chain by hashing BASE - 1 times.
            end_digest = hash_chain(
                parameter=parameter,
                epoch=epoch,
                chain_index=chain_index,
                start_step=0,
                num_steps=BASE - 1,
                start_digest=start_digest,
            )
            chain_ends.append(end_digest)

        # The Merkle leaf is the hash of all chain endpoints for this epoch.
        leaf_tweak = TreeTweak(level=0, index=epoch)
        leaf_hash = apply_tweakable_hash(parameter, leaf_tweak, chain_ends)
        leaf_hashes.append(leaf_hash)

    # Build the Merkle tree over the generated leaves.
    tree = build_tree(LOG_LIFETIME, activation_epoch, parameter, leaf_hashes)
    root = get_root(tree)

    # Assemble and return the public and secret keys.
    pk = PublicKey(root=root, parameter=parameter)
    sk = SecretKey(
        prf_key=prf_key,
        tree=tree,
        parameter=parameter,
        activation_epoch=activation_epoch,
        num_active_epochs=num_active_epochs,
    )
    return pk, sk


def sign(sk: SecretKey, epoch: int, message: bytes) -> Signature:
    """
    Produces a digital signature for a given message at a specific epoch. This
    is a **randomized** algorithm.

    **CRITICAL**: This function must never be called twice with the same secret
    key and epoch for different messages, as this would compromise security.

    The signing process involves:
        1.  Repeatedly attempting to encode the message with fresh randomness
            (`rho`) until a valid codeword is found.
        2.  Computing the one-time signature, which consists of intermediate
            values from the secret hash chains, determined by the digits of
            the codeword.
        3.  Retrieving the Merkle authentication path for the given epoch.

    For the formal specification of this process, please refer to:
    - "Hash-Based Multi-Signatures for Post-Quantum Ethereum": https://eprint.iacr.org/2025/055
    - "Technical Note: LeanSig for Post-Quantum Ethereum": https://eprint.iacr.org/2025/1332
    - The canonical Rust implementation: https://github.com/b-wagn/hash-sig
    """
    # Check that the key is active for the requested signing epoch.
    active_range = range(
        sk.activation_epoch, sk.activation_epoch + sk.num_active_epochs
    )
    if epoch not in active_range:
        raise ValueError("Key is not active for the specified epoch.")

    # Find a valid message encoding by trying different randomness `rho`.
    codeword = None
    rho = None
    for _ in range(MAX_TRIES):
        current_rho = rand_rho()
        current_codeword = encode(sk.parameter, message, current_rho, epoch)
        if current_codeword is not None:
            codeword = current_codeword
            rho = current_rho
            break

    # If no valid encoding is found after many tries, signing fails.
    if codeword is None or rho is None:
        raise RuntimeError("Failed to find a valid message encoding.")

    # Compute the one-time signature hashes based on the codeword.
    ots_hashes: List[HashDigest] = []
    for chain_index, steps in enumerate(codeword):
        # Derive the secret start of the chain from the master key.
        start_digest = apply_prf(sk.prf_key, epoch, chain_index)
        # Walk the chain for the number of steps given by the codeword digit.
        ots_digest = hash_chain(
            parameter=sk.parameter,
            epoch=epoch,
            chain_index=chain_index,
            start_step=0,
            num_steps=steps,
            start_digest=start_digest,
        )
        ots_hashes.append(ots_digest)

    # Get the Merkle authentication path for the current epoch.
    path = get_path(sk.tree, epoch)

    # Assemble and return the final signature.
    return Signature(path=path, rho=rho, hashes=ots_hashes)


def verify(pk: PublicKey, epoch: int, message: bytes, sig: Signature) -> bool:
    r"""
    Verifies a digital signature against a public key, message, and epoch. This
    is a **deterministic** algorithm.

    This function is a placeholder. The complete verification logic is detailed
    below and will be implemented in a future update.

    ### Verification Algorithm

    1.  **Re-encode Message**: The verifier uses the randomness `rho` from the
        signature to re-compute the codeword $x = (x_1, \dots, x_v)$ from the
        message `m`.
        This includes calculating the checksum or checking the target sum.

    2.  **Reconstruct One-Time Public Key**: For each intermediate hash $y_i$
        in the signature, the verifier completes the corresponding hash chain.
        Since $y_i$ was computed with $x_i$ steps, the verifier applies the
        hash function an additional $w - 1 - x_i$ times to arrive at the
        one-time public key component $pk_{ep,i}$.

    3.  **Compute Merkle Leaf**: The verifier hashes the reconstructed one-time
        public key components to compute the expected Merkle leaf for `epoch`.

    4.  **Verify Merkle Path**: The verifier uses the `path` from the signature
        to compute a candidate Merkle root starting from the computed leaf.
        Verification succeeds if and only if this candidate root matches the
        `root` in the `PublicKey`.

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
    # Re-encode the message using the randomness `rho` from the signature.
    #
    # If the encoding is invalid, the signature is invalid.
    codeword = encode(pk.parameter, message, sig.rho, epoch)
    if codeword is None:
        return False

    # Reconstruct the one-time public key (the list of chain endpoints).
    chain_ends: List[HashDigest] = []
    for chain_index, xi in enumerate(codeword):
        # The signature provides the hash value after `xi` steps.
        start_digest = sig.hashes[chain_index]
        # We must perform the remaining `BASE - 1 - xi` steps
        # to get to the end.
        num_steps_remaining = BASE - 1 - xi
        end_digest = hash_chain(
            parameter=pk.parameter,
            epoch=epoch,
            chain_index=chain_index,
            start_step=xi,
            num_steps=num_steps_remaining,
            start_digest=start_digest,
        )
        chain_ends.append(end_digest)

    # Verify the Merkle path. This function internally hashes `chain_ends`
    # to get the leaf node and then climbs the tree to recompute the root.
    return verify_path(
        parameter=pk.parameter,
        root=pk.root,
        position=epoch,
        leaf_parts=chain_ends,
        opening=sig.path,
    )
