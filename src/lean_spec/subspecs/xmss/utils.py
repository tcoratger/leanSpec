"""Cryptographic utilities and helper functions for the XMSS verification."""

from typing import List, Optional

from ..koalabear import Fp, P
from ..poseidon2 import PARAMS_16, PARAMS_24, permute
from .constants import (
    BASE,
    CAPACITY,
    CHUNK_SIZE,
    DIMENSION,
    HASH_LEN,
    MSG_HASH_LEN,
    MSG_LEN,
    PARAMETER_LEN,
    TARGET_SUM,
    TWEAK_LEN,
    TWEAK_PREFIX_CHAIN,
    TWEAK_PREFIX_MESSAGE,
    TWEAK_PREFIX_TREE,
)
from .structures import HashTreeOpening


def tweakable_hash(
    parameter: List[Fp], tweak: List[Fp], message: List[List[Fp]]
) -> List[Fp]:
    """
    A tweakable hash function using Poseidon2 for domain-separated hashing.

    Args:
        parameter: The public parameter `P`.
        tweak: A domain-separating value.
        message: The data to be hashed.

    Returns:
        The resulting hash digest as a list of field elements.
    """
    # Input Preparation
    #
    # Flatten the message (list of vectors -> single list of field elements).
    flat_message = [fe for sublist in message for fe in sublist]
    # Concatenate the parameter, tweak, and message into a single input.
    combined_input = parameter + tweak + flat_message

    # Hashing Logic
    #
    # The function selects a specific hashing mode based on the number of
    # message parts.

    # Case 1: Hashing a single value, as done within a hash chain.
    #
    # This uses Poseidon2 in compression mode (width of 16).
    if len(message) == 1:
        # Pad the input with zeros to match the permutation's required width.
        state = combined_input + [Fp(value=0)] * (16 - len(combined_input))
        # Apply the core cryptographic permutation to the state.
        permuted_state = permute(state, PARAMS_16)
        # Apply the feed-forward step:
        # We add the initial state back into the permuted state element-wise.
        result = [s + p for s, p in zip(permuted_state, state, strict=False)]
        # Truncate the full state to the desired hash output length and return.
        return result[:HASH_LEN]

    # Case 2: Hashing two values, typically for Merkle tree sibling nodes.
    #
    # This uses the wider Poseidon2 instance (width of 24) in compression mode.
    elif len(message) == 2:
        # Pad the input to the permutation's width of 24.
        state = combined_input + [Fp(value=0)] * (24 - len(combined_input))
        # Apply the core cryptographic permutation.
        permuted_state = permute(state, PARAMS_24)
        # Apply the feed-forward step.
        result = [s + p for s, p in zip(permuted_state, state, strict=False)]
        # Truncate the result to the desired hash output length and return.
        return result[:HASH_LEN]

    # Case 3: Hashing many values, such as a Merkle leaf from all chain ends.
    #
    # The sponge construction handles inputs larger than the state width.
    else:
        # The rate
        rate = 24 - CAPACITY

        # For domain separation, the capacity part of the state is initialized
        # with a hash of the input configuration.
        lengths = [
            Fp(value=PARAMETER_LEN),
            Fp(value=TWEAK_LEN),
            Fp(value=DIMENSION),
            Fp(value=HASH_LEN),
        ]
        # This is a recursive call with an input to generate the separator.
        capacity_value = tweakable_hash([], [], [lengths])[:CAPACITY]

        # Initialize the sponge state:
        # - the rate part is zero,
        # - the capacity part holds the separator.
        state = [Fp(value=0)] * 24
        state[rate:] = capacity_value

        # Pad the main input so its length is an even multiple of the rate.
        padding_len = (rate - (len(combined_input) % rate)) % rate
        padded_input = combined_input + [Fp(value=0)] * padding_len

        # Absorb the input in chunks of size `rate`.
        for i in range(0, len(padded_input), rate):
            chunk = padded_input[i : i + rate]
            # Add the current chunk into the rate part of the state.
            for j in range(rate):
                state[j] += chunk[j]
            # Apply the perm to the entire state to mix the absorbed data.
            state = permute(state, PARAMS_24)

        # Squeeze the final output from the rate part of the state.
        return state[:HASH_LEN]


def chain(
    parameter: List[Fp],
    epoch: int,
    chain_index: int,
    start_pos: int,
    steps: int,
    start_value: List[Fp],
) -> List[Fp]:
    """
    Computes `steps` iterations of a Winternitz-style hash chain.

    A hash chain is created by repeatedly applying a hash function:
        H(H(...H(start)))

    Each step uses a unique tweak to ensure that every hash computation in the
    entire system is unique.

    Args:
        parameter: The public parameter `P` for the hash function.
        epoch: The signature's epoch, used for tweaking.
        chain_index: The index of this specific chain (from 0 to DIMENSION-1).
        start_pos: The starting position within the chain.
        steps: The number of times to apply the hash function.
        start_value: The initial hash value to begin the chain from.

    Returns:
        The final hash value after `steps` iterations.
    """
    # Initialize the iterative hash value with the provided start_value.
    current_value = start_value
    # Loop `steps` times to perform the chained hashing.
    for i in range(steps):
        # The position in the chain is its starting offset + the current step.
        pos_in_chain = start_pos + i
        # Pack the tweak's components into a single integer.
        packed_data = (epoch << 24) | (chain_index << 16) | pos_in_chain
        # Create the domain-separating tweak for this specific hash operation.
        tweak = [TWEAK_PREFIX_CHAIN, Fp(value=packed_data)]
        # Apply the hash function to get the next value in the chain.
        current_value = tweakable_hash(parameter, tweak, [current_value])
    # Return the final value after all iterations.
    return current_value


def encode(
    parameter: List[Fp], message: bytes, rho: List[Fp], epoch: int
) -> Optional[List[int]]:
    """
    Performs the Target Sum message encoding.

    This function deterministically converts a message into a sequence of small
    integers (a "codeword"). The encoding is only considered valid if the sum
    of these integers equals a predefined `TARGET_SUM`.

    Args:
        parameter: The public parameter `P` for the hash function.
        message: The 32-byte message to encode.
        rho: The randomness used for this encoding.
        epoch: The signature's epoch, used for tweaking.

    Returns:
        A list of integers representing the codeword if the sum is correct,
        otherwise `None`.
    """
    # Prepare inputs for hashing.
    msg_int = int.from_bytes(message, "little")
    msg_fes: List[Fp] = []
    for _ in range(MSG_LEN):
        msg_fes.append(Fp(value=msg_int % P))
        msg_int //= P
    tweak: List[Fp] = [TWEAK_PREFIX_MESSAGE, Fp(value=epoch)]

    # Hash all inputs to create a digest.
    hash_input: List[Fp] = rho + parameter + tweak + msg_fes
    state = hash_input + [Fp(value=0)] * (24 - len(hash_input))
    permuted = permute(state, PARAMS_24)
    hash_output = [s + p for s, p in zip(permuted, state, strict=False)][
        :MSG_HASH_LEN
    ]

    # Decode the hash digest into the codeword chunks.
    digest_int = 0
    for fe in reversed(hash_output):
        digest_int = (digest_int * P) + fe.value

    chunks: List[int] = [
        (digest_int >> (i * CHUNK_SIZE)) & (BASE - 1) for i in range(DIMENSION)
    ]

    # Check if the sum of the chunks equals the required target sum.
    if sum(chunks) == TARGET_SUM:
        # If the sum is correct, the encoding is valid.
        return chunks
    else:
        # Otherwise, the encoding fails for this randomness `rho`.
        return None


def hash_tree_verify(
    parameter: List[Fp],
    root: List[Fp],
    epoch: int,
    leaf_content: List[List[Fp]],
    path: HashTreeOpening,
) -> bool:
    """
    Verifies a Merkle path from a leaf's content to the root.

    This function first hashes the raw leaf content to get the level 0 node,
    then reconstructs the Merkle root by iteratively hashing this node with
    the provided sibling nodes up the tree.

    Args:
        parameter: The public parameter `P` for the hash function.
        root: The known, trusted Merkle root from the public key.
        epoch: The index of the leaf in the tree.
        leaf_content: The pre-image of the leaf node (e.g., the list of chain ends).
        path: The authentication path containing the sibling hashes.

    Returns:
        - `True` if the computed root matches the provided root,
        - `False` otherwise.
    """
    # Initial Checks
    #
    # The depth of the tree is determined by the number of siblings in path.
    depth = len(path.siblings)
    # The epoch must be a valid index for a tree of this depth.
    assert 0 <= epoch < (1 << depth), "Epoch is out of range for this path"

    # Compute Leaf Node Hash
    #
    # The first step is to hash the provided leaf content to get the actual
    # leaf node that exists at level 0 of the Merkle tree.
    #
    # The tweak identifies this as a hash at level 0, position `epoch`.
    leaf_tweak_packed = (0 << 32) | epoch
    leaf_tweak = [TWEAK_PREFIX_TREE, Fp(value=leaf_tweak_packed)]
    current_hash = tweakable_hash(parameter, leaf_tweak, leaf_content)

    # Iteratively Compute Root
    #
    # Start with the leaf's index for the iterative process.
    current_index = epoch
    # Iterate up the tree, from the bottom (level 0) to the root.
    for i, sibling_hash in enumerate(path.siblings):
        # Determine the hash order based on whether the current node is a
        # left (even index) or right (odd index) child.
        if current_index % 2 == 0:
            # For a left child, the order is H(current, sibling).
            children = [current_hash, sibling_hash]
        else:
            # For a right child, the order is H(sibling, current).
            children = [sibling_hash, current_hash]

        # Move up to the parent's index for the next level.
        current_index //= 2

        # The level of the PARENT node we are about to compute.
        parent_level = i + 1

        # Create the unique tweak for this specific parent node, using its
        # level and its index within that level.
        parent_tweak_packed = (parent_level << 32) | current_index
        tweak = [TWEAK_PREFIX_TREE, Fp(value=parent_tweak_packed)]

        # Compute the parent's hash.
        current_hash = tweakable_hash(parameter, tweak, children)

    # Final Comparison
    #
    # After the loop, the computed hash should equal the public root.
    return current_hash == root
