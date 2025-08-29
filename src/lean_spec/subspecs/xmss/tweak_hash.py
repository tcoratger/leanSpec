"""
Defines the Tweakable Hash function using Poseidon2.

This module implements the core hashing logic for the XMSS scheme, including:
1.  **Tweak Encoding**: Domain-separating different hash usages (chains/trees).
2.  **Poseidon2 Compression**: Hashing fixed-size inputs.
3.  **Poseidon2 Sponge**: Hashing variable-length inputs (e.g., leaf nodes).
4.  **A unified `apply` function** that dispatches to the correct mode.
5.  **A `chain` utility** to perform repeated hashing for WOTS chains.
"""

from __future__ import annotations

import secrets
from itertools import chain
from typing import List, Union

from pydantic import Field

from lean_spec.types.base import StrictBaseModel

from ..koalabear import Fp, P
from ..poseidon2.permutation import PARAMS_16, PARAMS_24, permute
from .constants import (
    CAPACITY,
    DIMENSION,
    HASH_LEN_FE,
    PARAMETER_LEN,
    TWEAK_LEN_FE,
    TWEAK_PREFIX_CHAIN,
    TWEAK_PREFIX_TREE,
)
from .structures import HashDigest, Parameter


class TreeTweak(StrictBaseModel):
    """A tweak used for hashing nodes within the Merkle tree."""

    level: int = Field(ge=0, description="The level in the Merkle tree.")
    index: int = Field(ge=0, description="The node's index within that level.")


class ChainTweak(StrictBaseModel):
    """A tweak used for hashing elements within a WOTS+ hash chain."""

    epoch: int = Field(ge=0, description="The signature epoch.")
    chain_index: int = Field(ge=0, description="The index of the hash chain.")
    step: int = Field(ge=0, description="The step number within the chain.")


Tweak = Union[TreeTweak, ChainTweak]
"""A type alias representing any valid tweak structure."""


def encode_tweak(tweak: Tweak, length: int) -> List[Fp]:
    """
    Encodes a tweak structure into a list of field elements for hashing.

    This function packs the tweak's integer components into a single large
    integer, then performs a base-`P` decomposition to get field elements.
    This ensures a unique and deterministic mapping from any tweak to a format
    consumable by the hash function.

    The packing scheme is designed to be injective:
    - `TreeTweak`: `(level << 40) | (index << 8) | TWEAK_PREFIX_TREE`
    - `ChainTweak`: `(epoch << 24) | (chain_index << 16)
      | (step << 8) | TWEAK_PREFIX_CHAIN`

    Args:
        tweak: The `TreeTweak` or `ChainTweak` object.
        length: The desired number of field elements in the output list.

    Returns:
        A list of `length` field elements representing the encoded tweak.
    """
    # Pack the tweak's integer fields into a single large integer.
    #
    # A unique prefix is included for domain separation.
    if isinstance(tweak, TreeTweak):
        acc = (
            (tweak.level << 40) | (tweak.index << 8) | TWEAK_PREFIX_TREE.value
        )
    else:
        acc = (
            (tweak.epoch << 24)
            | (tweak.chain_index << 16)
            | (tweak.step << 8)
            | TWEAK_PREFIX_CHAIN.value
        )

    # Decompose the large integer `acc` into a list of field elements.
    # This is a standard base-P decomposition.
    #
    # The number of elements is determined by the `length` parameter.
    elements: List[Fp] = []
    for _ in range(length):
        elements.append(Fp(value=acc))
        acc //= P
    return elements


def poseidon_compress(
    input_vec: List[Fp], width: int, output_len: int
) -> HashDigest:
    """
    A low-level wrapper for Poseidon2 in compression mode.

    It computes: `Truncate(Permute(padded_input) + padded_input)`.

    Args:
        input_vec: The input data to be hashed.
        width: The state width of the Poseidon2 permutation (16 or 24).
        output_len: The number of field elements in the output digest.

    Returns:
        A hash digest of `output_len` field elements.
    """
    # Select the correct permutation parameters based on the state width.
    params = PARAMS_16 if width == 16 else PARAMS_24

    # Create a fixed-width buffer and copy the input, padding with zeros.
    padded_input = [Fp(value=0)] * width
    padded_input[: len(input_vec)] = input_vec

    # Apply the Poseidon2 permutation.
    permuted_state = permute(padded_input, params)

    # Apply the feed-forward step, adding the input back element-wise.
    final_state = [
        p + i for p, i in zip(permuted_state, padded_input, strict=True)
    ]

    # Truncate the state to the desired output length and return.
    return final_state[:output_len]


def _poseidon_safe_domain_separator(
    lengths: List[int], capacity_len: int
) -> List[Fp]:
    """
    Computes a domain separator for the sponge construction.

    This function hashes a list of length parameters to create a unique
    "capacity value" that configures the sponge for a specific hashing task.

    Args:
        lengths: A list of integer parameters defining the hash context.
        capacity_len: The desired length of the output capacity value.

    Returns:
        A list of `capacity_len` field elements.
    """
    # Pack the length parameters into a single large integer.
    acc = 0
    for length in lengths:
        acc = (acc << 32) | length

    # Decompose the integer into a list of 24 field elements for hashing.
    #
    # 24 is the fixed input width for this specific domain separation hash.
    input_vec: List[Fp] = []
    for _ in range(24):
        input_vec.append(Fp(value=acc))
        acc //= P

    # Compress the decomposed vector to produce the capacity value.
    return poseidon_compress(input_vec, 24, capacity_len)


def _poseidon_sponge(
    input_vec: List[Fp], capacity_value: List[Fp], output_len: int
) -> HashDigest:
    """
    A low-level wrapper for Poseidon2 in sponge mode.

    Args:
        input_vec: The input data of arbitrary length.
        capacity_value: A domain-separating value.
        output_len: The number of field elements in the output digest.

    Returns:
        A hash digest of `output_len` field elements.
    """
    # Use the width-24 permutation for the sponge.
    params = PARAMS_24
    width = params.width
    rate = width - len(capacity_value)

    # Pad the input vector to be an exact multiple of the rate.
    num_extra = (rate - (len(input_vec) % rate)) % rate
    padded_input = input_vec + [Fp(value=0)] * num_extra

    # Initialize the state with the capacity value.
    state = [Fp(value=0)] * width
    state[rate:] = capacity_value

    # Absorb the input in rate-sized chunks.
    for i in range(0, len(padded_input), rate):
        chunk = padded_input[i : i + rate]
        # Add the chunk to the rate part of the state.
        for j in range(rate):
            state[j] += chunk[j]
        # Apply the permutation.
        state = permute(state, params)

    # Squeeze the output until enough elements have been generated.
    output: HashDigest = []
    while len(output) < output_len:
        output.extend(state[:rate])
        state = permute(state, params)

    # Truncate to the final output length and return.
    return output[:output_len]


def apply(
    parameter: Parameter, tweak: Tweak, message_parts: List[HashDigest]
) -> HashDigest:
    """
    Applies the tweakable Poseidon2 hash function to a message.

    This function serves as the main entry point for all hashing operations.
    It automatically selects the correct Poseidon2 mode (compression or sponge)
    based on the number of message parts provided.

    Args:
        parameter: The public parameter `P` for the hash function.
        tweak: A `TreeTweak` or `ChainTweak` for domain separation.
        message_parts: A list of one or more hash digests to be hashed.

    Returns:
        A new hash digest of `HASH_LEN_FE` field elements.
    """
    # Encode the tweak structure into field elements.
    encoded_tweak = encode_tweak(tweak, TWEAK_LEN_FE)

    if len(message_parts) == 1:
        # Case 1: Hashing a single digest (used in hash chains).
        #
        # We use the efficient width-16 compression mode.
        input_vec = parameter + encoded_tweak + message_parts[0]
        return poseidon_compress(input_vec, 16, HASH_LEN_FE)

    elif len(message_parts) == 2:
        # Case 2: Hashing two digests (used for Merkle tree nodes).
        #
        # We use the width-24 compression mode.
        input_vec = (
            parameter + encoded_tweak + message_parts[0] + message_parts[1]
        )
        return poseidon_compress(input_vec, 24, HASH_LEN_FE)

    else:
        # Case 3: Hashing many digests (used for the Merkle tree leaf).
        #
        # We use the robust sponge mode.
        # First, flatten the list of message parts into a single vector.
        flattened_message = list(chain.from_iterable(message_parts))
        input_vec = parameter + encoded_tweak + flattened_message

        # Create a domain separator based on the dimensions of the input.
        lengths = [PARAMETER_LEN, TWEAK_LEN_FE, DIMENSION, HASH_LEN_FE]
        capacity_value = _poseidon_safe_domain_separator(lengths, CAPACITY)

        return _poseidon_sponge(input_vec, capacity_value, HASH_LEN_FE)


def hash_chain(
    parameter: Parameter,
    epoch: int,
    chain_index: int,
    start_step: int,
    num_steps: int,
    start_digest: HashDigest,
) -> HashDigest:
    """
    Performs repeated hashing to traverse a WOTS+ hash chain.

    Args:
        parameter: The public parameter `P`.
        epoch: The signature epoch.
        chain_index: The index of the hash chain.
        start_step: The starting step number in the chain.
        num_steps: The number of hashing steps to perform.
        start_digest: The digest to begin hashing from.

    Returns:
        The final hash digest after `num_steps` applications.
    """
    current_digest = start_digest
    for i in range(num_steps):
        # Create a unique tweak for the current position in the chain.
        tweak = ChainTweak(
            epoch=epoch, chain_index=chain_index, step=start_step + i + 1
        )
        # Apply the hash function.
        current_digest = apply(parameter, tweak, [current_digest])
    return current_digest


def rand_parameter() -> Parameter:
    """
    Generates a cryptographically secure random public parameter.

    Returns:
        A new, randomly generated list of `PARAMETER_LEN` field elements.
    """
    # For each element in the list, generate a secure random integer
    # in the range [0, P-1] and convert it to a field element.
    # `secrets.randbelow(P)` is used to avoid modulo bias.
    return [Fp(value=secrets.randbelow(P)) for _ in range(PARAMETER_LEN)]


def rand_domain() -> HashDigest:
    """
    Generates a cryptographically secure random hash digest.

    This is used for testing or as a starting point for hash chains
    where a random seed is required.

    Returns:
        A new, randomly generated list of `HASH_LEN_FE` field elements.
    """
    # For each element in the list, generate a secure random integer
    # in the range [0, P-1] and convert it to a field element.
    # `secrets.randbelow(P)` is used to avoid modulo bias.
    return [Fp(value=secrets.randbelow(P)) for _ in range(HASH_LEN_FE)]
