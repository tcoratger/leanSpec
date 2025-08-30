"""
Defines the "Top Level" message hashing for the signature scheme.

This module implements the logic for hashing a message into the top layers of
a hypercube, which is the first step in the "Top Level Target Sum" encoding.

The process involves:
1.  Encoding the message, epoch, and randomness into field elements.
2.  Hashing these elements with Poseidon2 to produce a digest.
3.  Interpreting the digest as a large integer and mapping it to a unique
    vertex within the allowed top layers of the hypercube.
"""

from __future__ import annotations

from typing import List

from ..koalabear import Fp, P
from .constants import (
    BASE,
    DIMENSION,
    FINAL_LAYER,
    MSG_LEN_FE,
    POS_INVOCATIONS,
    POS_OUTPUT_LEN_PER_INV_FE,
    TWEAK_LEN_FE,
    TWEAK_PREFIX_MESSAGE,
)
from .hypercube import find_layer, get_hypercube_part_size, map_to_vertex
from .structures import Parameter, Randomness
from .tweak_hash import poseidon_compress


def encode_message(message: bytes) -> List[Fp]:
    """
    Encodes a 32-byte message into a list of field elements.

    The message bytes are interpreted as a single little-endian integer,
    which is then decomposed into its base-`P` representation.
    """
    # Interpret the little-endian bytes as a single large integer.
    acc = int.from_bytes(message, "little")

    # Decompose the integer into a list of field elements (base-P).
    elements: List[Fp] = []
    for _ in range(MSG_LEN_FE):
        elements.append(Fp(value=acc))
        acc //= P
    return elements


def encode_epoch(epoch: int) -> List[Fp]:
    """Encodes epoch and domain separator into a list of field elements."""
    # Combine the epoch and the message hash prefix into a single integer.
    acc = (epoch << 8) | TWEAK_PREFIX_MESSAGE.value

    # Decompose the integer into its base-P representation.
    elements: List[Fp] = []
    for _ in range(TWEAK_LEN_FE):
        elements.append(Fp(value=acc % P))
        acc //= P
    return elements


def _map_into_hypercube_part(field_elements: List[Fp]) -> List[int]:
    """
    Maps a list of field elements to a vertex in
    the top `FINAL_LAYER` layers.
    """
    # Combine field elements into one large integer (big-endian, base-P).
    acc = 0
    for fe in field_elements:
        acc = acc * P + fe.value

    # Reduce this integer modulo the size of the target domain.
    #
    # The target domain is the set of all vertices in layers 0..FINAL_LAYER.
    domain_size = get_hypercube_part_size(BASE, DIMENSION, FINAL_LAYER)
    acc %= domain_size

    # Find which layer the resulting index falls into, and its offset.
    layer, offset = find_layer(BASE, DIMENSION, acc)

    # Map the offset within the layer to a unique vertex.
    return map_to_vertex(BASE, DIMENSION, layer, offset)


def apply(
    parameter: Parameter,
    epoch: int,
    randomness: Randomness,
    message: bytes,
) -> List[int]:
    """
    Applies the full "Top Level" message hash procedure.

    This involves multiple invocations of Poseidon2, with the combined output
    mapped into a specific region of the hypercube.

    Args:
        parameter: The public parameter `P`.
        epoch: The current epoch.
        randomness: A random value `rho`.
        message: The 32-byte message to be hashed.

    Returns:
        A vertex in the hypercube, represented as a list of `DIMENSION` ints.
    """
    # Encode the message and epoch as field elements.
    message_fe = encode_message(message)
    epoch_fe = encode_epoch(epoch)

    # Iteratively call Poseidon2 to generate a long hash output.
    poseidon_outputs: List[Fp] = []
    for i in range(POS_INVOCATIONS):
        # Use the iteration number as a domain separator for each hash call.
        iteration_separator = [Fp(value=i)]

        # The input is: rho || P || epoch || message || iteration.
        combined_input = (
            randomness
            + parameter
            + epoch_fe
            + message_fe
            + iteration_separator
        )

        # Hash the combined input using Poseidon2 compression mode.
        iteration_output = poseidon_compress(
            combined_input, 24, POS_OUTPUT_LEN_PER_INV_FE
        )
        poseidon_outputs.extend(iteration_output)

    # Map the final list of field elements into a hypercube vertex.
    return _map_into_hypercube_part(poseidon_outputs)
