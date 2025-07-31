"""
A minimal Python specification for the Poseidon2 permutation.

The design is based on the paper "Poseidon2: A Faster Version of the Poseidon
Hash Function" (https://eprint.iacr.org/2023/323).
"""

from itertools import chain
from typing import List, NamedTuple

from ..koalabear.field import Fp

# =================================================================
# Poseidon2 Parameter Definitions
# =================================================================

S_BOX_DEGREE = 3
"""
The S-box exponent `d`.

For fields where `gcd(d, p-1) = 1`, `x -> x^d` is a permutation.

For KoalaBear, `d=3` is chosen for its low degree.
"""


class Poseidon2Params(NamedTuple):
    """
    Encapsulates all necessary parameters for a specific Poseidon2 instance.

    This structure holds the configuration for a given state width, including
    the number of rounds and the constants for the internal linear layer.

    Attributes:
        WIDTH (int): The size of the state (t).

        ROUNDS_F (int): The total number of "full" rounds, where the S-box is
        applied to the entire state.

        ROUNDS_P (int): The number of "partial" rounds, where the S-box is
        applied to only the first element of the state.

        INTERNAL_DIAG_VECTORS (List[Fp]): The diagonal vectors for the
        efficient internal linear layer matrix (M_I).
    """

    WIDTH: int
    ROUNDS_F: int
    ROUNDS_P: int
    INTERNAL_DIAG_VECTORS: List[Fp]


def _generate_round_constants(params: Poseidon2Params) -> List[Fp]:
    """
    Generates a deterministic list of round constants for the permutation.

    Round constants are added in each round to break symmetries and prevent
    attacks like slide or interpolation attacks.

    Args:
        params: The object defining the permutation's configuration.

    Returns:
        A list of Fp elements to be used as round constants.
    """
    # The total number of constants needed for the entire permutation.
    #
    # This is the sum of constants for all full rounds and all partial rounds.
    #   - Full rounds require `WIDTH` constants each
    #   (one for each state element).
    #   - Partial rounds require 1 constant each
    #   (for the first state element).
    total_constants = (params.ROUNDS_F * params.WIDTH) + params.ROUNDS_P

    # For the specification, we generate the constants as a deterministic d
    # sequence of integers.
    #
    # This is sufficient to define the algorithm's mechanics.
    #
    # Real-world implementations would use constants generated from a secure,
    # pseudo-random source.
    return [Fp(value=i) for i in range(total_constants)]


# Parameters for WIDTH = 16
PARAMS_16 = Poseidon2Params(
    WIDTH=16,
    ROUNDS_F=8,
    ROUNDS_P=20,
    INTERNAL_DIAG_VECTORS=[
        Fp(value=-2),
        Fp(value=1),
        Fp(value=2),
        Fp(value=1) / Fp(value=2),
        Fp(value=3),
        Fp(value=4),
        Fp(value=-1) / Fp(value=2),
        Fp(value=-3),
        Fp(value=-4),
        Fp(value=1) / Fp(value=2**8),
        Fp(value=1) / Fp(value=8),
        Fp(value=1) / Fp(value=2**24),
        Fp(value=-1) / Fp(value=2**8),
        Fp(value=-1) / Fp(value=8),
        Fp(value=-1) / Fp(value=16),
        Fp(value=-1) / Fp(value=2**24),
    ],
)

# Parameters for WIDTH = 24
PARAMS_24 = Poseidon2Params(
    WIDTH=24,
    ROUNDS_F=8,
    ROUNDS_P=23,
    INTERNAL_DIAG_VECTORS=[
        Fp(value=-2),
        Fp(value=1),
        Fp(value=2),
        Fp(value=1) / Fp(value=2),
        Fp(value=3),
        Fp(value=4),
        Fp(value=-1) / Fp(value=2),
        Fp(value=-3),
        Fp(value=-4),
        Fp(value=1) / Fp(value=2**8),
        Fp(value=1) / Fp(value=4),
        Fp(value=1) / Fp(value=8),
        Fp(value=1) / Fp(value=16),
        Fp(value=1) / Fp(value=32),
        Fp(value=1) / Fp(value=64),
        Fp(value=1) / Fp(value=2**24),
        Fp(value=-1) / Fp(value=2**8),
        Fp(value=-1) / Fp(value=8),
        Fp(value=-1) / Fp(value=16),
        Fp(value=-1) / Fp(value=32),
        Fp(value=-1) / Fp(value=64),
        Fp(value=-1) / Fp(value=2**7),
        Fp(value=-1) / Fp(value=2**9),
        Fp(value=-1) / Fp(value=2**24),
    ],
)

# Base 4x4 matrix, used in the external linear layer.
M4_MATRIX = [
    [Fp(value=2), Fp(value=3), Fp(value=1), Fp(value=1)],
    [Fp(value=1), Fp(value=2), Fp(value=3), Fp(value=1)],
    [Fp(value=1), Fp(value=1), Fp(value=2), Fp(value=3)],
    [Fp(value=3), Fp(value=1), Fp(value=1), Fp(value=2)],
]

# =================================================================
# Linear Layers
# =================================================================


def _apply_m4(chunk: List[Fp]) -> List[Fp]:
    """
    Applies the 4x4 M4 MDS matrix to a 4-element chunk of the state.
    This is a helper function for the external linear layer.

    Args:
        chunk: A list of 4 Fp elements.

    Returns:
        The transformed 4-element chunk.
    """
    # Initialize the result vector with zeros.
    result = [Fp(value=0)] * 4
    # Perform standard matrix-vector multiplication.
    for i in range(4):
        for j in range(4):
            result[i] += M4_MATRIX[i][j] * chunk[j]
    return result


def external_linear_layer(state: List[Fp], width: int) -> List[Fp]:
    """
    Applies the external linear layer (M_E).

    This layer provides strong diffusion across the entire state and is used
    in the full rounds. For a state of size t=4k, it's constructed from the
    base M4 matrix to form a larger circulant-like matrix, which is efficient
    while ensuring that a change in any single element affects all other
    elements after application.

    The process follows Appendix B of the paper.

    Args:
        state: The current state vector.
        width: The width `t` of the state.

    Returns:
        The state vector after applying the external linear layer.
    """
    # Apply the M4 matrix to each 4-element chunk of the state.
    #
    # This provides strong local diffusion within each block.
    state_after_m4 = list(
        chain.from_iterable(
            _apply_m4(state[i : i + 4]) for i in range(0, width, 4)
        )
    )

    # Apply the outer circulant structure for global diffusion.
    #
    # We precompute the four sums of elements at the same offset in each chunk.
    # For each k in 0..4:
    #     sums[k] = state[k] + state[4 + k] + state[8 + k] + ... up to width
    sums = [
        sum((state_after_m4[j + k] for j in range(0, width, 4)), Fp(value=0))
        for k in range(4)
    ]

    # Add the corresponding sum to each element of the state.
    state_after_circulant = [
        s + sums[i % 4] for i, s in enumerate(state_after_m4)
    ]

    return state_after_circulant


def internal_linear_layer(
    state: List[Fp], params: Poseidon2Params
) -> List[Fp]:
    """
    Applies the internal linear layer (M_I).

    This layer is used during partial rounds and is optimized for speed. Its
    matrix is constructed as M_I = J + D, where J is the all-ones matrix and D
    is a diagonal matrix. This structure allows the matrix-vector product to be
    computed in O(t) time instead of O(t^2), as M_I * s = J*s + D*s.
    The term J*s is a vector where each element is the sum of
    all elements in s.

    Args:
        state: The current state vector.
        params: The Poseidon2Params object containing the diagonal vectors.

    Returns:
        The state vector after applying the internal linear layer.
    """
    # Calculate the sum of all elements in the state vector.
    s_sum = sum(state, Fp(value=0))
    # For each element s_i, compute s_i' = d_i * s_i + sum(s).
    # This is the efficient computation of (J + D)s.
    new_state = [
        s * d + s_sum
        for s, d in zip(state, params.INTERNAL_DIAG_VECTORS, strict=False)
    ]
    return new_state


# =================================================================
# Core Permutation
# =================================================================


def permute(state: List[Fp], params: Poseidon2Params) -> List[Fp]:
    """
    Performs the full Poseidon2 permutation on the given state.

    The permutation follows the structure:
    Initial Layer -> Full Rounds -> Partial Rounds -> Full Rounds

    Args:
        state: A list of Fp elements representing the current state.
        params: The object defining the permutation's configuration.

    Returns:
        The new state after applying the permutation.
    """
    # Ensure the input state has the correct dimensions.
    if len(state) != params.WIDTH:
        raise ValueError(f"Input state must have length {params.WIDTH}")

    # Generate the deterministic round constants for this parameter set.
    round_constants = _generate_round_constants(params)
    # The number of full rounds is split between the beginning and end.
    half_rounds_f = params.ROUNDS_F // 2
    # Initialize index for accessing the flat list of round constants.
    const_idx = 0

    # 1. Initial Linear Layer
    #
    # Another linear layer is applied at the start to prevent certain algebraic
    # attacks by ensuring the permutation begins with a diffusion layer.
    state = external_linear_layer(list(state), params.WIDTH)

    # 2. First Half of Full Rounds (R_F / 2)
    for _r in range(half_rounds_f):
        # Add round constants to the entire state.
        state = [
            s + round_constants[const_idx + i] for i, s in enumerate(state)
        ]
        const_idx += params.WIDTH
        # Apply the S-box (x -> x^d) to the full state.
        state = [s**S_BOX_DEGREE for s in state]
        # Apply the external linear layer for diffusion.
        state = external_linear_layer(state, params.WIDTH)

    # 3. Partial Rounds (R_P)
    for _r in range(params.ROUNDS_P):
        # Add a single round constant to the first state element.
        state[0] += round_constants[const_idx]
        const_idx += 1
        # Apply the S-box to the first state element only.
        #
        # This is the main optimization of the Hades design.
        state[0] = state[0] ** S_BOX_DEGREE
        # Apply the internal linear layer.
        state = internal_linear_layer(state, params)

    # 4. Second Half of Full Rounds (R_F / 2)
    for _r in range(half_rounds_f):
        # Add round constants to the entire state.
        state = [
            s + round_constants[const_idx + i] for i, s in enumerate(state)
        ]
        const_idx += params.WIDTH
        # Apply the S-box to the full state.
        state = [s**S_BOX_DEGREE for s in state]
        # Apply the external linear layer for diffusion.
        state = external_linear_layer(state, params.WIDTH)

    return state
