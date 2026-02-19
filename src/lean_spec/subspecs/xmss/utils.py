"""Utility functions for the XMSS signature scheme."""

from ...types.uint import Uint64
from ..koalabear import Fp, P
from .rand import Rand
from .types import HashDigestList, HashDigestVector, HashTreeLayer


def get_padded_layer(
    rand: Rand, nodes: list[HashDigestVector], start_index: Uint64
) -> HashTreeLayer:
    """
    Pads a layer of nodes with random hashes to simplify tree construction.

    This helper enforces a crucial invariant: every active layer must start at an
    even index and end at an odd index. This guarantees that every node within
    the layer can be neatly paired with a sibling (a left child with a right
    child), which dramatically simplifies the parent generation logic by
    removing the need to handle edge cases.

    Args:
        rand: Random generator for padding values.
        nodes: The list of active nodes for the current layer.
        start_index: The starting index of the first node in `nodes`.

    Returns:
        A new `HashTreeLayer` with the necessary padding applied.
    """
    nodes_with_padding: list[HashDigestVector] = []
    end_index = start_index + Uint64(len(nodes)) - Uint64(1)

    # Prepend random padding if the layer starts at an odd index.
    if start_index % Uint64(2) == Uint64(1):
        nodes_with_padding.append(rand.domain())

    # The actual start index of the padded layer is always the even
    # number at or immediately before the original start_index.
    actual_start_index = start_index - (start_index % Uint64(2))

    # Add the actual node content.
    nodes_with_padding.extend(nodes)

    # Append random padding if the layer ends at an even index.
    if end_index % Uint64(2) == Uint64(0):
        nodes_with_padding.append(rand.domain())

    return HashTreeLayer(
        start_index=actual_start_index, nodes=HashDigestList(data=nodes_with_padding)
    )


def int_to_base_p(value: int, num_limbs: int) -> list[Fp]:
    """
    Decomposes a large integer into a list of base-P field elements.

    This function performs a standard base conversion, where each "digit"
    is an element in the prime field F_p.

    Args:
        value: The integer to decompose.
        num_limbs: The desired number of output field elements (limbs).

    Returns:
        A list of `num_limbs` field elements representing the integer.
    """
    limbs: list[Fp] = []
    acc = value
    for _ in range(num_limbs):
        limbs.append(Fp(value=acc))
        acc //= P
    return limbs


def expand_activation_time(
    log_lifetime: int, desired_activation_slot: int, desired_num_active_slots: int
) -> tuple[int, int]:
    """
    Expands and aligns the activation time to top-bottom tree boundaries.

    For efficient top-bottom tree traversal, activation intervals must be aligned to
    `sqrt(LIFETIME)` boundaries. This function takes the user's desired activation
    interval and expands it to meet the following requirements:

    1.  **Start alignment**: Start slot is rounded down to a multiple of `sqrt(LIFETIME)`
    2.  **End alignment**: End slot is rounded up to a multiple of `sqrt(LIFETIME)`
    3.  **Minimum duration**: At least `2 * sqrt(LIFETIME)` slots (two bottom trees)
    4.  **Lifetime bounds**: Clamped to `[0, LIFETIME)`

    ### Algorithm

    Let `C = 2^(LOG_LIFETIME/2) = sqrt(LIFETIME)`

    1.  Align start downward: `start = desired_start & c_mask` where `c_mask = ~(C - 1)`
    2.  Round end upward: `end = (desired_end + C - 1) & c_mask`
    3.  Enforce minimum: `if end - start < 2*C: end = start + 2*C`
    4.  Clamp to bounds: Adjust if end exceeds `C^2 = LIFETIME`

    ### Example

    For `LOG_LIFETIME = 32` (LIFETIME = 2^32, C = 2^16 = 65536):
    - Request: slots [10000, 80000) → 70000 slots
    - Aligned: slots [0, 131072) → 131072 slots = 2 bottom trees

    Args:
        log_lifetime: The logarithm (base 2) of the total lifetime.
        desired_activation_slot: The user's requested first slot.
        desired_num_active_slots: The user's requested number of slots.

    Returns:
        A tuple `(start_bottom_tree_index, end_bottom_tree_index)` where:
        - `start_bottom_tree_index`: Index of the first bottom tree (0, 1, 2, ...)
        - `end_bottom_tree_index`: Index past the last bottom tree (exclusive)
        - Actual slots: `[start_index * C, end_index * C)`
    """
    # Calculate sqrt(LIFETIME) and the alignment mask.
    c = 1 << (log_lifetime // 2)  # C = 2^(LOG_LIFETIME/2)
    c_mask = ~(c - 1)  # Mask for rounding to multiples of C

    # Calculate the desired end slot.
    desired_end_slot = desired_activation_slot + desired_num_active_slots

    # Step 1: Align start downward to a multiple of C.
    start = desired_activation_slot & c_mask

    # Step 2: Round end upward to a multiple of C.
    end = (desired_end_slot + c - 1) & c_mask

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
    # Bottom tree i covers slots [i*C, (i+1)*C).
    start_bottom_tree_index = start // c
    end_bottom_tree_index = end // c

    return (start_bottom_tree_index, end_bottom_tree_index)
