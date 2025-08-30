"""
Tests for the "Top Level" message hashing and encoding logic.
"""

from typing import List

from lean_spec.subspecs.koalabear import Fp, P
from lean_spec.subspecs.xmss.constants import (
    BASE,
    DIMENSION,
    FINAL_LAYER,
    MESSAGE_LENGTH,
    MSG_LEN_FE,
    TWEAK_LEN_FE,
    TWEAK_PREFIX_MESSAGE,
)
from lean_spec.subspecs.xmss.message_hash import (
    apply,
    encode_epoch,
    encode_message,
)
from lean_spec.subspecs.xmss.utils import rand_parameter, rand_rho


def test_encode_message() -> None:
    """Tests `encode_message` with various message patterns."""
    # All-zero message
    msg_zeros = b"\x00" * MESSAGE_LENGTH
    encoded_zeros = encode_message(msg_zeros)
    assert len(encoded_zeros) == MSG_LEN_FE
    assert all(fe.value == 0 for fe in encoded_zeros)

    # All-max message (0xff)
    msg_max = b"\xff" * MESSAGE_LENGTH
    acc = int.from_bytes(msg_max, "little")
    expected_max: List[Fp] = []
    for _ in range(MSG_LEN_FE):
        expected_max.append(Fp(value=acc))
        acc //= P
    assert encode_message(msg_max) == expected_max


def test_encode_epoch() -> None:
    """
    Tests `encode_epoch` for correctness and injectivity.
    """
    # Test specific values from the Rust reference tests.
    test_epochs = [0, 42, 2**32 - 1]
    for epoch in test_epochs:
        acc = (epoch << 8) | TWEAK_PREFIX_MESSAGE.value
        expected: List[Fp] = []
        for _ in range(TWEAK_LEN_FE):
            expected.append(Fp(value=acc))
            acc //= P
        assert encode_epoch(epoch) == expected

    # Test for injectivity. It is highly unlikely for a collision to occur
    # with a few random samples if the encoding is injective.
    num_trials = 1000
    seen_encodings: set[tuple[Fp, ...]] = set()
    for i in range(num_trials):
        encoding = tuple(encode_epoch(i))
        assert encoding not in seen_encodings
        seen_encodings.add(encoding)


def test_apply_output_is_in_correct_hypercube_part() -> None:
    """
    Tests that the output of `apply` is a valid vertex that lies within
    the top `FINAL_LAYER` layers of the hypercube.
    """
    # Setup with random inputs.
    parameter = rand_parameter()
    epoch = 313
    randomness = rand_rho()
    message = b"\xaa" * MESSAGE_LENGTH

    # Call the message hash function.
    vertex = apply(parameter, epoch, randomness, message)

    # Verify the properties of the output vertex.
    #
    # The length of the vertex must be equal to the hypercube's dimension.
    assert len(vertex) == DIMENSION
    # Each coordinate must be smaller than the base `w`.
    assert all(0 <= coord < BASE for coord in vertex)

    # Check that the vertex lies in the correct set of layers.
    #
    # By definition, a vertex is in layer `d` if `d = v*(w-1) - sum(coords)`.
    #
    # We require `d <= FINAL_LAYER`.
    #
    # This is equivalent to `sum(coords) >= v*(w-1) - FINAL_LAYER`.
    coord_sum = sum(vertex)
    min_required_sum = (BASE - 1) * DIMENSION - FINAL_LAYER

    assert coord_sum >= min_required_sum, "Vertex is not in the top layers"
