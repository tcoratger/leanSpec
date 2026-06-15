"""Tests for the mocked prover's placeholder proof builder."""

import pytest

from consensus_testing.crypto_mode import AggregationProver


class TestPlaceholderProof:
    """Tests for AggregationProver._placeholder_proof."""

    def test_identical_arguments_produce_identical_bytes(self) -> None:
        """Two calls with equal arguments return byte-identical proofs."""
        first_proof = AggregationProver._placeholder_proof((b"block", 7, True, None))
        second_proof = AggregationProver._placeholder_proof((b"block", 7, True, None))
        assert first_proof == second_proof

    def test_length_framing_disambiguates_concatenation(self) -> None:
        """One two-byte argument differs from two one-byte arguments."""
        single_two_byte_argument = AggregationProver._placeholder_proof((b"ab",))
        two_one_byte_arguments = AggregationProver._placeholder_proof((b"a", b"b"))
        assert single_two_byte_argument != two_one_byte_arguments

    def test_true_is_distinguished_from_one(self) -> None:
        """A boolean True hashes differently from the integer one."""
        boolean_true_proof = AggregationProver._placeholder_proof((True,))
        integer_one_proof = AggregationProver._placeholder_proof((1,))
        assert boolean_true_proof != integer_one_proof

    def test_false_is_distinguished_from_zero(self) -> None:
        """A boolean False hashes differently from the integer zero."""
        boolean_false_proof = AggregationProver._placeholder_proof((False,))
        integer_zero_proof = AggregationProver._placeholder_proof((0,))
        assert boolean_false_proof != integer_zero_proof

    def test_unsupported_argument_type_raises(self) -> None:
        """An argument the framing cannot tag raises a typed error."""
        with pytest.raises(TypeError) as exception_info:
            AggregationProver._placeholder_proof(({1},))
        assert str(exception_info.value) == "unmockable prover argument of type set"
