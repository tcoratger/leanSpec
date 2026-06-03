"""Tests for greedy attestation-proof selection."""

from lean_spec.spec.forks import AggregationBits, ValidatorIndex
from lean_spec.spec.forks.lstar.aggregation import select_proofs_for_coverage
from lean_spec.spec.forks.lstar.containers import SingleMessageAggregate
from lean_spec.spec.ssz import ByteList512KiB


def _proof(validator_indices: list[int], distinguishing_bytes: bytes) -> SingleMessageAggregate:
    """Build a proof covering the given validators.

    Args:
        validator_indices: Validators this proof attests for.
        distinguishing_bytes: Proof payload that makes this object distinct.
            Also drives the canonical-bytes tie-break.
    """
    return SingleMessageAggregate(
        participants=AggregationBits.from_indices([ValidatorIndex(i) for i in validator_indices]),
        proof=ByteList512KiB(data=distinguishing_bytes),
    )


class TestSelectProofsForCoverage:
    """Test greedy proof selection over single-message aggregate proofs."""

    def test_picks_proof_with_most_coverage_first(self) -> None:
        """The proof adding the most uncovered validators is selected first."""
        wide = _proof([1, 2, 3], b"\xaa")
        narrow = _proof([4], b"\xbb")

        selected, covered = select_proofs_for_coverage({wide, narrow})

        assert selected == [wide, narrow]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3, 4)}

    def test_stops_when_remaining_proof_adds_no_new_validator(self) -> None:
        """A proof whose validators are already covered is never selected."""
        full = _proof([1, 2, 3], b"\xaa")
        subset = _proof([1, 2], b"\xbb")

        selected, covered = select_proofs_for_coverage({full, subset})

        assert selected == [full]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3)}

    def test_partial_overlap_picks_by_marginal_coverage(self) -> None:
        """Greedy scores by new coverage, then takes the next proof for its remainder."""
        # The second proof shares validator 3, so its marginal gain is only {4}.
        first = _proof([1, 2, 3], b"\xaa")
        overlapping = _proof([3, 4], b"\xbb")

        selected, covered = select_proofs_for_coverage({first, overlapping})

        assert selected == [first, overlapping]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3, 4)}

    def test_priority_pool_is_consumed_before_fallback(self) -> None:
        """A priority proof is chosen first even when a fallback proof covers more."""
        priority = _proof([1, 2], b"\xaa")
        fallback = _proof([1, 2, 3, 4, 5], b"\xbb")

        selected, covered = select_proofs_for_coverage({priority}, {fallback})

        assert selected == [priority, fallback]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3, 4, 5)}

    def test_fallback_proof_already_covered_by_priority_is_skipped(self) -> None:
        """A fallback proof adds nothing when priority already covers its validators."""
        priority = _proof([1, 2, 3], b"\xaa")
        redundant_fallback = _proof([1, 2], b"\xbb")

        selected, covered = select_proofs_for_coverage({priority}, {redundant_fallback})

        assert selected == [priority]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3)}

    def test_exhausting_priority_pool_early_still_processes_fallback(self) -> None:
        """Stopping one pool early still lets the next pool contribute."""
        # The priority subset adds nothing after the full proof, ending that pool.
        # The fallback must still be consulted afterward.
        full = _proof([1, 2, 3], b"\xaa")
        subset = _proof([1, 2], b"\xbb")
        fallback = _proof([4], b"\xcc")

        selected, covered = select_proofs_for_coverage({full, subset}, {fallback})

        assert selected == [full, fallback]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3, 4)}

    def test_none_and_empty_pools_are_skipped(self) -> None:
        """None or empty pools contribute nothing and select nothing."""
        assert select_proofs_for_coverage(None) == ([], set())
        assert select_proofs_for_coverage(set()) == ([], set())
        assert select_proofs_for_coverage(None, None) == ([], set())

    def test_tie_break_prefers_larger_canonical_encoding(self) -> None:
        """Tied proofs resolve to the one with the larger canonical encoding."""
        # Both cover the same single validator, so only one can be chosen.
        # The winner must be fixed by canonical bytes, not set iteration order.
        smaller = _proof([1], b"\x01")
        larger = _proof([1], b"\x02")

        # Precondition: the second proof really does encode larger.
        # If this ever flips, the assertion below is meaningless, so pin it.
        assert larger.encode_bytes() > smaller.encode_bytes()

        selected, covered = select_proofs_for_coverage({smaller, larger})

        assert selected == [larger]
        assert covered == {ValidatorIndex(1)}
