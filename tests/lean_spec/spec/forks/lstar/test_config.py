"""Tests for lstar time-related constants."""

from lean_spec.spec.forks.lstar.config import (
    INTERVALS_PER_SLOT,
    MILLISECONDS_PER_INTERVAL,
    MILLISECONDS_PER_SLOT,
    SECONDS_PER_SLOT,
)
from lean_spec.spec.ssz import Uint64


class TestTimeConstants:
    """Test time-related constants and their relationships."""

    def test_time_constants_consistency(self) -> None:
        """Test that time constants are consistent with each other."""
        # MILLISECONDS_PER_SLOT should equal INTERVALS_PER_SLOT * MILLISECONDS_PER_INTERVAL
        expected_milliseconds_per_slot = INTERVALS_PER_SLOT * MILLISECONDS_PER_INTERVAL
        assert MILLISECONDS_PER_SLOT == expected_milliseconds_per_slot

        # MILLISECONDS_PER_SLOT should equal SECONDS_PER_SLOT * 1000
        assert MILLISECONDS_PER_SLOT == SECONDS_PER_SLOT * Uint64(1000)

        # All should be positive
        assert INTERVALS_PER_SLOT > Uint64(0)
        assert MILLISECONDS_PER_INTERVAL > Uint64(0)
        assert MILLISECONDS_PER_SLOT > Uint64(0)
        assert SECONDS_PER_SLOT > Uint64(0)

    def test_interval_slot_relationship(self) -> None:
        """Test the relationship between intervals and slots."""
        # Should have multiple intervals per slot
        assert INTERVALS_PER_SLOT >= Uint64(2)  # At least 2 intervals per slot

        # Test arithmetic with intervals
        total_intervals = Uint64(100)
        complete_slots = total_intervals // INTERVALS_PER_SLOT
        remaining_intervals = total_intervals % INTERVALS_PER_SLOT

        # Should be able to reconstruct total
        reconstructed = complete_slots * INTERVALS_PER_SLOT + remaining_intervals
        assert reconstructed == total_intervals
