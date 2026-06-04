"""Tests for time advancement and interval ticking."""

from lean_spec.spec.forks import Interval
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.config import INTERVALS_PER_SLOT, MILLISECONDS_PER_INTERVAL
from lean_spec.spec.forks.lstar.spec import LstarSpec


class TestOnTick:
    """Test Store on_tick functionality."""

    def test_on_tick_basic(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test basic on_tick."""
        initial_time = sample_store.time
        # 200 seconds = 200*1000/800 = 250 intervals
        target_interval = Interval(200 * 1000 // int(MILLISECONDS_PER_INTERVAL))

        sample_store, _ = spec.on_tick(sample_store, target_interval, has_proposal=True)

        # Time should advance
        assert sample_store.time > initial_time

    def test_on_tick_no_proposal(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test on_tick without proposal."""
        initial_time = sample_store.time
        # 100 seconds = 125 intervals
        target_interval = Interval(100 * 1000 // int(MILLISECONDS_PER_INTERVAL))

        sample_store, _ = spec.on_tick(sample_store, target_interval, has_proposal=False)

        # Time should still advance
        assert sample_store.time >= initial_time

    def test_on_tick_already_current(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test on_tick when already at target time (should be no-op)."""
        initial_time = sample_store.time

        sample_store, _ = spec.on_tick(sample_store, Interval(initial_time), has_proposal=True)

        # No-op: target equals current time
        assert sample_store.time == initial_time

    def test_on_tick_small_increment(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test on_tick with small interval increment."""
        initial_time = sample_store.time
        target_interval = Interval(int(initial_time) + 1)

        sample_store, _ = spec.on_tick(sample_store, target_interval, has_proposal=False)

        # Should advance by exactly one interval
        assert sample_store.time == target_interval


class TestIntervalTicking:
    """Test interval-based time ticking."""

    def test_tick_interval_basic(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test basic interval ticking."""
        initial_time = sample_store.time

        # Tick one interval forward
        sample_store, _ = spec.tick_interval(sample_store, has_proposal=False)

        # Time should advance by one interval
        assert sample_store.time == initial_time + Interval(1)

    def test_tick_interval_with_proposal(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test interval ticking with proposal."""
        initial_time = sample_store.time

        sample_store, _ = spec.tick_interval(sample_store, has_proposal=True)

        # Time should advance
        assert sample_store.time == initial_time + Interval(1)

    def test_tick_interval_sequence(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test sequence of interval ticks."""
        initial_time = sample_store.time

        # Tick multiple intervals
        for i in range(5):
            sample_store, _ = spec.tick_interval(sample_store, has_proposal=(i % 2 == 0))

        # Should have advanced by 5 intervals
        assert sample_store.time == initial_time + Interval(5)

    def test_tick_interval_actions_by_phase(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test different actions performed based on interval phase."""
        # Reset store to known state
        initial_time = Interval(0)
        object.__setattr__(sample_store, "time", initial_time)

        # Tick through a complete slot cycle
        for interval in range(int(INTERVALS_PER_SLOT)):
            has_proposal = interval == 0  # Proposal only in first interval
            sample_store, _ = spec.tick_interval(sample_store, has_proposal=has_proposal)

            current_interval = Interval(int(sample_store.time) % int(INTERVALS_PER_SLOT))
            expected_interval = Interval((interval + 1) % int(INTERVALS_PER_SLOT))
            assert current_interval == expected_interval
