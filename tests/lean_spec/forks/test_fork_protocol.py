"""Tests for the multi-fork architecture"""

import pytest

from lean_spec.forks import (
    Devnet4Spec,
    Devnet5Spec,
    ForkProtocol,
    SpecRunner,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Uint64
from tests.lean_spec.helpers.builders import make_genesis_state, make_validators


class TestDevnet4Spec:
    """Tests for the Devnet4Spec fork implementation."""

    def test_name(self) -> None:
        """Devnet4Spec reports its name."""
        assert Devnet4Spec.name() == "devnet4"

    def test_version(self) -> None:
        """Devnet4Spec reports version 4."""
        assert Devnet4Spec.version() == 4

    def test_is_fork_protocol(self) -> None:
        """Devnet4Spec is a ForkProtocol instance."""
        assert isinstance(Devnet4Spec(), ForkProtocol)

    def test_generate_genesis(self) -> None:
        """Devnet4Spec generates a valid genesis state."""
        fork = Devnet4Spec()
        validators = make_validators(4)
        state = fork.generate_genesis(Uint64(0), validators)
        assert state.slot == Slot(0)
        assert len(state.validators) == 4

    def test_process_slots(self) -> None:
        """Devnet4Spec delegates process_slots to State."""
        fork = Devnet4Spec()
        state = make_genesis_state(num_validators=4)
        advanced = fork.process_slots(state, Slot(3))
        assert advanced.slot == Slot(3)

    def test_upgrade_state_is_identity(self) -> None:
        """Default upgrade_state returns the same state."""
        fork = Devnet4Spec()
        state = make_genesis_state(num_validators=4)
        assert fork.upgrade_state(state) is state


class TestDevnet5Spec:
    """Tests for the Devnet5Spec fork skeleton."""

    def test_name(self) -> None:
        """Devnet5Spec reports its name."""
        assert Devnet5Spec.name() == "devnet5"

    def test_version(self) -> None:
        """Devnet5Spec reports version 5."""
        assert Devnet5Spec.version() == 5

    def test_inherits_from_devnet4(self) -> None:
        """Devnet5Spec is a subclass of Devnet4Spec."""
        assert issubclass(Devnet5Spec, Devnet4Spec)

    def test_inherited_process_slots(self) -> None:
        """Devnet5Spec inherits process_slots from Devnet4Spec."""
        fork = Devnet5Spec()
        state = make_genesis_state(num_validators=4)
        advanced = fork.process_slots(state, Slot(3))
        assert advanced.slot == Slot(3)

    def test_inherited_generate_genesis(self) -> None:
        """Devnet5Spec inherits genesis generation from Devnet4Spec."""
        fork = Devnet5Spec()
        validators = make_validators(4)
        state = fork.generate_genesis(Uint64(0), validators)
        assert state.slot == Slot(0)
        assert len(state.validators) == 4


class TestSpecRunner:
    """Tests for the SpecRunner dispatcher."""

    def test_current_returns_latest(self) -> None:
        """SpecRunner.current returns the latest fork."""
        fork = Devnet4Spec()
        runner = SpecRunner(forks=[fork])
        assert runner.current is fork

    def test_at_returns_fork(self) -> None:
        """SpecRunner.at returns the active fork for a slot."""
        fork = Devnet4Spec()
        runner = SpecRunner(forks=[fork])
        assert runner.at(Slot(0)) is fork
        assert runner.at(Slot(100)) is fork

    def test_get_fork_by_name(self) -> None:
        """SpecRunner.get_fork looks up by name."""
        fork = Devnet4Spec()
        runner = SpecRunner(forks=[fork])
        assert runner.get_fork("devnet4") is fork

    def test_get_fork_unknown_raises(self) -> None:
        """SpecRunner.get_fork raises KeyError for unknown forks."""
        runner = SpecRunner(forks=[Devnet4Spec()])
        with pytest.raises(KeyError, match="Unknown fork: devnet99"):
            runner.get_fork("devnet99")

    def test_empty_forks_raises(self) -> None:
        """SpecRunner requires at least one fork."""
        with pytest.raises(AssertionError, match="At least one fork"):
            SpecRunner(forks=[])

    def test_wrong_order_raises(self) -> None:
        """SpecRunner rejects forks in wrong order."""
        with pytest.raises(AssertionError, match="Forks must be ordered"):
            SpecRunner(forks=[Devnet5Spec(), Devnet4Spec()])

    def test_multi_fork_runner(self) -> None:
        """SpecRunner accepts multiple forks in order."""
        d4 = Devnet4Spec()
        d5 = Devnet5Spec()
        runner = SpecRunner(forks=[d4, d5])
        assert runner.current is d5
        assert runner.get_fork("devnet4") is d4
        assert runner.get_fork("devnet5") is d5

    def test_round_trip_genesis_and_process_slots(self) -> None:
        """SpecRunner dispatches genesis and slot processing correctly."""
        runner = SpecRunner(forks=[Devnet4Spec()])
        fork = runner.current
        validators = make_validators(4)
        state = fork.generate_genesis(Uint64(0), validators)
        advanced = fork.process_slots(state, Slot(5))
        assert advanced.slot == Slot(5)
