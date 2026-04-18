"""Dispatcher routing spec calls to the correct fork."""

from lean_spec.subspecs.containers.slot import Slot

from .protocol import ForkProtocol


class SpecRunner:
    """Routes specification calls to the correct fork based on slot."""

    def __init__(self, forks: list[ForkProtocol]) -> None:
        """
        Initialize with an ordered list of forks.

        Forks must be ordered by version (ascending).

        Each fork handles slots from its activation slot onward, until the next fork activates.

        Args:
            forks: Ordered list of fork implementations.
        """
        assert len(forks) > 0, "At least one fork is required"
        assert all(forks[i].version() < forks[i + 1].version() for i in range(len(forks) - 1)), (
            "Forks must be ordered by version"
        )
        self._forks = forks

    @property
    def current(self) -> ForkProtocol:
        """Return the latest (highest version) fork."""
        return self._forks[-1]

    def at(self, slot: Slot) -> ForkProtocol:
        """
        Return the fork active at the given slot.

        Phase 1: always returns the latest fork.
        Future: will check fork activation slots.

        Args:
            slot: The slot to look up.

        Returns:
            The ForkProtocol instance active at that slot.
        """
        return self._forks[-1]

    def get_fork(self, name: str) -> ForkProtocol:
        """
        Look up a fork by name.

        Args:
            name: Fork name (e.g. 'devnet4').

        Returns:
            The matching ForkProtocol instance.

        Raises:
            KeyError: If no fork matches the name.
        """
        for fork in self._forks:
            if fork.name() == name:
                return fork
        raise KeyError(f"Unknown fork: {name}")
