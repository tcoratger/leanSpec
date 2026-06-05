"""Fork registry for discovering and looking up forks by name."""

from types import ModuleType

from framework.forks.base import BaseFork


class ForkRegistry:
    """Discovers forks from a module and provides O(1) name-based lookup."""

    def __init__(self, forks_module: ModuleType) -> None:
        """Scan a forks module and build the name index."""
        discovered: set[type[BaseFork]] = set()
        for attribute_name in dir(forks_module):
            module_attribute = getattr(forks_module, attribute_name)
            if (
                isinstance(module_attribute, type)
                and issubclass(module_attribute, BaseFork)
                and module_attribute is not BaseFork
            ):
                discovered.add(module_attribute)

        self._forks = frozenset(fork for fork in discovered if not fork.ignore())
        self._by_name: dict[str, type[BaseFork]] = {
            fork.name().lower(): fork for fork in self._forks
        }

    @property
    def forks(self) -> frozenset[type[BaseFork]]:
        """All available non-ignored forks."""
        return self._forks

    def get_fork_by_name(self, fork_name: str) -> type[BaseFork] | None:
        """Case-insensitive fork lookup."""
        return self._by_name.get(fork_name.lower())
