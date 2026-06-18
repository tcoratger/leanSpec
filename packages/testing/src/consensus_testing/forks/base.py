"""Base fork class for spec test generation."""

from abc import ABC, ABCMeta, abstractmethod


class BaseForkMeta(ABCMeta):
    """Metaclass ordering forks by inheritance: an older fork is a base of a newer one."""

    def __repr__(cls: "type[BaseFork]") -> str:
        """Print the fork name instead of the class."""
        return cls.name()

    def __le__(cls: "type[BaseFork]", other: "type[BaseFork]") -> bool:
        """Older-or-equal: a fork precedes any fork that inherits from it."""
        return cls is other or issubclass(other, cls)


class BaseFork(ABC, metaclass=BaseForkMeta):
    """Protocol version in the fork inheritance hierarchy."""

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """Fork name as it appears in the network field of generated fixtures."""
