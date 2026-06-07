"""Tests for the GenesisConfig container."""

import pytest
from pydantic import ValidationError

from lean_spec.spec.forks.lstar.containers import GenesisConfig
from lean_spec.spec.ssz import Uint64


class TestGenesisConfigImmutability:
    """Frozen-model semantics forbid post-construction mutation."""

    def test_assigning_genesis_time_raises(self) -> None:
        """Assigning a new genesis time on a constructed config raises."""
        config = GenesisConfig(genesis_time=Uint64(1_700_000_000))
        with pytest.raises(ValidationError, match="frozen"):
            config.genesis_time = Uint64(1_700_000_001)
