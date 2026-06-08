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
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for GenesisConfig\ngenesis_time\n"
            r"  Instance is frozen \[type=frozen_instance, input_value=Uint64\(1700000001\), "
            r"input_type=Uint64\]\n    For further information visit "
            r"https://errors\.pydantic\.dev/[^\s]+/v/frozen_instance\Z",
        ):
            config.genesis_time = Uint64(1_700_000_001)
