"""Tests for the lstar forkchoice Store container."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from lean_spec.spec.forks.lstar.containers import Interval
from tests.lean_spec.helpers import make_store


class TestStoreImmutability:
    """Frozen-model semantics forbid post-construction mutation."""

    def test_assigning_time_raises(self) -> None:
        """Assigning a new time on a constructed store raises."""
        store = make_store(num_validators=1)
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for Store\[State, Block\]\ntime\n"
            r"  Instance is frozen \[type=frozen_instance, input_value=Interval\(1\), "
            r"input_type=Interval\]\n    For further information visit "
            r"https://errors\.pydantic\.dev/[^\s]+/v/frozen_instance\Z",
        ):
            store.time = Interval(1)
