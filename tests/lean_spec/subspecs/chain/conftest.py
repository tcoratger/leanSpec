"""Shared fixtures for chain service tests."""

from __future__ import annotations

from typing import Any

import pytest

from lean_spec.forks.lstar.spec import LstarSpec


@pytest.fixture(autouse=True)
def _delegate_spec_to_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route chain-service spec calls back to the mock store's matching method.

    Chain tests run against `MockStore`, which records calls on its own
    `tick_interval`. The real spec implementation expects a fully-formed
    Pydantic Store. Routing the spec call back lets the mock intercept in-place.
    """

    def tick_interval(
        self: LstarSpec, store: Any, has_proposal: bool, is_aggregator: bool = False
    ) -> Any:
        return store.tick_interval(has_proposal, is_aggregator)

    monkeypatch.setattr(LstarSpec, "tick_interval", tick_interval)
