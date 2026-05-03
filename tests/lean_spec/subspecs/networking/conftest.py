"""Shared fixtures for networking subspec tests."""

from __future__ import annotations

from typing import Any

import pytest

from lean_spec.forks.lstar.spec import LstarSpec


@pytest.fixture(autouse=True)
def _delegate_spec_to_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route sync-service spec calls back to the mock store's matching method.

    Networking tests drive `SyncService` against `MockForkchoiceStore` for
    isolation. The real spec implementation expects a fully-formed Pydantic
    Store; routing each spec call back to `store.method(...)` lets the mock
    intercept in-place without changing service code.
    """

    def on_block(self: LstarSpec, store: Any, signed_block: Any, *args: Any, **kwargs: Any) -> Any:
        return store.on_block(signed_block, *args, **kwargs)

    def on_gossip_attestation(
        self: LstarSpec,
        store: Any,
        signed_attestation: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        kwargs.pop("scheme", None)
        return store.on_gossip_attestation(signed_attestation, *args, **kwargs)

    def on_gossip_aggregated_attestation(
        self: LstarSpec, store: Any, signed_attestation: Any, *args: Any, **kwargs: Any
    ) -> Any:
        return store.on_gossip_aggregated_attestation(signed_attestation, *args, **kwargs)

    monkeypatch.setattr(LstarSpec, "on_block", on_block)
    monkeypatch.setattr(LstarSpec, "on_gossip_attestation", on_gossip_attestation)
    monkeypatch.setattr(
        LstarSpec, "on_gossip_aggregated_attestation", on_gossip_aggregated_attestation
    )
