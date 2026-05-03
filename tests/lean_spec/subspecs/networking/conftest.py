"""Shared fixtures for networking subspec tests."""

from __future__ import annotations

from typing import Any

import pytest

from lean_spec.subspecs.sync import service as sync_service_module


@pytest.fixture(autouse=True)
def _delegate_spec_to_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route sync-service spec calls back to the mock store's matching method.

    Networking tests drive `SyncService` against `MockForkchoiceStore` for
    isolation. The real spec implementation expects a fully-formed Pydantic
    Store; routing each spec call back to `store.method(...)` lets the mock
    intercept in-place without changing service code.
    """
    spec = sync_service_module._SPEC

    def on_block(store: Any, signed_block: Any, *args: Any, **kwargs: Any) -> Any:
        return store.on_block(signed_block, *args, **kwargs)

    def on_gossip_attestation(
        store: Any,
        signed_attestation: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        kwargs.pop("scheme", None)
        return store.on_gossip_attestation(signed_attestation, *args, **kwargs)

    def on_gossip_aggregated_attestation(
        store: Any, signed_attestation: Any, *args: Any, **kwargs: Any
    ) -> Any:
        return store.on_gossip_aggregated_attestation(signed_attestation, *args, **kwargs)

    monkeypatch.setattr(spec, "on_block", on_block)
    monkeypatch.setattr(spec, "on_gossip_attestation", on_gossip_attestation)
    monkeypatch.setattr(spec, "on_gossip_aggregated_attestation", on_gossip_aggregated_attestation)
