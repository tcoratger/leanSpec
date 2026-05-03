"""
Shared pytest fixtures for sync service tests.

Peer ID and connection state fixtures are inherited from the parent conftest.
"""

from __future__ import annotations

from typing import Any

import pytest

from lean_spec.forks.lstar.spec import LstarSpec
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.types import Bytes32, Checkpoint, Slot


@pytest.fixture(autouse=True)
def _delegate_spec_to_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route sync-service spec calls back to the mock store's matching method.

    Sync tests run against `MockForkchoiceStore`, which records calls on its own
    methods. The real spec implementation expects a fully-formed Pydantic Store.
    Routing each spec call back to `store.method(...)` lets the mock intercept
    in-place without a sync-service code change.
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


@pytest.fixture
def sample_checkpoint() -> Checkpoint:
    """Sample checkpoint for sync tests."""
    return Checkpoint(root=Bytes32.zero(), slot=Slot(100))


@pytest.fixture
def sample_status(sample_checkpoint: Checkpoint) -> Status:
    """Sample Status message for sync tests."""
    return Status(
        finalized=sample_checkpoint,
        head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
    )
