"""Canonical store snapshot emitted after every fork choice step."""

from lean_spec.base import CamelModel
from lean_spec.spec.forks import Interval
from lean_spec.spec.forks.lstar.containers import Checkpoint, Store
from lean_spec.spec.ssz import Bytes32


class StoreSnapshot(CamelModel):
    """
    Canonical store observables captured after a fork choice step.

    Recorded by the framework after every successful step.
    Clients must reproduce every field, not just authored checks.

    Why explicit fields instead of an opaque digest:
    a digest needs a spec-defined canonical store encoding.
    Explicit fields are self-describing and language-neutral.
    """

    time: Interval
    """Store time in intervals since genesis."""

    head_root: Bytes32
    """Root of the canonical chain head block."""

    safe_target_root: Bytes32
    """Root of the current safe attestation target."""

    latest_justified: Checkpoint
    """Highest slot justified checkpoint known to the store."""

    latest_finalized: Checkpoint
    """Highest slot finalized checkpoint known to the store."""

    @classmethod
    def from_store(cls, store: Store) -> "StoreSnapshot":
        """Capture the canonical observables of a store."""
        return cls(
            time=store.time,
            head_root=store.head,
            safe_target_root=store.safe_target,
            latest_justified=store.latest_justified,
            latest_finalized=store.latest_finalized,
        )
