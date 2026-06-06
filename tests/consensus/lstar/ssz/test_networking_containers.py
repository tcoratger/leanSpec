"""SSZ conformance tests for networking containers."""

import pytest
from consensus_testing import SSZTestFiller

from lean_spec.node.networking.reqresp.message import (
    BlocksByRootRequest,
    RequestedBlockRoots,
    Status,
)
from lean_spec.spec.forks import Checkpoint, Slot
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


# --- Status ---


def test_status_zero(ssz_test: SSZTestFiller) -> None:
    """SSZ roundtrip for Status with zero values."""
    ssz_test(
        type_name="Status",
        value=Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        ),
    )


def test_status_typical(ssz_test: SSZTestFiller) -> None:
    """SSZ roundtrip for Status with typical values."""
    ssz_test(
        type_name="Status",
        value=Status(
            finalized=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(100)),
            head=Checkpoint(root=Bytes32(b"\x02" * 32), slot=Slot(150)),
        ),
    )


# --- BlocksByRootRequest ---


def test_blocks_by_root_request_empty(ssz_test: SSZTestFiller) -> None:
    """SSZ roundtrip for BlocksByRootRequest with no roots."""
    ssz_test(
        type_name="BlocksByRootRequest",
        value=BlocksByRootRequest(roots=RequestedBlockRoots(data=[])),
    )


def test_blocks_by_root_request_single(ssz_test: SSZTestFiller) -> None:
    """SSZ roundtrip for BlocksByRootRequest with single root."""
    ssz_test(
        type_name="BlocksByRootRequest",
        value=BlocksByRootRequest(roots=RequestedBlockRoots(data=[Bytes32(b"\xab" * 32)])),
    )


def test_blocks_by_root_request_multiple(ssz_test: SSZTestFiller) -> None:
    """SSZ roundtrip for BlocksByRootRequest with multiple roots."""
    ssz_test(
        type_name="BlocksByRootRequest",
        value=BlocksByRootRequest(
            roots=RequestedBlockRoots(
                data=[Bytes32(b"\x01" * 32), Bytes32(b"\x02" * 32), Bytes32(b"\x03" * 32)]
            )
        ),
    )


def test_blocks_by_root_request_max_roots(ssz_test: SSZTestFiller) -> None:
    """SSZ roundtrip for BlocksByRootRequest with ten distinct roots."""
    ssz_test(
        type_name="BlocksByRootRequest",
        value=BlocksByRootRequest(
            roots=RequestedBlockRoots(data=[Bytes32(bytes([i]) * 32) for i in range(1, 11)])
        ),
    )
