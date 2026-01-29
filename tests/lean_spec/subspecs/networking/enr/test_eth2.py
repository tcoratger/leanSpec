"""Tests for Ethereum 2.0 ENR types (Eth2Data, AttestationSubnets, SyncCommitteeSubnets)."""

import pytest
from pydantic import ValidationError

from lean_spec.subspecs.networking.enr import Eth2Data
from lean_spec.subspecs.networking.enr.eth2 import AttestationSubnets, SyncCommitteeSubnets
from lean_spec.types import Uint64
from lean_spec.types.byte_arrays import Bytes4


class TestEth2Data:
    """Tests for Eth2Data structure."""

    def test_create_eth2_data(self) -> None:
        """Eth2Data can be created with valid parameters."""
        data = Eth2Data(
            fork_digest=Bytes4(b"\x12\x34\x56\x78"),
            next_fork_version=Bytes4(b"\x02\x00\x00\x00"),
            next_fork_epoch=Uint64(194048),
        )
        assert data.fork_digest == Bytes4(b"\x12\x34\x56\x78")
        assert data.next_fork_epoch == Uint64(194048)

    def test_no_scheduled_fork_factory(self) -> None:
        """no_scheduled_fork factory creates correct data."""
        digest = Bytes4(b"\xab\xcd\xef\x01")
        data = Eth2Data.no_scheduled_fork(digest)

        assert data.fork_digest == digest
        assert data.next_fork_version == digest
        assert data.next_fork_epoch == Uint64(2**64 - 1)

    def test_eth2_data_immutable(self) -> None:
        """Eth2Data is immutable (frozen)."""
        data = Eth2Data(
            fork_digest=Bytes4(b"\x12\x34\x56\x78"),
            next_fork_version=Bytes4(b"\x02\x00\x00\x00"),
            next_fork_epoch=Uint64(0),
        )
        with pytest.raises(ValidationError):
            data.fork_digest = Bytes4(b"\x00\x00\x00\x00")


class TestAttestationSubnets:
    """Tests for AttestationSubnets bitvector."""

    def test_empty_subscriptions(self) -> None:
        """none() creates empty subscriptions."""
        subnets = AttestationSubnets.none()
        assert subnets.subscription_count() == 0
        assert subnets.subscribed_subnets() == []

    def test_all_subscriptions(self) -> None:
        """all() creates full subscriptions."""
        subnets = AttestationSubnets.all()
        assert subnets.subscription_count() == 64
        assert len(subnets.subscribed_subnets()) == 64

    def test_specific_subscriptions(self) -> None:
        """from_subnet_ids() creates specific subscriptions."""
        subnets = AttestationSubnets.from_subnet_ids([0, 5, 63])

        assert subnets.is_subscribed(0)
        assert subnets.is_subscribed(5)
        assert subnets.is_subscribed(63)
        assert not subnets.is_subscribed(1)
        assert not subnets.is_subscribed(62)
        assert subnets.subscription_count() == 3

    def test_subscribed_subnets_list(self) -> None:
        """subscribed_subnets() returns correct list."""
        subnets = AttestationSubnets.from_subnet_ids([10, 20, 30])
        result = subnets.subscribed_subnets()

        assert result == [10, 20, 30]

    def test_invalid_subnet_id_in_from_subnet_ids(self) -> None:
        """from_subnet_ids() raises for invalid subnet IDs."""
        with pytest.raises(ValueError):
            AttestationSubnets.from_subnet_ids([64])

        with pytest.raises(ValueError):
            AttestationSubnets.from_subnet_ids([-1])

    def test_invalid_subnet_id_in_is_subscribed(self) -> None:
        """is_subscribed() raises for invalid subnet IDs."""
        subnets = AttestationSubnets.none()

        with pytest.raises(ValueError):
            subnets.is_subscribed(64)

        with pytest.raises(ValueError):
            subnets.is_subscribed(-1)


class TestSyncCommitteeSubnets:
    """Tests for SyncCommitteeSubnets bitvector."""

    def test_none_creates_empty_subscriptions(self) -> None:
        """none() creates empty subscriptions."""
        subnets = SyncCommitteeSubnets.none()
        for i in range(4):
            assert not subnets.is_subscribed(i)

    def test_all_creates_full_subscriptions(self) -> None:
        """all() creates full subscriptions."""
        subnets = SyncCommitteeSubnets.all()
        for i in range(4):
            assert subnets.is_subscribed(i)

    def test_is_subscribed_with_valid_ids(self) -> None:
        """is_subscribed() works for valid subnet IDs 0-3."""
        subnets = SyncCommitteeSubnets.all()
        assert subnets.is_subscribed(0)
        assert subnets.is_subscribed(1)
        assert subnets.is_subscribed(2)
        assert subnets.is_subscribed(3)

    def test_is_subscribed_raises_for_invalid_high_id(self) -> None:
        """is_subscribed() raises for subnet ID >= 4."""
        subnets = SyncCommitteeSubnets.none()
        with pytest.raises(ValueError, match="must be 0-3"):
            subnets.is_subscribed(4)

    def test_is_subscribed_raises_for_negative_id(self) -> None:
        """is_subscribed() raises for negative subnet ID."""
        subnets = SyncCommitteeSubnets.none()
        with pytest.raises(ValueError, match="must be 0-3"):
            subnets.is_subscribed(-1)
