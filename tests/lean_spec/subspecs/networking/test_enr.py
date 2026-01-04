"""Tests for Ethereum Node Record (ENR) specification."""

import pytest
from pydantic import ValidationError

from lean_spec.subspecs.networking.enr import ENR, Eth2Data, keys
from lean_spec.subspecs.networking.enr.eth2 import AttestationSubnets
from lean_spec.types import Uint64
from lean_spec.types.byte_arrays import Bytes4


class TestEnrKeys:
    """Tests for ENR key constants."""

    def test_identity_keys(self) -> None:
        """Identity keys have correct values."""
        assert keys.ID == "id"
        assert keys.SECP256K1 == "secp256k1"

    def test_network_keys(self) -> None:
        """Network keys have correct values."""
        assert keys.IP == "ip"
        assert keys.IP6 == "ip6"
        assert keys.TCP == "tcp"
        assert keys.UDP == "udp"

    def test_ethereum_keys(self) -> None:
        """Ethereum-specific keys have correct values."""
        assert keys.ETH2 == "eth2"
        assert keys.ATTNETS == "attnets"
        assert keys.SYNCNETS == "syncnets"


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


class TestENR:
    """Tests for ENR structure."""

    def test_create_minimal_enr(self) -> None:
        """ENR can be created with minimal valid data."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": b"\x02" + b"\x00" * 32,  # Compressed pubkey
            },
        )
        assert enr.seq == Uint64(1)
        assert enr.identity_scheme == "v4"

    def test_enr_ip4_property(self) -> None:
        """ip4 property formats IPv4 address."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": b"\x02" + b"\x00" * 32,
                "ip": b"\xc0\xa8\x01\x01",  # 192.168.1.1
            },
        )
        assert enr.ip4 == "192.168.1.1"

    def test_enr_tcp_port_property(self) -> None:
        """tcp_port property extracts port number."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": b"\x02" + b"\x00" * 32,
                "tcp": (9000).to_bytes(2, "big"),
            },
        )
        assert enr.tcp_port == 9000

    def test_enr_multiaddr_construction(self) -> None:
        """multiaddr() constructs valid multiaddress."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": b"\x02" + b"\x00" * 32,
                "ip": b"\xc0\xa8\x01\x01",
                "tcp": (9000).to_bytes(2, "big"),
            },
        )
        assert enr.multiaddr() == "/ip4/192.168.1.1/tcp/9000"

    def test_enr_has_key(self) -> None:
        """has() correctly checks key presence."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": b"\x02" + b"\x00" * 32,
            },
        )
        assert enr.has(keys.ID)
        assert enr.has(keys.SECP256K1)
        assert not enr.has(keys.IP)
        assert not enr.has(keys.ETH2)

    def test_enr_get_key(self) -> None:
        """get() retrieves values by key."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={
                "id": b"v4",
            },
        )
        assert enr.get(keys.ID) == b"v4"
        assert enr.get(keys.IP) is None

    def test_enr_is_valid_basic(self) -> None:
        """is_valid() checks basic structure."""
        valid_enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": b"\x02" + b"\x00" * 32,
            },
        )
        assert valid_enr.is_valid()

        # Missing public key
        invalid_enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={
                "id": b"v4",
            },
        )
        assert not invalid_enr.is_valid()

    def test_enr_compatibility(self) -> None:
        """is_compatible_with() checks fork digest match."""
        eth2_bytes = b"\x12\x34\x56\x78" + b"\x02\x00\x00\x00" + b"\x00" * 8

        enr1 = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": b"\x02" + b"\x00" * 32,
                "eth2": eth2_bytes,
            },
        )

        enr2 = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(2),
            pairs={
                "id": b"v4",
                "secp256k1": b"\x02" + b"\x00" * 32,
                "eth2": eth2_bytes,
            },
        )

        assert enr1.is_compatible_with(enr2)

    def test_enr_string_representation(self) -> None:
        """ENR has readable string representation."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(42),
            pairs={
                "id": b"v4",
                "secp256k1": b"\x02" + b"\x00" * 32,
                "ip": b"\xc0\xa8\x01\x01",
                "tcp": (9000).to_bytes(2, "big"),
            },
        )
        s = str(enr)
        assert "seq=42" in s
        assert "192.168.1.1" in s
        assert "tcp=9000" in s
