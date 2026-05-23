"""Tests for the validated, file-loaded boot configuration."""

from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from consensus_testing.keys import XmssKeyManager
from Crypto.Hash import keccak
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from lean_spec.cli import CliValidationError, NodeBootstrap, parse_args
from lean_spec.subspecs.api import ApiServerConfig
from lean_spec.types import Slot, SubnetId, ValidatorIndex
from lean_spec.types.rlp import RLPItem, encode_rlp

# Generate a test keypair once for all ENR tests.
_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256K1())
_TEST_PUBLIC_KEY = _TEST_PRIVATE_KEY.public_key()
_TEST_COMPRESSED_PUBKEY = _TEST_PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.CompressedPoint,
)


def _sign_enr_content(content_items: list[RLPItem]) -> bytes:
    """Sign ENR content and return 64-byte r||s signature."""
    content_rlp = encode_rlp(content_items)

    k = keccak.new(digest_bits=256)
    k.update(content_rlp)
    digest = k.digest()

    signature_der = _TEST_PRIVATE_KEY.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(signature_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _make_enr_with_udp(ip_bytes: bytes, udp_port: int) -> str:
    """Create a properly signed ENR string with IPv4 and UDP port."""
    # Content items (keys must be sorted).
    content_items: list[RLPItem] = [
        b"\x01",  # seq = 1
        b"id",
        b"v4",
        b"ip",
        ip_bytes,
        b"secp256k1",
        _TEST_COMPRESSED_PUBKEY,
        b"udp",
        udp_port.to_bytes(2, "big"),
    ]
    signature = _sign_enr_content(content_items)

    rlp_data = encode_rlp([signature] + content_items)
    b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")
    return f"enr:{b64_content}"


def _make_enr_without_udp(ip_bytes: bytes) -> str:
    """Create a properly signed ENR string with IPv4 but no UDP port."""
    content_items: list[RLPItem] = [
        b"\x01",  # seq = 1
        b"id",
        b"v4",
        b"ip",
        ip_bytes,
        b"secp256k1",
        _TEST_COMPRESSED_PUBKEY,
    ]
    signature = _sign_enr_content(content_items)

    rlp_data = encode_rlp([signature] + content_items)
    b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")
    return f"enr:{b64_content}"


# Pre-built test ENRs
ENR_WITH_UDP = _make_enr_with_udp(b"\xc0\xa8\x01\x01", 9000)  # 192.168.1.1:9000
ENR_WITHOUT_UDP = _make_enr_without_udp(b"\xc0\xa8\x01\x01")  # 192.168.1.1, no UDP

# Valid multiaddr strings (QUIC format)
MULTIADDR_IPV4 = "/ip4/127.0.0.1/udp/9000/quic-v1"


@pytest.fixture
def genesis_yaml(tmp_path: Path) -> Path:
    """Write a minimal genesis YAML to a temporary path."""
    path = tmp_path / "genesis.yaml"
    path.write_text("GENESIS_TIME: 1000\nGENESIS_VALIDATORS: []\n")
    return path


def _write_aggregator_key_layout(tmp_path: Path) -> Path:
    """Materialise a one-validator key directory the registry loader accepts."""
    keys_root = tmp_path / "keys"
    hash_sig_dir = keys_root / "hash-sig-keys"
    hash_sig_dir.mkdir(parents=True)

    km = XmssKeyManager.shared(max_slot=Slot(10))
    kp = km[ValidatorIndex(0)]

    (hash_sig_dir / "att_key_0.ssz").write_bytes(kp.attestation_keypair.secret_key.encode_bytes())
    (hash_sig_dir / "prop_key_0.ssz").write_bytes(kp.proposal_keypair.secret_key.encode_bytes())

    manifest = hash_sig_dir / "validator-keys-manifest.yaml"
    manifest.write_text(
        "key_scheme: SIGTopLevelTargetSumLifetime32Dim64Base8\n"
        "hash_function: Poseidon2\n"
        "encoding: TargetSum\n"
        "lifetime: 32\n"
        "log_num_active_epochs: 5\n"
        "num_active_epochs: 32\n"
        "num_validators: 1\n"
        "validators:\n"
        "  - index: 0\n"
        f"    attestation_pubkey_hex: '0x{'00' * 52}'\n"
        f"    proposal_pubkey_hex: '0x{'00' * 52}'\n"
        "    attestation_privkey_file: att_key_0.ssz\n"
        "    proposal_privkey_file: prop_key_0.ssz\n"
    )

    (keys_root / "validators.yaml").write_text("lean_spec_0: [0]\n")
    return keys_root


def _bootstrap_from_argv(genesis_yaml: Path, *extra: str) -> NodeBootstrap:
    """Construct a bootstrap from a genesis path and extra CLI tokens."""
    argv = ["--genesis", str(genesis_yaml), *extra]
    return NodeBootstrap.from_cli_args(parse_args(argv))


def _bootstrap_with_bootnodes(genesis_yaml: Path, *bootnodes: str) -> NodeBootstrap:
    """Construct a bootstrap from a genesis path and bootnode strings."""
    extra: list[str] = []
    for b in bootnodes:
        extra.extend(["--bootnode", b])
    return _bootstrap_from_argv(genesis_yaml, *extra)


class TestBootnodeResolution:
    """Tests for bootnode resolution at the CLI boundary."""

    def test_multiaddr_passes_through(self, genesis_yaml: Path) -> None:
        """A bare multiaddr is kept as-is."""
        boot = _bootstrap_with_bootnodes(genesis_yaml, MULTIADDR_IPV4)
        assert boot.bootnode_multiaddrs == (MULTIADDR_IPV4,)

    def test_enr_resolves_to_multiaddr(self, genesis_yaml: Path) -> None:
        """An ENR carrying UDP info expands to its dialable multiaddr view."""
        boot = _bootstrap_with_bootnodes(genesis_yaml, ENR_WITH_UDP)
        assert boot.bootnode_multiaddrs == ("/ip4/192.168.1.1/udp/9000/quic-v1",)

    def test_enr_without_udp_rejected(self, genesis_yaml: Path) -> None:
        """An ENR lacking UDP info is rejected before any dial attempt."""
        with pytest.raises(CliValidationError, match=r"no UDP connection info"):
            _bootstrap_with_bootnodes(genesis_yaml, ENR_WITHOUT_UDP)

    def test_malformed_enr_rejected(self, genesis_yaml: Path) -> None:
        """A malformed ENR fails at RLP decoding."""
        with pytest.raises(ValueError, match=r"Invalid RLP"):
            _bootstrap_with_bootnodes(genesis_yaml, "enr:YWJj")

    def test_mixed_inputs_preserve_order(self, genesis_yaml: Path) -> None:
        """Mixed multiaddr and ENR inputs resolve into a single ordered tuple."""
        boot = _bootstrap_with_bootnodes(
            genesis_yaml,
            MULTIADDR_IPV4,
            ENR_WITH_UDP,
            "/ip4/10.0.0.1/udp/8000/quic-v1",
        )
        assert boot.bootnode_multiaddrs == (
            MULTIADDR_IPV4,
            "/ip4/192.168.1.1/udp/9000/quic-v1",
            "/ip4/10.0.0.1/udp/8000/quic-v1",
        )

    def test_no_bootnodes_resolves_empty_tuple(self, genesis_yaml: Path) -> None:
        """No bootnode flags resolve to an empty tuple."""
        assert _bootstrap_from_argv(genesis_yaml).bootnode_multiaddrs == ()


class TestNodeBootstrapValidation:
    """Tests for the CLI argument validator."""

    def test_aggregator_without_validator_keys_rejected(self, tmp_path: Path) -> None:
        """The aggregator flag requires a validator keys path."""
        genesis_path = tmp_path / "genesis.yaml"
        genesis_path.write_text("GENESIS_TIME: 1000\nGENESIS_VALIDATORS: []\n")

        args = parse_args(
            [
                "--genesis",
                str(genesis_path),
                "--is-aggregator",
            ]
        )

        with pytest.raises(CliValidationError, match="--is-aggregator requires --validator-keys"):
            NodeBootstrap.from_cli_args(args)


class TestAggregateSubnetIds:
    """Tests for parsing the extra-subnets flag."""

    def test_empty_string_parses_to_empty_tuple(self, genesis_yaml: Path) -> None:
        """An empty extras string resolves to an empty subnet tuple."""
        boot = _bootstrap_from_argv(genesis_yaml, "--aggregate-subnet-ids", "")
        assert boot.aggregate_subnet_ids == ()

    def test_valid_extras_parse_into_tuple(self, genesis_yaml: Path, tmp_path: Path) -> None:
        """A comma list with aggregator mode and a populated registry resolves in order."""
        keys_root = _write_aggregator_key_layout(tmp_path)
        boot = _bootstrap_from_argv(
            genesis_yaml,
            "--validator-keys",
            str(keys_root),
            "--is-aggregator",
            "--aggregate-subnet-ids",
            "1,2,3",
        )
        assert boot.aggregate_subnet_ids == (SubnetId(1), SubnetId(2), SubnetId(3))

    def test_extras_without_aggregator_rejected(self, genesis_yaml: Path) -> None:
        """Subnet extras without aggregator mode raise a typed validation error."""
        with pytest.raises(CliValidationError, match="requires --is-aggregator"):
            _bootstrap_from_argv(genesis_yaml, "--aggregate-subnet-ids", "1,2,3")

    def test_malformed_extras_rejected(self, genesis_yaml: Path, tmp_path: Path) -> None:
        """A non-integer token in the extras list raises a typed validation error."""
        # Why:
        # The integer parser runs before any registry load, so any non-empty
        # validator-keys path is enough to reach the parse branch.
        with pytest.raises(CliValidationError, match="comma-separated integers"):
            _bootstrap_from_argv(
                genesis_yaml,
                "--validator-keys",
                str(tmp_path / "keys"),
                "--is-aggregator",
                "--aggregate-subnet-ids",
                "1,abc,3",
            )


class TestApiConfigResolution:
    """Tests for the api_config field on the boot configuration."""

    def test_zero_port_disables_api(self, genesis_yaml: Path) -> None:
        """A port of zero leaves the API configuration unset."""
        boot = _bootstrap_from_argv(genesis_yaml, "--api-port", "0")
        assert boot.api_config is None

    def test_non_zero_port_enables_api(self, genesis_yaml: Path) -> None:
        """A non-zero port produces an API configuration carrying that port."""
        boot = _bootstrap_from_argv(genesis_yaml, "--api-port", "5052")
        assert boot.api_config == ApiServerConfig(port=5052)


class TestListenAddressResolution:
    """Tests for the listen-address field on the boot configuration."""

    def test_empty_listen_address_becomes_none(self, genesis_yaml: Path) -> None:
        """An empty listen string resolves to no listener."""
        boot = _bootstrap_from_argv(genesis_yaml, "--listen", "")
        assert boot.listen_addr is None


class TestBuildAnchor:
    """Tests for the async anchor builder method."""

    async def test_no_checkpoint_calls_from_genesis(self, genesis_yaml: Path) -> None:
        """Without a checkpoint URL the boot delegates to the synchronous genesis builder."""
        boot = _bootstrap_from_argv(genesis_yaml)

        sentinel = object()
        with patch(
            "lean_spec.cli.bootstrap.Anchor.from_genesis",
            return_value=sentinel,
        ) as from_genesis:
            anchor = await boot.build_anchor()

        assert anchor is sentinel
        assert from_genesis.call_args.args == (boot.genesis,)

    async def test_checkpoint_url_calls_from_checkpoint(self, genesis_yaml: Path) -> None:
        """With a checkpoint URL the boot delegates to the asynchronous checkpoint builder."""
        boot = _bootstrap_from_argv(
            genesis_yaml,
            "--checkpoint-sync-url",
            "http://localhost:5052",
        )

        sentinel = object()
        with patch(
            "lean_spec.cli.bootstrap.Anchor.from_checkpoint",
            new_callable=AsyncMock,
            return_value=sentinel,
        ) as from_checkpoint:
            anchor = await boot.build_anchor()

        assert anchor is sentinel
        await_args = from_checkpoint.await_args
        assert await_args is not None
        assert await_args.kwargs == {
            "url": "http://localhost:5052",
            "genesis": boot.genesis,
            "fork": boot.fork,
            "validator_id": boot.registry.primary_index(),
        }
