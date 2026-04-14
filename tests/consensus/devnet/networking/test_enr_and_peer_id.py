"""Test vectors for ENR encoding and PeerId derivation."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Devnet")

OFFICIAL_ENR = (
    "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjz"
    "CBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQ"
    "PKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8"
)
"""Official EIP-778 test vector."""


# --- ENR ---


def test_enr_official_eip778(networking_codec: NetworkingCodecTestFiller) -> None:
    """Official EIP-778 test vector. Verifies text/RLP roundtrip and all properties."""
    networking_codec(codec_name="enr", input={"enrString": OFFICIAL_ENR})


# --- PeerId ---


def test_peer_id_ed25519(networking_codec: NetworkingCodecTestFiller) -> None:
    """ED25519 PeerId from libp2p spec. 32-byte key, identity multihash."""
    networking_codec(
        codec_name="peer_id",
        input={
            "keyType": "ed25519",
            "publicKey": "0x1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e",
        },
    )


def test_peer_id_secp256k1(networking_codec: NetworkingCodecTestFiller) -> None:
    """secp256k1 PeerId from libp2p spec. 33-byte key, identity multihash."""
    networking_codec(
        codec_name="peer_id",
        input={
            "keyType": "secp256k1",
            "publicKey": "0x037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99",
        },
    )


def test_peer_id_ecdsa(networking_codec: NetworkingCodecTestFiller) -> None:
    """ECDSA PeerId from libp2p spec. 91-byte key, crosses 42-byte threshold, SHA256 multihash."""
    networking_codec(
        codec_name="peer_id",
        input={
            "keyType": "ecdsa",
            "publicKey": (
                "0x3059301306072a8648ce3d020106082a8648ce3d030107034200"
                "04de3d300fa36ae0e8f5d530899d83abab44abf3161f162a4bc901d8e6ec"
                "da020e8b6d5f8da30525e71d6851510c098e5c47c646a597fb4dcec034e9"
                "f77c409e62"
            ),
        },
    )


def test_peer_id_secp256k1_from_enr(networking_codec: NetworkingCodecTestFiller) -> None:
    """secp256k1 PeerId using the public key from the official EIP-778 ENR."""
    networking_codec(
        codec_name="peer_id",
        input={
            "keyType": "secp256k1",
            "publicKey": "0x03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138",
        },
    )
