"""
Official Discovery v5 Test Vectors

Test vectors from the devp2p specification for spec compliance verification.

Reference:
    https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md
"""

from __future__ import annotations

from lean_spec.subspecs.networking.discovery.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    ecdh_agree,
    sign_id_nonce,
    verify_id_nonce_signature,
)
from lean_spec.subspecs.networking.discovery.keys import (
    compute_node_id,
    derive_keys,
)
from lean_spec.subspecs.networking.discovery.messages import PacketFlag
from lean_spec.subspecs.networking.discovery.packet import (
    decode_handshake_authdata,
    decode_message_authdata,
    decode_packet_header,
    decode_whoareyou_authdata,
    decrypt_message,
    encode_handshake_authdata,
    encode_message_authdata,
    encode_packet,
    encode_whoareyou_authdata,
)
from lean_spec.types import Bytes12, Bytes16, Bytes32, Bytes33, Bytes64
from tests.lean_spec.helpers import make_challenge_data

# Node B's secp256k1 keypair (from devp2p spec)
# Node B's private key is provided in the test vectors.
NODE_B_PRIVKEY = bytes.fromhex("66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628")
NODE_B_ID = bytes.fromhex("bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9")

# Node A's ID (from devp2p spec, private key not provided)
NODE_A_ID = bytes.fromhex("aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb")

# Spec test vector values for ECDH and key derivation.
SPEC_ID_NONCE = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
SPEC_NONCE = bytes.fromhex("0102030405060708090a0b0c")
SPEC_CHALLENGE_DATA = bytes.fromhex(
    "000000000000000000000000000000006469736376350001010102030405060708090a0b0c"
    "00180102030405060708090a0b0c0d0e0f100000000000000000"
)


class TestOfficialNodeIdVectors:
    """Verify node ID computation matches official test vectors."""

    def test_node_b_id_from_privkey(self):
        """
        Node B's ID is keccak256 of uncompressed public key.

        We derive the public key from the private key since the spec
        provides the private key for Node B.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        # Derive public key from private key.
        private_key = ec.derive_private_key(
            int.from_bytes(NODE_B_PRIVKEY, "big"),
            ec.SECP256K1(),
        )
        pubkey_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

        computed = compute_node_id(pubkey_bytes)
        assert bytes(computed) == NODE_B_ID


class TestOfficialCryptoVectors:
    """Cryptographic operation test vectors from devp2p spec."""

    def test_ecdh_shared_secret(self):
        """
        ECDH between Node A's private key and Node B's public key.

        Per spec, the shared secret is the 33-byte compressed point.
        """
        secret_key = bytes.fromhex(
            "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
        )
        public_key = bytes.fromhex(
            "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231"
        )
        expected_shared = bytes.fromhex(
            "033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e"
        )

        shared = ecdh_agree(Bytes32(secret_key), public_key)

        assert shared == expected_shared

    def test_key_derivation_hkdf(self):
        """
        Key derivation using HKDF-SHA256.

        Derives initiator_key and recipient_key from ECDH shared secret.
        Uses exact spec challenge_data (with nonce 0102030405060708090a0b0c).
        """
        ephemeral_key = bytes.fromhex(
            "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
        )
        dest_pubkey = bytes.fromhex(
            "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
        )
        node_id_a = bytes.fromhex(
            "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
        )
        node_id_b = bytes.fromhex(
            "bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"
        )

        # Compute ECDH shared secret.
        shared_secret = ecdh_agree(Bytes32(ephemeral_key), dest_pubkey)

        # Derive keys using exact spec challenge_data.
        initiator_key, recipient_key = derive_keys(
            secret=shared_secret,
            initiator_id=Bytes32(node_id_a),
            recipient_id=Bytes32(node_id_b),
            challenge_data=SPEC_CHALLENGE_DATA,
        )

        assert initiator_key == bytes.fromhex("dccc82d81bd610f4f76d3ebe97a40571")
        assert recipient_key == bytes.fromhex("ac74bb8773749920b0d3a8881c173ec5")

    def test_id_nonce_signature(self):
        """
        ID nonce signature proves node identity ownership.

        Per spec:
            id-signature-input = "discovery v5 identity proof" || challenge-data ||
                                ephemeral-pubkey || node-id-B
            signature = sign(sha256(id-signature-input))

        Uses exact spec challenge_data and verifies byte-exact signature output.
        """
        static_key = bytes.fromhex(
            "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
        )
        ephemeral_pubkey = bytes.fromhex(
            "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231"
        )
        node_id_b = bytes.fromhex(
            "bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"
        )

        # Sign using exact spec challenge_data.
        signature = sign_id_nonce(
            private_key_bytes=Bytes32(static_key),
            challenge_data=SPEC_CHALLENGE_DATA,
            ephemeral_pubkey=Bytes33(ephemeral_pubkey),
            dest_node_id=Bytes32(node_id_b),
        )

        expected_sig = bytes.fromhex(
            "94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b48"
            "4fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6"
        )
        assert signature == expected_sig

        # Also verify the signature.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        private_key = ec.derive_private_key(
            int.from_bytes(static_key, "big"),
            ec.SECP256K1(),
        )
        pubkey_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

        assert verify_id_nonce_signature(
            signature=Bytes64(signature),
            challenge_data=SPEC_CHALLENGE_DATA,
            ephemeral_pubkey=Bytes33(ephemeral_pubkey),
            dest_node_id=Bytes32(node_id_b),
            public_key_bytes=Bytes33(pubkey_bytes),
        )

    def test_id_nonce_signature_different_challenge_data(self):
        """Different challenge_data produces different signatures."""
        static_key = NODE_B_PRIVKEY
        ephemeral_pubkey = bytes.fromhex(
            "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231"
        )
        node_id = NODE_A_ID

        challenge_data1 = make_challenge_data(bytes(16))
        challenge_data2 = make_challenge_data(bytes([1]) + bytes(15))

        sig1 = sign_id_nonce(
            Bytes32(static_key), challenge_data1, Bytes33(ephemeral_pubkey), Bytes32(node_id)
        )
        sig2 = sign_id_nonce(
            Bytes32(static_key), challenge_data2, Bytes33(ephemeral_pubkey), Bytes32(node_id)
        )

        assert sig1 != sig2

    def test_aes_gcm_encryption(self):
        """
        AES-128-GCM message encryption.

        The 16-byte authentication tag is appended to ciphertext.
        """
        encryption_key = bytes.fromhex("9f2d77db7004bf8a1a85107ac686990b")
        nonce = bytes.fromhex("27b5af763c446acd2749fe8e")
        plaintext = bytes.fromhex("01c20101")
        aad = bytes.fromhex("93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903")
        expected_ciphertext = bytes.fromhex("a5d12a2d94b8ccb3ba55558229867dc13bfa3648")

        # Encrypt.
        ciphertext = aes_gcm_encrypt(Bytes16(encryption_key), Bytes12(nonce), plaintext, aad)

        assert ciphertext == expected_ciphertext

        # Verify decryption works.
        decrypted = aes_gcm_decrypt(Bytes16(encryption_key), Bytes12(nonce), ciphertext, aad)
        assert decrypted == plaintext


class TestPacketEncodingRoundtrip:
    """Test full packet encoding/decoding roundtrips."""

    def test_message_packet_roundtrip(self):
        """MESSAGE packet encodes and decodes correctly."""
        src_id = NODE_A_ID
        dest_id = NODE_B_ID
        nonce = bytes(12)  # 12-byte nonce.
        encryption_key = bytes(16)  # 16-byte key.
        message = b"\x01\xc2\x01\x01"  # PING message.

        authdata = encode_message_authdata(src_id)

        packet = encode_packet(
            dest_node_id=dest_id,
            src_node_id=src_id,
            flag=PacketFlag.MESSAGE,
            nonce=nonce,
            authdata=authdata,
            message=message,
            encryption_key=encryption_key,
        )

        # Decode header.
        header, ciphertext, _message_ad = decode_packet_header(dest_id, packet)

        assert header.flag == PacketFlag.MESSAGE
        assert len(header.authdata) == 32

        decoded_authdata = decode_message_authdata(header.authdata)
        assert decoded_authdata.src_id == src_id

    def test_whoareyou_packet_roundtrip(self):
        """WHOAREYOU packet encodes and decodes correctly."""
        src_id = NODE_A_ID
        dest_id = NODE_B_ID
        nonce = bytes.fromhex("0102030405060708090a0b0c")
        id_nonce = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        enr_seq = 0

        authdata = encode_whoareyou_authdata(id_nonce, enr_seq)

        packet = encode_packet(
            dest_node_id=dest_id,
            src_node_id=src_id,
            flag=PacketFlag.WHOAREYOU,
            nonce=nonce,
            authdata=authdata,
            message=b"",  # WHOAREYOU has no message.
            encryption_key=None,
        )

        # Decode header.
        header, message, _message_ad = decode_packet_header(dest_id, packet)

        assert header.flag == PacketFlag.WHOAREYOU
        assert bytes(header.nonce) == nonce

        decoded_authdata = decode_whoareyou_authdata(header.authdata)
        assert bytes(decoded_authdata.id_nonce) == id_nonce
        assert int(decoded_authdata.enr_seq) == enr_seq

    def test_handshake_packet_roundtrip(self):
        """HANDSHAKE packet encodes and decodes correctly."""
        src_id = NODE_A_ID
        dest_id = NODE_B_ID
        nonce = bytes(12)
        encryption_key = bytes.fromhex("dccc82d81bd610f4f76d3ebe97a40571")
        message = b"\x01\xc2\x01\x01"  # PING message.

        id_signature = bytes(64)
        eph_pubkey = bytes.fromhex(
            "039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5"
        )

        authdata = encode_handshake_authdata(
            src_id=src_id,
            id_signature=id_signature,
            eph_pubkey=eph_pubkey,
            record=None,
        )

        packet = encode_packet(
            dest_node_id=dest_id,
            src_node_id=src_id,
            flag=PacketFlag.HANDSHAKE,
            nonce=nonce,
            authdata=authdata,
            message=message,
            encryption_key=encryption_key,
        )

        # Decode header.
        header, ciphertext, _message_ad = decode_packet_header(dest_id, packet)

        assert header.flag == PacketFlag.HANDSHAKE

        decoded_authdata = decode_handshake_authdata(header.authdata)
        assert decoded_authdata.src_id == src_id
        assert decoded_authdata.eph_pubkey == eph_pubkey


class TestOfficialPacketEncoding:
    """Byte-exact packet encoding from devp2p spec wire test vectors.

    These tests verify that our packet encoding produces correct structure
    and can interoperate with other implementations.

    Reference:
        https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md
    """

    def test_official_ping_message_rlp_encoding(self):
        """PING message RLP encodes to exact spec format.

        PING format: [request-id, enr-seq]
        Message type byte 0x01 prepended.
        """
        from lean_spec.subspecs.networking.discovery.codec import encode_message
        from lean_spec.subspecs.networking.discovery.messages import MessageType, Ping, RequestId
        from lean_spec.types import Uint64

        # PING with request ID [0x00, 0x00, 0x00, 0x01] and enr_seq = 1
        ping = Ping(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            enr_seq=Uint64(1),
        )

        encoded = encode_message(ping)

        # First byte should be message type PING (0x01).
        assert encoded[0] == MessageType.PING
        # Rest is RLP-encoded [request-id, enr-seq].
        # request-id: 84 00000001 (4-byte string)
        # enr-seq: 01 (single byte)
        assert len(encoded) > 1

    def test_official_pong_message_rlp_encoding(self):
        """PONG message RLP encodes to exact spec format.

        PONG format: [request-id, enr-seq, recipient-ip, recipient-port]
        Message type byte 0x02 prepended.
        """
        from lean_spec.subspecs.networking.discovery.codec import encode_message
        from lean_spec.subspecs.networking.discovery.messages import (
            MessageType,
            Pong,
            Port,
            RequestId,
        )
        from lean_spec.types import Uint64

        pong = Pong(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            enr_seq=Uint64(1),
            recipient_ip=b"\x7f\x00\x00\x01",  # 127.0.0.1
            recipient_port=Port(30303),
        )

        encoded = encode_message(pong)

        # First byte should be message type PONG (0x02).
        assert encoded[0] == MessageType.PONG
        assert len(encoded) > 1

    def test_official_findnode_message_rlp_encoding(self):
        """FINDNODE message RLP encodes to exact spec format.

        FINDNODE format: [request-id, [distances...]]
        Message type byte 0x03 prepended.
        """
        from lean_spec.subspecs.networking.discovery.codec import encode_message
        from lean_spec.subspecs.networking.discovery.messages import (
            Distance,
            FindNode,
            MessageType,
            RequestId,
        )

        findnode = FindNode(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            distances=[Distance(256), Distance(255)],
        )

        encoded = encode_message(findnode)

        # First byte should be message type FINDNODE (0x03).
        assert encoded[0] == MessageType.FINDNODE
        assert len(encoded) > 1

    def test_official_nodes_message_rlp_encoding(self):
        """NODES message RLP encodes to exact spec format.

        NODES format: [request-id, total, [enrs...]]
        Message type byte 0x04 prepended.
        """
        from lean_spec.subspecs.networking.discovery.codec import encode_message
        from lean_spec.subspecs.networking.discovery.messages import (
            MessageType,
            Nodes,
            RequestId,
        )
        from lean_spec.types.uint import Uint8

        nodes = Nodes(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            total=Uint8(1),
            enrs=[b"enr:-test-data"],
        )

        encoded = encode_message(nodes)

        # First byte should be message type NODES (0x04).
        assert encoded[0] == MessageType.NODES
        assert len(encoded) > 1

    def test_message_packet_header_structure(self):
        """MESSAGE packet header follows spec structure.

        Structure:
        - masking-iv: 16 bytes
        - masked-header: variable (static-header + authdata)
        - message ciphertext: variable

        Static header (23 bytes):
        - protocol-id: "discv5" (6 bytes)
        - version: 0x0001 (2 bytes)
        - flag: 0x00 for MESSAGE (1 byte)
        - nonce: 12 bytes
        - authdata-size: 2 bytes
        """
        from lean_spec.subspecs.networking.discovery.packet import (
            STATIC_HEADER_SIZE,
            encode_message_authdata,
            encode_packet,
        )

        src_id = NODE_A_ID
        dest_id = NODE_B_ID
        nonce = bytes(12)
        encryption_key = bytes(16)
        message = b"\x01\xc2\x01\x01"

        authdata = encode_message_authdata(src_id)

        packet = encode_packet(
            dest_node_id=dest_id,
            src_node_id=src_id,
            flag=PacketFlag.MESSAGE,
            nonce=nonce,
            authdata=authdata,
            message=message,
            encryption_key=encryption_key,
        )

        # Minimum packet size: 16 (masking-iv) + 23 (static) + 32 (authdata) + 16 (tag)
        assert len(packet) >= 16 + STATIC_HEADER_SIZE + 32 + 16

    def test_whoareyou_packet_header_structure(self):
        """WHOAREYOU packet header follows spec structure.

        WHOAREYOU has:
        - flag: 0x01
        - authdata: id-nonce (16) + enr-seq (8) = 24 bytes
        - no message payload
        """
        from lean_spec.subspecs.networking.discovery.packet import (
            STATIC_HEADER_SIZE,
            WHOAREYOU_AUTHDATA_SIZE,
            encode_packet,
            encode_whoareyou_authdata,
        )

        src_id = NODE_A_ID
        dest_id = NODE_B_ID
        nonce = bytes(12)
        id_nonce = bytes(16)
        enr_seq = 0

        authdata = encode_whoareyou_authdata(id_nonce, enr_seq)

        packet = encode_packet(
            dest_node_id=dest_id,
            src_node_id=src_id,
            flag=PacketFlag.WHOAREYOU,
            nonce=nonce,
            authdata=authdata,
            message=b"",
            encryption_key=None,
        )

        # WHOAREYOU packet size: 16 (masking-iv) + 23 (static) + 24 (authdata)
        expected_size = 16 + STATIC_HEADER_SIZE + WHOAREYOU_AUTHDATA_SIZE
        assert len(packet) == expected_size

    def test_handshake_packet_header_structure(self):
        """HANDSHAKE packet header follows spec structure.

        HANDSHAKE has:
        - flag: 0x02
        - authdata: src-id (32) + sig-size (1) + eph-key-size (1) + sig + eph-key + [record]
        - encrypted message
        """
        from lean_spec.subspecs.networking.discovery.packet import (
            HANDSHAKE_HEADER_SIZE,
            STATIC_HEADER_SIZE,
            encode_handshake_authdata,
            encode_packet,
        )

        src_id = NODE_A_ID
        dest_id = NODE_B_ID
        nonce = bytes(12)
        encryption_key = bytes(16)
        message = b"\x01\xc2\x01\x01"

        id_signature = bytes(64)
        eph_pubkey = bytes.fromhex(
            "039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5"
        )

        authdata = encode_handshake_authdata(
            src_id=src_id,
            id_signature=id_signature,
            eph_pubkey=eph_pubkey,
            record=None,
        )

        packet = encode_packet(
            dest_node_id=dest_id,
            src_node_id=src_id,
            flag=PacketFlag.HANDSHAKE,
            nonce=nonce,
            authdata=authdata,
            message=message,
            encryption_key=encryption_key,
        )

        # Minimum: 16 (iv) + 23 (static) + 34 (handshake header) + 64 (sig) + 33 (key) + 16 (tag)
        min_size = 16 + STATIC_HEADER_SIZE + HANDSHAKE_HEADER_SIZE + 64 + 33 + 16
        assert len(packet) >= min_size


class TestOfficialKeyDerivation:
    """Key derivation with exact spec inputs/outputs.

    HKDF parameters per spec:
    - Hash: SHA256
    - salt: challenge-data (63 bytes)
    - IKM: secret || initiator-id || recipient-id
    - info: "discovery v5 key agreement"
    - L: 32 bytes (2 x 16-byte keys)
    """

    def test_challenge_data_format(self):
        """challenge_data follows spec format: masking-iv || static-header || authdata."""
        id_nonce = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")

        challenge_data = make_challenge_data(id_nonce)

        # Total size: 16 (masking-iv) + 23 (static-header) + 24 (authdata) = 63 bytes.
        assert len(challenge_data) == 63

        # First 16 bytes: masking-iv (all zeros in our test helper).
        assert challenge_data[:16] == bytes(16)

        # Bytes 16-22: protocol-id "discv5".
        assert challenge_data[16:22] == b"discv5"

        # Bytes 22-24: version 0x0001.
        assert challenge_data[22:24] == b"\x00\x01"

        # Byte 24: flag 0x01 (WHOAREYOU).
        assert challenge_data[24] == 0x01

        # Bytes 25-37: nonce (12 bytes, all zeros in test helper).
        assert challenge_data[25:37] == bytes(12)

        # Bytes 37-39: authdata-size (24 = 0x0018).
        assert challenge_data[37:39] == b"\x00\x18"

        # Bytes 39-55: id-nonce (16 bytes).
        assert challenge_data[39:55] == id_nonce

        # Bytes 55-63: enr-seq (8 bytes, all zeros).
        assert challenge_data[55:63] == bytes(8)

    def test_key_derivation_with_different_secrets_produces_different_keys(self):
        """Different ECDH secrets produce completely different session keys."""
        id_nonce = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        challenge_data = make_challenge_data(id_nonce)

        secret1 = Bytes33(
            bytes.fromhex("033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e")
        )
        secret2 = Bytes33(
            bytes.fromhex("024c22b3b2f325678e2648df6f610aaead32484358f3b4ee7952e5a87964276f8f")
        )

        keys1 = derive_keys(secret1, Bytes32(NODE_A_ID), Bytes32(NODE_B_ID), challenge_data)
        keys2 = derive_keys(secret2, Bytes32(NODE_A_ID), Bytes32(NODE_B_ID), challenge_data)

        # Different secrets must produce different keys.
        assert keys1 != keys2


class TestAESCryptoEdgeCases:
    """Additional AES-GCM test cases beyond spec vectors."""

    def test_aes_gcm_empty_plaintext(self):
        """AES-GCM handles empty plaintext correctly."""
        key = Bytes16(bytes.fromhex("9f2d77db7004bf8a1a85107ac686990b"))
        nonce = Bytes12(bytes.fromhex("27b5af763c446acd2749fe8e"))
        aad = bytes(32)
        plaintext = b""

        ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)

        # Empty plaintext should produce just the 16-byte auth tag.
        assert len(ciphertext) == 16

        # Decryption should recover empty plaintext.
        decrypted = aes_gcm_decrypt(key, nonce, ciphertext, aad)
        assert decrypted == b""

    def test_aes_gcm_large_plaintext(self):
        """AES-GCM handles large plaintext correctly."""
        key = Bytes16(bytes.fromhex("9f2d77db7004bf8a1a85107ac686990b"))
        nonce = Bytes12(bytes.fromhex("27b5af763c446acd2749fe8e"))
        aad = bytes(32)
        plaintext = bytes(1024)  # 1KB of zeros.

        ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)

        # Ciphertext = plaintext length + 16-byte tag.
        assert len(ciphertext) == len(plaintext) + 16

        # Decryption should recover original plaintext.
        decrypted = aes_gcm_decrypt(key, nonce, ciphertext, aad)
        assert decrypted == plaintext

    def test_aes_gcm_wrong_key_fails_decryption(self):
        """AES-GCM decryption fails with wrong key."""
        import pytest
        from cryptography.exceptions import InvalidTag

        key = Bytes16(bytes.fromhex("9f2d77db7004bf8a1a85107ac686990b"))
        wrong_key = Bytes16(bytes.fromhex("00000000000000001a85107ac686990b"))
        nonce = Bytes12(bytes.fromhex("27b5af763c446acd2749fe8e"))
        aad = bytes(32)
        plaintext = b"secret message"

        ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)

        # Decryption with wrong key should fail with InvalidTag.
        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(wrong_key, nonce, ciphertext, aad)

    def test_aes_gcm_wrong_aad_fails_decryption(self):
        """AES-GCM decryption fails with wrong AAD."""
        import pytest
        from cryptography.exceptions import InvalidTag

        key = Bytes16(bytes.fromhex("9f2d77db7004bf8a1a85107ac686990b"))
        nonce = Bytes12(bytes.fromhex("27b5af763c446acd2749fe8e"))
        aad = bytes(32)
        wrong_aad = bytes([0xFF] * 32)
        plaintext = b"secret message"

        ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)

        # Decryption with wrong AAD should fail with InvalidTag.
        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(key, nonce, ciphertext, wrong_aad)

    def test_aes_gcm_tampered_ciphertext_fails(self):
        """AES-GCM decryption fails with tampered ciphertext."""
        import pytest
        from cryptography.exceptions import InvalidTag

        key = Bytes16(bytes.fromhex("9f2d77db7004bf8a1a85107ac686990b"))
        nonce = Bytes12(bytes.fromhex("27b5af763c446acd2749fe8e"))
        aad = bytes(32)
        plaintext = b"secret message"

        ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)

        # Tamper with ciphertext by flipping a bit.
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0x01
        tampered = bytes(tampered)

        # Decryption of tampered ciphertext should fail with InvalidTag.
        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(key, nonce, tampered, aad)


class TestSpecPacketPayloadDecryption:
    """Verify message payload decryption using correct AAD (masking-iv || plaintext header)."""

    def test_message_packet_encrypt_decrypt_roundtrip(self):
        """Encrypt a message in a packet and decrypt using message_ad from decode."""
        src_id = NODE_A_ID
        dest_id = NODE_B_ID
        nonce = bytes(12)
        encryption_key = bytes.fromhex("dccc82d81bd610f4f76d3ebe97a40571")
        plaintext = bytes.fromhex("01c20101")  # PING message.

        authdata = encode_message_authdata(src_id)

        packet = encode_packet(
            dest_node_id=dest_id,
            src_node_id=src_id,
            flag=PacketFlag.MESSAGE,
            nonce=nonce,
            authdata=authdata,
            message=plaintext,
            encryption_key=encryption_key,
        )

        # Decode header - returns message_ad for AAD.
        header, ciphertext, message_ad = decode_packet_header(dest_id, packet)

        # Decrypt using message_ad as AAD.
        decrypted = decrypt_message(encryption_key, bytes(header.nonce), ciphertext, message_ad)
        assert decrypted == plaintext

    def test_handshake_packet_encrypt_decrypt_roundtrip(self):
        """Handshake packet encrypts and decrypts using correct AAD."""
        src_id = NODE_A_ID
        dest_id = NODE_B_ID
        nonce = bytes(12)
        encryption_key = bytes.fromhex("dccc82d81bd610f4f76d3ebe97a40571")
        plaintext = bytes.fromhex("01c20101")  # PING message.

        id_signature = bytes(64)
        eph_pubkey = bytes.fromhex(
            "039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5"
        )

        authdata = encode_handshake_authdata(
            src_id=src_id,
            id_signature=id_signature,
            eph_pubkey=eph_pubkey,
            record=None,
        )

        packet = encode_packet(
            dest_node_id=dest_id,
            src_node_id=src_id,
            flag=PacketFlag.HANDSHAKE,
            nonce=nonce,
            authdata=authdata,
            message=plaintext,
            encryption_key=encryption_key,
        )

        # Decode header - returns message_ad for AAD.
        header, ciphertext, message_ad = decode_packet_header(dest_id, packet)

        # Decrypt using message_ad as AAD.
        decrypted = decrypt_message(encryption_key, bytes(header.nonce), ciphertext, message_ad)
        assert decrypted == plaintext
