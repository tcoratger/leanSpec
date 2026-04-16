"""Discovery v5 cryptographic primitive test fixture.

Generates JSON test vectors for the cryptographic operations used in
Discovery v5 peer discovery. All clients must produce identical outputs
for ECDH, key derivation, signing, and encryption to interoperate.
"""

from typing import Any, ClassVar

from lean_spec.subspecs.networking.discovery.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    ecdh_agree,
    sign_id_nonce,
    verify_id_nonce_signature,
)
from lean_spec.subspecs.networking.discovery.keys import compute_node_id, derive_keys
from lean_spec.types import Bytes12, Bytes16, Bytes32, Bytes33, Bytes64, Bytes65

from .base import BaseConsensusFixture


def _to_hex(data: bytes) -> str:
    return "0x" + data.hex()


def _from_hex(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.removeprefix("0x"))


class DiscoveryCryptoTest(BaseConsensusFixture):
    """Fixture for Discovery v5 cryptographic conformance.

    Tests deterministic crypto operations: ECDH, HKDF key derivation,
    ID nonce signing/verification, AES-GCM, and node ID computation.

    JSON output: operation, input, output.
    """

    format_name: ClassVar[str] = "discovery_crypto"
    description: ClassVar[str] = "Tests Discovery v5 cryptographic primitives"

    operation: str
    """Crypto operation: ecdh, key_derivation, id_nonce_sign,
    id_nonce_verify, aes_gcm_encrypt, or node_id."""

    input: dict[str, Any]
    """Operation-specific input parameters (hex-encoded bytes)."""

    output: dict[str, Any] = {}
    """Computed output. Filled by make_fixture."""

    def make_fixture(self) -> "DiscoveryCryptoTest":
        """Dispatch to the operation handler and produce computed output."""
        match self.operation:
            case "ecdh":
                output = self._make_ecdh()
            case "key_derivation":
                output = self._make_key_derivation()
            case "id_nonce_sign":
                output = self._make_id_nonce_sign()
            case "id_nonce_verify":
                output = self._make_id_nonce_verify()
            case "aes_gcm_encrypt":
                output = self._make_aes_gcm_encrypt()
            case "node_id":
                output = self._make_node_id()
            case _:
                raise ValueError(f"Unknown operation: {self.operation}")
        return self.model_copy(update={"output": output})

    def _make_ecdh(self) -> dict[str, Any]:
        """Compute ECDH shared secret from private key and public key."""
        private_key = Bytes32(_from_hex(self.input["privateKey"]))
        public_key_raw = _from_hex(self.input["publicKey"])
        public_key: Bytes33 | Bytes65
        if len(public_key_raw) == 33:
            public_key = Bytes33(public_key_raw)
        else:
            public_key = Bytes65(public_key_raw)

        shared_secret = ecdh_agree(private_key, public_key)
        return {"sharedSecret": _to_hex(shared_secret)}

    def _make_key_derivation(self) -> dict[str, Any]:
        """Derive session keys via HKDF from shared secret and IDs."""
        secret = Bytes33(_from_hex(self.input["sharedSecret"]))
        initiator_id = Bytes32(_from_hex(self.input["initiatorId"]))
        recipient_id = Bytes32(_from_hex(self.input["recipientId"]))
        challenge_data = _from_hex(self.input["challengeData"])

        initiator_key, recipient_key = derive_keys(
            secret, initiator_id, recipient_id, challenge_data
        )
        return {
            "initiatorKey": _to_hex(initiator_key),
            "recipientKey": _to_hex(recipient_key),
        }

    def _make_id_nonce_sign(self) -> dict[str, Any]:
        """Sign an ID nonce for handshake authentication."""
        private_key = Bytes32(_from_hex(self.input["privateKey"]))
        challenge_data = _from_hex(self.input["challengeData"])
        ephemeral_pubkey = Bytes33(_from_hex(self.input["ephemeralPubkey"]))
        dest_node_id = Bytes32(_from_hex(self.input["destNodeId"]))

        signature = sign_id_nonce(private_key, challenge_data, ephemeral_pubkey, dest_node_id)

        # Cross-check: signature must verify against the signer's public key.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        priv = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
        pubkey = Bytes33(
            priv.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            )
        )
        assert verify_id_nonce_signature(
            signature, challenge_data, ephemeral_pubkey, dest_node_id, pubkey
        ), "Signature failed self-verification"

        return {"signature": _to_hex(signature)}

    def _make_id_nonce_verify(self) -> dict[str, Any]:
        """Verify an ID nonce signature."""
        signature = Bytes64(_from_hex(self.input["signature"]))
        challenge_data = _from_hex(self.input["challengeData"])
        ephemeral_pubkey = Bytes33(_from_hex(self.input["ephemeralPubkey"]))
        dest_node_id = Bytes32(_from_hex(self.input["destNodeId"]))
        public_key = Bytes33(_from_hex(self.input["publicKey"]))

        valid = verify_id_nonce_signature(
            signature, challenge_data, ephemeral_pubkey, dest_node_id, public_key
        )
        return {"valid": valid}

    def _make_aes_gcm_encrypt(self) -> dict[str, Any]:
        """Encrypt with AES-128-GCM, verify roundtrip via decrypt."""
        key = Bytes16(_from_hex(self.input["key"]))
        nonce = Bytes12(_from_hex(self.input["nonce"]))
        plaintext = _from_hex(self.input["plaintext"])
        aad = _from_hex(self.input["aad"])

        ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)

        # Roundtrip: decrypt must recover original plaintext.
        decrypted = aes_gcm_decrypt(key, nonce, ciphertext, aad)
        assert decrypted == plaintext, "AES-GCM roundtrip produced different bytes"

        return {"ciphertext": _to_hex(ciphertext)}

    def _make_node_id(self) -> dict[str, Any]:
        """Compute node ID from public key via keccak256."""
        public_key_raw = _from_hex(self.input["publicKey"])
        public_key: Bytes33 | Bytes65
        if len(public_key_raw) == 33:
            public_key = Bytes33(public_key_raw)
        else:
            public_key = Bytes65(public_key_raw)

        node_id = compute_node_id(public_key)
        return {"nodeId": _to_hex(node_id)}
