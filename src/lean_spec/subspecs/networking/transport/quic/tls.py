"""
libp2p TLS certificate generation and verification.

libp2p uses TLS 1.3 with a custom extension to bind peer IDs to TLS certificates.
Each peer:
    1. Generates an ephemeral TLS key pair (P-256 or Ed25519)
    2. Creates a self-signed certificate with the libp2p extension
    3. The extension contains a signature proving identity key ownership

The extension format (OID 1.3.6.1.4.1.53594.1.1):
    - protobuf-encoded PublicKey (identity key)
    - signature over "libp2p-tls-handshake:" + TLS public key bytes

Why this design? TLS certificates are normally validated against a CA. libp2p
has no CA - peers prove identity through cryptographic signatures. The extension
binds the TLS key to the libp2p identity key.

References:
    - libp2p TLS spec: https://github.com/libp2p/specs/blob/master/tls/tls.md
    - OID registry: 1.3.6.1.4.1.53594 is assigned to Protocol Labs
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lean_spec.subspecs.networking import varint

from ..identity import IdentityKeypair, Secp256k1PublicKey
from ..peer_id import KeyType, PeerId, PublicKeyProto

LIBP2P_EXTENSION_OID: Final = x509.ObjectIdentifier("1.3.6.1.4.1.53594.1.1")
"""libp2p TLS extension OID (Protocol Labs assigned)."""

SIGNATURE_PREFIX: Final = b"libp2p-tls-handshake:"
"""
Prefix for the signed payload.

The signature proves ownership of the identity key over this specific TLS key.
Without a prefix, the signature could potentially be replayed in other contexts.
"""

# Key type identifiers matching libp2p protobuf definitions
KEY_TYPE_SECP256K1: Final = 2
"""secp256k1 key type in libp2p protobuf."""


def generate_libp2p_certificate(
    identity_key: IdentityKeypair,
) -> tuple[bytes, bytes, x509.Certificate]:
    """
    Generate a self-signed certificate with libp2p extension.

    Creates an ephemeral P-256 TLS key pair and a certificate containing:
        - Random subject/issuer (privacy - doesn't reveal identity)
        - Short validity (security - limits key exposure)
        - libp2p extension with identity proof

    Args:
        identity_key: secp256k1 identity keypair for signing.

    Returns:
        (private_key_pem, certificate_pem, certificate) tuple.
    """
    # Generate ephemeral P-256 key for TLS.
    #
    # Why P-256 and not secp256k1?
    #   1. P-256 has better TLS library support
    #   2. TLS key is ephemeral, only used for this connection
    #   3. secp256k1 identity is proven via the extension signature
    tls_private = ec.generate_private_key(ec.SECP256R1())
    tls_public = tls_private.public_key()

    # Get TLS public key bytes for signing.
    #
    # The signature binds our identity key to this specific TLS key.
    # We use the SubjectPublicKeyInfo format (DER-encoded public key).
    tls_public_bytes = tls_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Create the libp2p extension payload.
    #
    # Format: protobuf-encoded SignedKey message
    #   - PublicKey: our secp256k1 identity public key
    #   - Signature: over (prefix + tls_public_bytes)
    extension_payload = _create_extension_payload(identity_key, tls_public_bytes)

    # Build the certificate.
    #
    # Empty subject/issuer to match rust-libp2p's format.
    # The peer identity is proven via the libp2p extension, not the DN.
    # Short validity (1 hour) limits key compromise exposure.
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([])

    # Compute Subject Key Identifier from public key.
    #
    # SKI is the SHA-256 hash of the TLS public key, truncated to 20 bytes.
    # This matches webpki's expected format for self-signed certificates.
    ski_digest = hashlib.sha256(tls_public_bytes).digest()[:20]

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(tls_public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))  # Allow clock skew
        .not_valid_after(now + timedelta(days=365))  # Longer validity like rcgen
        # Subject Key Identifier for self-signed certificate validation.
        .add_extension(
            x509.SubjectKeyIdentifier(ski_digest),
            critical=False,
        )
        # libp2p extension with identity proof.
        #
        # NOT marked critical so that standard TLS libraries don't reject it
        # before the libp2p verifier can check it.
        .add_extension(
            x509.UnrecognizedExtension(LIBP2P_EXTENSION_OID, extension_payload),
            critical=False,
        )
        .sign(tls_private, hashes.SHA256())
    )

    # Serialize to PEM for aioquic configuration.
    private_pem = tls_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    return private_pem, cert_pem, cert


def _create_extension_payload(
    identity_key: IdentityKeypair,
    tls_public_bytes: bytes,
) -> bytes:
    """
    Create the libp2p extension payload.

    The extension uses ASN.1 DER encoding:

        SignedKey ::= SEQUENCE {
            publicKey OCTET STRING,  -- protobuf-encoded PublicKey
            signature OCTET STRING   -- raw r||s signature
        }

    The publicKey OCTET STRING contains a protobuf-encoded PublicKey message:

        message PublicKey {
            KeyType Type = 1;
            bytes Data = 2;
        }
    """
    # Get compressed public key (33 bytes for secp256k1).
    public_key_compressed = identity_key.public_key.to_bytes()

    # Create signature over (prefix + tls_public_bytes).
    #
    # The signature format: py-libp2p uses DER-encoded signatures
    # (via coincurve), so we keep the DER format from our sign() method.
    to_sign = SIGNATURE_PREFIX + tls_public_bytes
    signature = identity_key.sign(to_sign)  # DER-encoded signature

    # Encode PublicKey as protobuf.
    #   Field 1 (Type): tag=0x08, value=2 (secp256k1)
    #   Field 2 (Data): tag=0x12, length, bytes
    public_key_proto = (
        bytes([0x08, KEY_TYPE_SECP256K1, 0x12, len(public_key_compressed)]) + public_key_compressed
    )

    # Encode as ASN.1 DER SEQUENCE.
    #
    # SignedKey ::= SEQUENCE {
    #     publicKey OCTET STRING,
    #     signature OCTET STRING
    # }
    return _encode_asn1_signed_key(public_key_proto, signature)


def _encode_asn1_signed_key(public_key_proto: bytes, signature: bytes) -> bytes:
    """
    Encode SignedKey as ASN.1 DER.

    ASN.1 structure:
        SEQUENCE {
            OCTET STRING (public_key_proto),
            OCTET STRING (signature)
        }
    """
    # Encode the two OCTET STRINGs.
    octet1 = _encode_asn1_octet_string(public_key_proto)
    octet2 = _encode_asn1_octet_string(signature)

    # Encode the SEQUENCE.
    content = octet1 + octet2
    return _encode_asn1_sequence(content)


def _encode_asn1_octet_string(data: bytes) -> bytes:
    """Encode bytes as ASN.1 OCTET STRING."""
    # Tag 0x04 = OCTET STRING
    return bytes([0x04]) + _encode_asn1_length(len(data)) + data


def _encode_asn1_sequence(content: bytes) -> bytes:
    """Encode content as ASN.1 SEQUENCE."""
    # Tag 0x30 = SEQUENCE
    return bytes([0x30]) + _encode_asn1_length(len(content)) + content


def _encode_asn1_length(length: int) -> bytes:
    """Encode length in ASN.1 DER format."""
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    else:
        return bytes([0x82, length >> 8, length & 0xFF])


class PeerVerificationError(Exception):
    """Raised when the libp2p TLS extension fails to validate."""


def verify_libp2p_certificate(cert: x509.Certificate) -> PeerId:
    """
    Extract and verify the peer identity from a libp2p TLS certificate.

    The certificate carries the libp2p extension (OID 1.3.6.1.4.1.53594.1.1).
    The extension contains a SignedKey envelope binding the peer's identity
    public key to the TLS public key:

        SignedKey ::= SEQUENCE {
            publicKey OCTET STRING,  -- protobuf-encoded PublicKey
            signature OCTET STRING   -- ECDSA over prefix || tls_pub_der
        }

    The signature proves the identity-key holder controls the TLS key.

    Args:
        cert: Peer's leaf X.509 certificate from the QUIC handshake.

    Returns:
        Canonical PeerId derived from the verified identity public key.

    Raises:
        PeerVerificationError: if the extension is missing, malformed, the
            signature does not verify, or the key type is unsupported.
    """
    # Locate the libp2p extension.
    try:
        ext = cert.extensions.get_extension_for_oid(LIBP2P_EXTENSION_OID)
    except x509.ExtensionNotFound as exc:
        raise PeerVerificationError("libp2p extension missing from certificate") from exc

    if not isinstance(ext.value, x509.UnrecognizedExtension):
        raise PeerVerificationError("libp2p extension has unexpected type")

    # Parse the ASN.1 SignedKey envelope.
    public_key_proto, signature = _parse_asn1_signed_key(ext.value.value)

    # Decode the protobuf PublicKey.
    key_type, key_data = _decode_protobuf_public_key(public_key_proto)

    # The spec allows multiple key types, but only secp256k1 is used today.
    if key_type != KeyType.SECP256K1:
        raise PeerVerificationError(f"unsupported libp2p key type: {key_type}")

    # Reconstruct the identity public key from the compressed point.
    try:
        identity_key = Secp256k1PublicKey(
            _key=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), key_data)
        )
    except ValueError as exc:
        raise PeerVerificationError(f"invalid secp256k1 public key: {exc}") from exc

    # Extract the TLS public key as SubjectPublicKeyInfo DER.
    #
    # The signature was computed over (prefix || SubjectPublicKeyInfo DER)
    # by the certificate generator, so we must reproduce the same bytes here.
    tls_public_bytes = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if not identity_key.verify(SIGNATURE_PREFIX + tls_public_bytes, signature):
        raise PeerVerificationError("libp2p extension signature failed verification")

    # Derive the canonical PeerId via the protobuf-encoded identity key.
    return PeerId.from_public_key(PublicKeyProto(key_type=key_type, key_data=key_data))


def _parse_asn1_signed_key(payload: bytes) -> tuple[bytes, bytes]:
    """
    Parse the SignedKey envelope.

    Mirrors _encode_asn1_signed_key. Accepts the three DER length forms used
    by the encoder (short, 0x81, 0x82) and rejects any other form.

    Returns:
        (public_key_proto_bytes, signature_bytes) tuple.

    Raises:
        PeerVerificationError: if the envelope is malformed.
    """
    # Outer SEQUENCE.
    body, rest = _parse_asn1_tlv(payload, expected_tag=0x30)
    if rest:
        raise PeerVerificationError("trailing bytes after SignedKey SEQUENCE")

    # Two OCTET STRINGs inside the SEQUENCE.
    public_key_proto, after_first = _parse_asn1_tlv(body, expected_tag=0x04)
    signature, after_second = _parse_asn1_tlv(after_first, expected_tag=0x04)
    if after_second:
        raise PeerVerificationError("trailing bytes after SignedKey contents")

    return public_key_proto, signature


def _parse_asn1_tlv(data: bytes, *, expected_tag: int) -> tuple[bytes, bytes]:
    """
    Parse a single ASN.1 TLV with the given tag and return (value, rest).

    Raises:
        PeerVerificationError: if the data is truncated, the tag mismatches,
            or the length uses an unsupported encoding form.
    """
    if not data:
        raise PeerVerificationError("ASN.1 TLV truncated at tag")
    if data[0] != expected_tag:
        raise PeerVerificationError(
            f"ASN.1 tag mismatch: expected 0x{expected_tag:02x}, got 0x{data[0]:02x}"
        )

    length, length_size = _decode_asn1_length(data[1:])
    start = 1 + length_size
    end = start + length
    if end > len(data):
        raise PeerVerificationError("ASN.1 TLV truncated at value")
    return data[start:end], data[end:]


def _decode_asn1_length(data: bytes) -> tuple[int, int]:
    """
    Decode an ASN.1 DER length and return (length, bytes_consumed).

    Only the three forms emitted by _encode_asn1_length are accepted:
        - short form (length < 128, single byte)
        - long-1 form (0x81 + 1 byte)
        - long-2 form (0x82 + 2 bytes)
    """
    if not data:
        raise PeerVerificationError("ASN.1 length truncated")

    first = data[0]
    if first < 0x80:
        return first, 1
    if first == 0x81:
        if len(data) < 2:
            raise PeerVerificationError("ASN.1 long-1 length truncated")
        return data[1], 2
    if first == 0x82:
        if len(data) < 3:
            raise PeerVerificationError("ASN.1 long-2 length truncated")
        return (data[1] << 8) | data[2], 3
    raise PeerVerificationError(f"unsupported ASN.1 length form: 0x{first:02x}")


def _decode_protobuf_public_key(payload: bytes) -> tuple[KeyType, bytes]:
    """
    Decode the protobuf PublicKey message.

    Wire format (deterministic encoding, fields in tag order):

        [0x08][type_varint][0x12][length_varint][key_bytes]

    Returns:
        (key_type, key_data) tuple.

    Raises:
        PeerVerificationError: on truncation, missing field, or unknown tag.
    """
    if len(payload) < 2 or payload[0] != 0x08:
        raise PeerVerificationError("protobuf PublicKey: missing Type tag")
    try:
        type_value, type_size = varint.decode_varint(payload, offset=1)
    except varint.VarintError as exc:
        raise PeerVerificationError(f"protobuf PublicKey Type: {exc}") from exc

    try:
        key_type = KeyType(type_value)
    except ValueError as exc:
        raise PeerVerificationError(f"protobuf PublicKey: unknown KeyType {type_value}") from exc

    data_start = 1 + type_size
    if data_start >= len(payload) or payload[data_start] != 0x12:
        raise PeerVerificationError("protobuf PublicKey: missing Data tag")
    try:
        data_length, length_size = varint.decode_varint(payload, offset=data_start + 1)
    except varint.VarintError as exc:
        raise PeerVerificationError(f"protobuf PublicKey Data length: {exc}") from exc

    key_start = data_start + 1 + length_size
    key_end = key_start + data_length
    if key_end > len(payload):
        raise PeerVerificationError("protobuf PublicKey: Data truncated")
    if key_end != len(payload):
        raise PeerVerificationError("protobuf PublicKey: trailing bytes after Data")
    return key_type, payload[key_start:key_end]
