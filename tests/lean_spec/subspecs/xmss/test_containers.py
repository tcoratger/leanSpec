"""
Tests for XMSS container serialization and deserialization.
"""

import pytest

from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss.constants import PROD_CONFIG, TEST_CONFIG
from lean_spec.subspecs.xmss.containers import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
    PublicKey,
    Signature,
)


class TestPublicKey:
    """Tests for PublicKey serialization and deserialization."""

    def test_bytes_protocol(self) -> None:
        """Test that PublicKey implements Python's bytes protocol."""
        root = HashDigestVector(data=[Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)])
        parameter = Parameter(data=[Fp(value=i + 100) for i in range(TEST_CONFIG.PARAMETER_LEN)])
        pk = PublicKey(root=root, parameter=parameter)

        # Test __bytes__()
        data = bytes(pk)
        assert isinstance(data, bytes)
        assert len(data) == TEST_CONFIG.PUBLIC_KEY_LEN_BYTES

    def test_to_bytes_with_validation(self) -> None:
        """Test that to_bytes validates field lengths."""
        root = HashDigestVector(data=[Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)])
        parameter = Parameter(data=[Fp(value=i) for i in range(TEST_CONFIG.PARAMETER_LEN)])
        pk = PublicKey(root=root, parameter=parameter)

        # Valid serialization
        data = pk.to_bytes(TEST_CONFIG)
        assert len(data) == TEST_CONFIG.PUBLIC_KEY_LEN_BYTES

        # Invalid root length - HashDigestVector validates length at construction
        with pytest.raises(ValueError, match="requires exactly"):
            HashDigestVector(data=[Fp(value=0)] * 5)

        # Invalid parameter length - Parameter validates length at construction
        with pytest.raises(ValueError, match="requires exactly"):
            Parameter(data=[Fp(value=0)] * 3)

    def test_roundtrip_test_config(self) -> None:
        """Test serialization round-trip with TEST_CONFIG."""
        root = HashDigestVector(data=[Fp(value=i * 10) for i in range(TEST_CONFIG.HASH_LEN_FE)])
        parameter = Parameter(data=[Fp(value=i * 20) for i in range(TEST_CONFIG.PARAMETER_LEN)])
        original = PublicKey(root=root, parameter=parameter)

        # Serialize and deserialize
        data = original.to_bytes(TEST_CONFIG)
        recovered = PublicKey.from_bytes(data, TEST_CONFIG)

        assert recovered.root == original.root
        assert recovered.parameter == original.parameter
        assert recovered == original

    def test_roundtrip_prod_config(self) -> None:
        """Test serialization round-trip with PROD_CONFIG."""
        root = HashDigestVector(data=[Fp(value=i) for i in range(PROD_CONFIG.HASH_LEN_FE)])
        parameter = Parameter(data=[Fp(value=i + 1000) for i in range(PROD_CONFIG.PARAMETER_LEN)])
        original = PublicKey(root=root, parameter=parameter)

        data = original.to_bytes(PROD_CONFIG)
        recovered = PublicKey.from_bytes(data, PROD_CONFIG)

        assert recovered == original

    def test_from_bytes_invalid_length(self) -> None:
        """Test that from_bytes rejects invalid data lengths."""
        # Too short
        with pytest.raises(ValueError, match="Invalid public key length"):
            PublicKey.from_bytes(b"\x00" * 10, TEST_CONFIG)

        # Too long
        with pytest.raises(ValueError, match="Invalid public key length"):
            PublicKey.from_bytes(b"\x00" * 100, TEST_CONFIG)

    def test_serialization_format(self) -> None:
        """Test that serialization follows the documented format: root || parameter."""
        root = HashDigestVector(data=[Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)])
        parameter = Parameter(data=[Fp(value=i + 100) for i in range(TEST_CONFIG.PARAMETER_LEN)])
        pk = PublicKey(root=root, parameter=parameter)

        data = bytes(pk)

        # Check that root comes first
        from typing import List, cast

        root_data = Fp.serialize_list(cast(List[Fp], list(root.data)))
        parameter_data = Fp.serialize_list(cast(List[Fp], list(parameter.data)))

        assert data == root_data + parameter_data
        assert data[: len(root_data)] == root_data
        assert data[len(root_data) :] == parameter_data


class TestSignature:
    """Tests for Signature serialization and deserialization."""

    def test_bytes_protocol(self) -> None:
        """Test that Signature implements Python's bytes protocol."""
        # Create SSZ-compliant siblings
        siblings_data = [
            HashDigestVector(data=[Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)])
            for _ in range(TEST_CONFIG.LOG_LIFETIME)
        ]
        path = HashTreeOpening(siblings=HashDigestList(data=siblings_data))
        rho = [Fp(value=i) for i in range(TEST_CONFIG.RAND_LEN_FE)]
        # Create SSZ-compliant hashes
        hashes_data = [
            HashDigestVector(data=[Fp(value=i + j) for i in range(TEST_CONFIG.HASH_LEN_FE)])
            for j in range(TEST_CONFIG.DIMENSION)
        ]
        sig = Signature(path=path, rho=rho, hashes=HashDigestList(data=hashes_data))

        # Test __bytes__()
        data = bytes(sig)
        assert isinstance(data, bytes)
        assert len(data) == TEST_CONFIG.SIGNATURE_LEN_BYTES

    def test_to_bytes_with_validation(self) -> None:
        """Test that to_bytes validates all field lengths."""
        # Create valid signature
        siblings_data = [
            HashDigestVector(data=[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE)
            for _ in range(TEST_CONFIG.LOG_LIFETIME)
        ]
        path = HashTreeOpening(siblings=HashDigestList(data=siblings_data))
        rho = [Fp(value=0)] * TEST_CONFIG.RAND_LEN_FE
        hashes_data = [
            HashDigestVector(data=[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE)
            for _ in range(TEST_CONFIG.DIMENSION)
        ]
        sig = Signature(path=path, rho=rho, hashes=HashDigestList(data=hashes_data))

        # Valid serialization
        data = sig.to_bytes(TEST_CONFIG)
        assert len(data) == TEST_CONFIG.SIGNATURE_LEN_BYTES

        # Test path length validation (wrong number of siblings)
        invalid_siblings = [
            HashDigestVector(data=[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE) for _ in range(5)
        ]
        invalid_path = HashTreeOpening(siblings=HashDigestList(data=invalid_siblings))
        invalid_sig = Signature(path=invalid_path, rho=rho, hashes=HashDigestList(data=hashes_data))
        with pytest.raises(ValueError, match="Invalid path length"):
            invalid_sig.to_bytes(TEST_CONFIG)

        # Invalid rho length
        invalid_sig = Signature(
            path=path, rho=[Fp(value=0)] * 3, hashes=HashDigestList(data=hashes_data)
        )
        with pytest.raises(ValueError, match="Invalid rho length"):
            invalid_sig.to_bytes(TEST_CONFIG)

        # Invalid hashes count
        invalid_hashes = [
            HashDigestVector(data=[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE) for _ in range(5)
        ]
        invalid_sig = Signature(path=path, rho=rho, hashes=HashDigestList(data=invalid_hashes))
        with pytest.raises(ValueError, match="Invalid hashes length"):
            invalid_sig.to_bytes(TEST_CONFIG)

    def test_roundtrip_test_config(self) -> None:
        """Test serialization round-trip with TEST_CONFIG."""
        siblings_data = [
            HashDigestVector(data=[Fp(value=i * j) for i in range(TEST_CONFIG.HASH_LEN_FE)])
            for j in range(TEST_CONFIG.LOG_LIFETIME)
        ]
        path = HashTreeOpening(siblings=HashDigestList(data=siblings_data))
        rho = [Fp(value=i * 10) for i in range(TEST_CONFIG.RAND_LEN_FE)]
        hashes_data = [
            HashDigestVector(data=[Fp(value=i + j * 100) for i in range(TEST_CONFIG.HASH_LEN_FE)])
            for j in range(TEST_CONFIG.DIMENSION)
        ]
        original = Signature(path=path, rho=rho, hashes=HashDigestList(data=hashes_data))

        # Serialize and deserialize
        data = original.to_bytes(TEST_CONFIG)
        recovered = Signature.from_bytes(data, TEST_CONFIG)

        assert recovered.path.siblings == original.path.siblings
        assert recovered.rho == original.rho
        assert recovered.hashes == original.hashes
        assert recovered == original

    def test_roundtrip_prod_config(self) -> None:
        """Test serialization round-trip with PROD_CONFIG."""
        siblings_data = [
            HashDigestVector(data=[Fp(value=i)] * PROD_CONFIG.HASH_LEN_FE)
            for i in range(PROD_CONFIG.LOG_LIFETIME)
        ]
        path = HashTreeOpening(siblings=HashDigestList(data=siblings_data))
        rho = [Fp(value=i) for i in range(PROD_CONFIG.RAND_LEN_FE)]
        hashes_data = [
            HashDigestVector(data=[Fp(value=i + j) for i in range(PROD_CONFIG.HASH_LEN_FE)])
            for j in range(PROD_CONFIG.DIMENSION)
        ]
        original = Signature(path=path, rho=rho, hashes=HashDigestList(data=hashes_data))

        data = original.to_bytes(PROD_CONFIG)
        recovered = Signature.from_bytes(data, PROD_CONFIG)

        assert recovered == original

    def test_from_bytes_invalid_length(self) -> None:
        """Test that from_bytes rejects invalid data lengths."""
        # Too short
        with pytest.raises(ValueError, match="Invalid signature length"):
            Signature.from_bytes(b"\x00" * 10, TEST_CONFIG)

        # Too long
        with pytest.raises(ValueError, match="Invalid signature length"):
            Signature.from_bytes(b"\x00" * 10000, TEST_CONFIG)

    def test_serialization_format(self) -> None:
        """Test that serialization follows format: path || rho || hashes."""
        siblings_data = [
            HashDigestVector(data=[Fp(value=i)] * TEST_CONFIG.HASH_LEN_FE)
            for i in range(TEST_CONFIG.LOG_LIFETIME)
        ]
        path = HashTreeOpening(siblings=HashDigestList(data=siblings_data))
        rho = [Fp(value=i + 100) for i in range(TEST_CONFIG.RAND_LEN_FE)]
        hashes_data = [
            HashDigestVector(data=[Fp(value=i + j + 200) for i in range(TEST_CONFIG.HASH_LEN_FE)])
            for j in range(TEST_CONFIG.DIMENSION)
        ]
        sig = Signature(path=path, rho=rho, hashes=HashDigestList(data=hashes_data))

        data = bytes(sig)

        # Calculate expected section sizes
        path_size = TEST_CONFIG.LOG_LIFETIME * TEST_CONFIG.HASH_LEN_FE * 4
        rho_size = TEST_CONFIG.RAND_LEN_FE * 4
        hashes_size = TEST_CONFIG.DIMENSION * TEST_CONFIG.HASH_LEN_FE * 4

        assert len(data) == path_size + rho_size + hashes_size

        # Deserialize and verify correct parsing
        recovered = Signature.from_bytes(data, TEST_CONFIG)
        assert recovered == sig


class TestSerializationProperties:
    """Property-based tests for serialization."""

    def test_public_key_deterministic(self) -> None:
        """Test that serialization is deterministic."""
        root = HashDigestVector(data=[Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)])
        parameter = Parameter(data=[Fp(value=i) for i in range(TEST_CONFIG.PARAMETER_LEN)])
        pk = PublicKey(root=root, parameter=parameter)

        # Serialize multiple times
        data1 = pk.to_bytes(TEST_CONFIG)
        data2 = pk.to_bytes(TEST_CONFIG)
        data3 = bytes(pk)

        assert data1 == data2
        assert data1 == data3

    def test_signature_deterministic(self) -> None:
        """Test that serialization is deterministic."""
        siblings_data = [
            HashDigestVector(data=[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE)
            for _ in range(TEST_CONFIG.LOG_LIFETIME)
        ]
        path = HashTreeOpening(siblings=HashDigestList(data=siblings_data))
        rho = [Fp(value=0)] * TEST_CONFIG.RAND_LEN_FE
        hashes_data = [
            HashDigestVector(data=[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE)
            for _ in range(TEST_CONFIG.DIMENSION)
        ]
        sig = Signature(path=path, rho=rho, hashes=HashDigestList(data=hashes_data))

        data1 = sig.to_bytes(TEST_CONFIG)
        data2 = sig.to_bytes(TEST_CONFIG)
        data3 = bytes(sig)

        assert data1 == data2
        assert data1 == data3

    def test_different_values_produce_different_bytes(self) -> None:
        """Test that different values produce different serializations."""
        root1 = HashDigestVector(data=[Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)])
        root2 = HashDigestVector(data=[Fp(value=i + 1) for i in range(TEST_CONFIG.HASH_LEN_FE)])
        parameter = Parameter(data=[Fp(value=0)] * TEST_CONFIG.PARAMETER_LEN)

        pk1 = PublicKey(root=root1, parameter=parameter)
        pk2 = PublicKey(root=root2, parameter=parameter)

        assert bytes(pk1) != bytes(pk2)
