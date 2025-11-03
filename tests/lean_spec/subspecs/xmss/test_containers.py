"""
Tests for XMSS container serialization and deserialization.
"""

import pytest

from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss.constants import PROD_CONFIG, TEST_CONFIG
from lean_spec.subspecs.xmss.containers import HashTreeOpening, PublicKey, Signature


class TestPublicKey:
    """Tests for PublicKey serialization and deserialization."""

    def test_bytes_protocol(self) -> None:
        """Test that PublicKey implements Python's bytes protocol."""
        root = [Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)]
        parameter = [Fp(value=i + 100) for i in range(TEST_CONFIG.PARAMETER_LEN)]
        pk = PublicKey(root=root, parameter=parameter)

        # Test __bytes__()
        data = bytes(pk)
        assert isinstance(data, bytes)
        assert len(data) == TEST_CONFIG.PUBLIC_KEY_LEN_BYTES

    def test_to_bytes_with_validation(self) -> None:
        """Test that to_bytes validates field lengths."""
        root = [Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)]
        parameter = [Fp(value=i) for i in range(TEST_CONFIG.PARAMETER_LEN)]
        pk = PublicKey(root=root, parameter=parameter)

        # Valid serialization
        data = pk.to_bytes(TEST_CONFIG)
        assert len(data) == TEST_CONFIG.PUBLIC_KEY_LEN_BYTES

        # Invalid root length
        invalid_pk = PublicKey(root=[Fp(value=0)] * 5, parameter=parameter)
        with pytest.raises(ValueError, match="Invalid root length"):
            invalid_pk.to_bytes(TEST_CONFIG)

        # Invalid parameter length
        invalid_pk = PublicKey(root=root, parameter=[Fp(value=0)] * 3)
        with pytest.raises(ValueError, match="Invalid parameter length"):
            invalid_pk.to_bytes(TEST_CONFIG)

    def test_roundtrip_test_config(self) -> None:
        """Test serialization round-trip with TEST_CONFIG."""
        root = [Fp(value=i * 10) for i in range(TEST_CONFIG.HASH_LEN_FE)]
        parameter = [Fp(value=i * 20) for i in range(TEST_CONFIG.PARAMETER_LEN)]
        original = PublicKey(root=root, parameter=parameter)

        # Serialize and deserialize
        data = original.to_bytes(TEST_CONFIG)
        recovered = PublicKey.from_bytes(data, TEST_CONFIG)

        assert recovered.root == original.root
        assert recovered.parameter == original.parameter
        assert recovered == original

    def test_roundtrip_prod_config(self) -> None:
        """Test serialization round-trip with PROD_CONFIG."""
        root = [Fp(value=i) for i in range(PROD_CONFIG.HASH_LEN_FE)]
        parameter = [Fp(value=i + 1000) for i in range(PROD_CONFIG.PARAMETER_LEN)]
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
        root = [Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)]
        parameter = [Fp(value=i + 100) for i in range(TEST_CONFIG.PARAMETER_LEN)]
        pk = PublicKey(root=root, parameter=parameter)

        data = bytes(pk)

        # Check that root comes first
        root_data = Fp.serialize_list(root)
        parameter_data = Fp.serialize_list(parameter)

        assert data == root_data + parameter_data
        assert data[: len(root_data)] == root_data
        assert data[len(root_data) :] == parameter_data


class TestSignature:
    """Tests for Signature serialization and deserialization."""

    def test_bytes_protocol(self) -> None:
        """Test that Signature implements Python's bytes protocol."""
        path = HashTreeOpening(
            siblings=[[Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)]]
            * TEST_CONFIG.LOG_LIFETIME
        )
        rho = [Fp(value=i) for i in range(TEST_CONFIG.RAND_LEN_FE)]
        hashes = [
            [Fp(value=i + j) for i in range(TEST_CONFIG.HASH_LEN_FE)]
            for j in range(TEST_CONFIG.DIMENSION)
        ]
        sig = Signature(path=path, rho=rho, hashes=hashes)

        # Test __bytes__()
        data = bytes(sig)
        assert isinstance(data, bytes)
        assert len(data) == TEST_CONFIG.SIGNATURE_LEN_BYTES

    def test_to_bytes_with_validation(self) -> None:
        """Test that to_bytes validates all field lengths."""
        # Create valid signature
        path = HashTreeOpening(
            siblings=[[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE] * TEST_CONFIG.LOG_LIFETIME
        )
        rho = [Fp(value=0)] * TEST_CONFIG.RAND_LEN_FE
        hashes = [[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE] * TEST_CONFIG.DIMENSION
        sig = Signature(path=path, rho=rho, hashes=hashes)

        # Valid serialization
        data = sig.to_bytes(TEST_CONFIG)
        assert len(data) == TEST_CONFIG.SIGNATURE_LEN_BYTES

        # Invalid path length (wrong number of siblings)
        invalid_path = HashTreeOpening(siblings=[[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE] * 5)
        invalid_sig = Signature(path=invalid_path, rho=rho, hashes=hashes)
        with pytest.raises(ValueError, match="Invalid path length"):
            invalid_sig.to_bytes(TEST_CONFIG)

        # Invalid sibling length
        invalid_path = HashTreeOpening(siblings=[[Fp(value=0)] * 5] * TEST_CONFIG.LOG_LIFETIME)
        invalid_sig = Signature(path=invalid_path, rho=rho, hashes=hashes)
        with pytest.raises(ValueError, match="Invalid sibling .* length"):
            invalid_sig.to_bytes(TEST_CONFIG)

        # Invalid rho length
        invalid_sig = Signature(path=path, rho=[Fp(value=0)] * 3, hashes=hashes)
        with pytest.raises(ValueError, match="Invalid rho length"):
            invalid_sig.to_bytes(TEST_CONFIG)

        # Invalid hashes count
        invalid_sig = Signature(
            path=path, rho=rho, hashes=[[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE] * 5
        )
        with pytest.raises(ValueError, match="Invalid hashes length"):
            invalid_sig.to_bytes(TEST_CONFIG)

        # Invalid hash digest length
        invalid_hashes = [[Fp(value=0)] * 5] * TEST_CONFIG.DIMENSION
        invalid_sig = Signature(path=path, rho=rho, hashes=invalid_hashes)
        with pytest.raises(ValueError, match="Invalid hash .* length"):
            invalid_sig.to_bytes(TEST_CONFIG)

    def test_roundtrip_test_config(self) -> None:
        """Test serialization round-trip with TEST_CONFIG."""
        path = HashTreeOpening(
            siblings=[
                [Fp(value=i * j) for i in range(TEST_CONFIG.HASH_LEN_FE)]
                for j in range(TEST_CONFIG.LOG_LIFETIME)
            ]
        )
        rho = [Fp(value=i * 10) for i in range(TEST_CONFIG.RAND_LEN_FE)]
        hashes = [
            [Fp(value=i + j * 100) for i in range(TEST_CONFIG.HASH_LEN_FE)]
            for j in range(TEST_CONFIG.DIMENSION)
        ]
        original = Signature(path=path, rho=rho, hashes=hashes)

        # Serialize and deserialize
        data = original.to_bytes(TEST_CONFIG)
        recovered = Signature.from_bytes(data, TEST_CONFIG)

        assert recovered.path.siblings == original.path.siblings
        assert recovered.rho == original.rho
        assert recovered.hashes == original.hashes
        assert recovered == original

    def test_roundtrip_prod_config(self) -> None:
        """Test serialization round-trip with PROD_CONFIG."""
        path = HashTreeOpening(
            siblings=[
                [Fp(value=i)] * PROD_CONFIG.HASH_LEN_FE for i in range(PROD_CONFIG.LOG_LIFETIME)
            ]
        )
        rho = [Fp(value=i) for i in range(PROD_CONFIG.RAND_LEN_FE)]
        hashes = [
            [Fp(value=i + j) for i in range(PROD_CONFIG.HASH_LEN_FE)]
            for j in range(PROD_CONFIG.DIMENSION)
        ]
        original = Signature(path=path, rho=rho, hashes=hashes)

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
        path = HashTreeOpening(
            siblings=[
                [Fp(value=i)] * TEST_CONFIG.HASH_LEN_FE for i in range(TEST_CONFIG.LOG_LIFETIME)
            ]
        )
        rho = [Fp(value=i + 100) for i in range(TEST_CONFIG.RAND_LEN_FE)]
        hashes = [
            [Fp(value=i + j + 200) for i in range(TEST_CONFIG.HASH_LEN_FE)]
            for j in range(TEST_CONFIG.DIMENSION)
        ]
        sig = Signature(path=path, rho=rho, hashes=hashes)

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
        root = [Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)]
        parameter = [Fp(value=i) for i in range(TEST_CONFIG.PARAMETER_LEN)]
        pk = PublicKey(root=root, parameter=parameter)

        # Serialize multiple times
        data1 = pk.to_bytes(TEST_CONFIG)
        data2 = pk.to_bytes(TEST_CONFIG)
        data3 = bytes(pk)

        assert data1 == data2
        assert data1 == data3

    def test_signature_deterministic(self) -> None:
        """Test that serialization is deterministic."""
        path = HashTreeOpening(
            siblings=[[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE] * TEST_CONFIG.LOG_LIFETIME
        )
        rho = [Fp(value=0)] * TEST_CONFIG.RAND_LEN_FE
        hashes = [[Fp(value=0)] * TEST_CONFIG.HASH_LEN_FE] * TEST_CONFIG.DIMENSION
        sig = Signature(path=path, rho=rho, hashes=hashes)

        data1 = sig.to_bytes(TEST_CONFIG)
        data2 = sig.to_bytes(TEST_CONFIG)
        data3 = bytes(sig)

        assert data1 == data2
        assert data1 == data3

    def test_different_values_produce_different_bytes(self) -> None:
        """Test that different values produce different serializations."""
        root1 = [Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)]
        root2 = [Fp(value=i + 1) for i in range(TEST_CONFIG.HASH_LEN_FE)]
        parameter = [Fp(value=0)] * TEST_CONFIG.PARAMETER_LEN

        pk1 = PublicKey(root=root1, parameter=parameter)
        pk2 = PublicKey(root=root2, parameter=parameter)

        assert bytes(pk1) != bytes(pk2)
