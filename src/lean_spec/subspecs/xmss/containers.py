"""Defines the data containers for the Generalized XMSS signature scheme."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, List, cast

from pydantic import Field

from ...types import StrictBaseModel, Uint64
from ...types.collections import SSZList, SSZVector
from ..koalabear import P_BYTES, Fp
from .constants import PRF_KEY_LENGTH, PROD_CONFIG

if TYPE_CHECKING:
    from .constants import XmssConfig
    from .subtree import HashSubTree

PRFKey = Annotated[bytes, Field(min_length=PRF_KEY_LENGTH, max_length=PRF_KEY_LENGTH)]
"""
A type alias for the PRF **master secret key**.

This is a high-entropy byte string that acts as the single root secret from
which all one-time signing keys are deterministically derived.
"""


HASH_DIGEST_LENGTH = PROD_CONFIG.HASH_LEN_FE
"""
The fixed length of a hash digest in field elements.

Derived from `PROD_CONFIG.HASH_LEN_FE`. This corresponds to the output length
of the Poseidon2 hash function used in the XMSS scheme.
"""

# Calculate the maximum number of nodes in a sparse Merkle tree layer:
# - A bottom tree has at most 2^(LOG_LIFETIME/2) leaves
# - With padding, we may add up to 2 additional nodes
# - To be generous and future-proof, we use 2^(LOG_LIFETIME/2 + 1)
NODE_LIST_LIMIT = 1 << (PROD_CONFIG.LOG_LIFETIME // 2 + 1)
"""
The maximum number of nodes that can be stored in a sparse Merkle tree layer.

Calculated as `2^(LOG_LIFETIME/2 + 1)` from PROD_CONFIG to accommodate:
- Bottom trees with up to `2^(LOG_LIFETIME/2)` nodes
- Padding overhead (up to 2 additional nodes)
- Future-proofing with 2x margin
"""


class HashDigestVector(SSZVector):
    """
    A single hash digest represented as a fixed-size vector of field elements.

    This is the SSZ-compliant representation of a Poseidon2 hash output.
    In SSZ notation: `Vector[Fp, HASH_DIGEST_LENGTH]`

    The fixed size enables efficient serialization when used in collections,
    as SSZ can pack these back-to-back without per-element offsets.
    """

    ELEMENT_TYPE = Fp
    LENGTH = HASH_DIGEST_LENGTH


class HashDigestList(SSZList):
    """
    Variable-length list of hash digests.

    In SSZ notation: `List[Vector[Fp, HASH_DIGEST_LENGTH], NODE_LIST_LIMIT]`

    This type is used to represent collections of hash digests in the XMSS scheme.
    """

    ELEMENT_TYPE = HashDigestVector
    LIMIT = NODE_LIST_LIMIT


Parameter = List[Fp]
"""
A type alias for the public parameter `P`.

This is a unique, randomly generated value associated with a single key pair. It
is mixed into every hash computation to "personalize" the hash function, preventing
certain cross-key attacks. It is public knowledge.
"""

Randomness = List[Fp]
"""
A type alias for the randomness `rho` (ρ) used during signing.

This value provides a variable input to the message hash, allowing the signer to
repeatedly try hashing until a valid "codeword" is found. It must be included in
the final signature for the verifier to reproduce the same hash.
"""


def _serialize_digests(digests: HashDigestList) -> bytes:
    """
    Serialize a list of hash digests.

    Args:
        digests: SSZ-compliant list of hash digests.

    Returns:
        Concatenated serialized field elements.
    """
    return b"".join(Fp.serialize_list(list(digest.data)) for digest in digests)


def _deserialize_digests(data: bytes, count: int, elements_per_digest: int) -> HashDigestList:
    """
    Deserialize multiple hash digests from bytes.

    Args:
        data: Raw bytes to deserialize.
        count: Number of digests.
        elements_per_digest: Field elements per digest.

    Returns:
        SSZ-compliant list of hash digests.

    Raises:
        ValueError: If data length doesn't match expectations.
    """
    total_elements = count * elements_per_digest
    all_elements = Fp.deserialize_list(data, total_elements)

    # Convert to list of lists first
    digests = [
        all_elements[i : i + elements_per_digest]
        for i in range(0, len(all_elements), elements_per_digest)
    ]

    # Wrap in SSZ types
    ssz_digests = [HashDigestVector(data=digest) for digest in digests]
    return HashDigestList(data=ssz_digests)


class HashTreeOpening(StrictBaseModel):
    """
    A Merkle authentication path.

    This object contains the minimal proof required to connect a specific leaf
    to the Merkle root. It consists of the list of all sibling nodes along the
    path from the leaf to the top of the tree.
    """

    siblings: HashDigestList
    """SSZ-compliant list of sibling hashes, from bottom to top."""


class HashTreeLayer(StrictBaseModel):
    """
    Represents a single horizontal "slice" of the sparse Merkle tree.

    Because the tree is sparse, we only store the nodes that are actually computed
    for the active range of leaves, not the entire conceptual layer.
    """

    start_index: Uint64
    """The starting index of the first node in this layer."""
    nodes: HashDigestList
    """SSZ-compliant list of hash digests stored for this layer."""


class PublicKey(StrictBaseModel):
    """
    The public-facing component of a key pair.

    This is the data a verifier needs to check signatures. It is compact, safe to
    distribute publicly, and acts as the signer's identity.

    Binary Format
    -------------
    The serialized format concatenates:
    1. Merkle root (`HASH_LEN_FE` field elements)
    2. Public parameter (`PARAMETER_LEN` field elements)

    All field elements are serialized in little-endian byte order.
    """

    root: HashDigestVector
    """The Merkle root, which commits to all one-time keys for the key's lifetime."""
    parameter: Parameter
    """The public parameter `P` that personalizes the hash function."""

    def __bytes__(self) -> bytes:
        """
        Serialize using Python's bytes protocol.

        Format: root || parameter (concatenated field elements).

        Example:
            >>> pk = PublicKey(root=[Fp(value=0)] * 8, parameter=[Fp(value=1)] * 5)
            >>> data = bytes(pk)
            >>> isinstance(data, bytes)
            True
        """
        return Fp.serialize_list(cast(List[Fp], list(self.root.data))) + Fp.serialize_list(
            self.parameter
        )

    def to_bytes(self, config: XmssConfig) -> bytes:
        """
        Serialize with validation against configuration.

        This validates field lengths match the expected configuration before
        serialization, providing better error messages for invalid keys.

        Args:
            config: XMSS configuration for validation.

        Returns:
            Binary representation of the public key.

        Raises:
            ValueError: If field lengths don't match configuration.
        """
        if len(self.root) != config.HASH_LEN_FE:
            raise ValueError(
                f"Invalid root length: expected {config.HASH_LEN_FE}, got {len(self.root)}"
            )

        if len(self.parameter) != config.PARAMETER_LEN:
            raise ValueError(
                f"Invalid parameter length: expected {config.PARAMETER_LEN}, "
                f"got {len(self.parameter)}"
            )

        return bytes(self)

    @classmethod
    def from_bytes(cls, data: bytes, config: XmssConfig) -> PublicKey:
        """
        Deserialize a public key from bytes.

        Args:
            data: Binary representation of a public key.
            config: The XMSS configuration defining field lengths.

        Returns:
            Deserialized PublicKey instance.

        Raises:
            ValueError: If the data has incorrect length or format.

        Example:
            >>> data = bytes(PROD_CONFIG.PUBLIC_KEY_LEN_BYTES)
            >>> pk = PublicKey.from_bytes(data, PROD_CONFIG)
            >>> isinstance(pk, PublicKey)
            True
        """
        expected_length = config.PUBLIC_KEY_LEN_BYTES

        if len(data) != expected_length:
            raise ValueError(
                f"Invalid public key length: expected {expected_length} bytes "
                f"({config.HASH_LEN_FE} root + {config.PARAMETER_LEN} parameter "
                f"× {P_BYTES} bytes each), got {len(data)} bytes"
            )

        # Parse: root || parameter
        root_len = config.HASH_LEN_FE * P_BYTES
        root = Fp.deserialize_list(data[:root_len], config.HASH_LEN_FE)
        parameter = Fp.deserialize_list(data[root_len:], config.PARAMETER_LEN)

        return cls(root=HashDigestVector(data=root), parameter=parameter)


class Signature(StrictBaseModel):
    """
    A signature produced by the `sign` function.

    It contains all the necessary components for a verifier to confirm that a
    specific message was signed by the owner of a `PublicKey` for a specific epoch.

    All field elements are serialized in little-endian byte order.
    """

    path: HashTreeOpening
    """The authentication path proving the one-time key's inclusion in the Merkle tree."""
    rho: Randomness
    """The randomness used to successfully encode the message."""
    hashes: HashDigestList
    """The one-time signature itself: a list of intermediate Winternitz chain hashes."""

    def __bytes__(self) -> bytes:
        """
        Serialize using Python's bytes protocol.

        Format: path siblings || rho || hashes (concatenated field elements).
        """
        return (
            _serialize_digests(self.path.siblings)
            + Fp.serialize_list(self.rho)
            + _serialize_digests(self.hashes)
        )

    def to_bytes(self, config: XmssConfig) -> bytes:
        """
        Serialize the signature to bytes with validation.

        Args:
            config: The XMSS configuration defining field lengths.

        Returns:
            Binary representation of the signature.

        Raises:
            ValueError: If any component has incorrect length.
        """
        # Validate Merkle path
        if len(self.path.siblings) != config.LOG_LIFETIME:
            raise ValueError(
                f"Invalid path length: expected {config.LOG_LIFETIME} siblings, "
                f"got {len(self.path.siblings)}"
            )

        for i, sibling_vector in enumerate(self.path.siblings):
            if len(sibling_vector) != config.HASH_LEN_FE:
                raise ValueError(
                    f"Invalid sibling {i} length: expected {config.HASH_LEN_FE} elements, "
                    f"got {len(sibling_vector)}"
                )

        # Validate randomness
        if len(self.rho) != config.RAND_LEN_FE:
            raise ValueError(
                f"Invalid rho length: expected {config.RAND_LEN_FE} elements, got {len(self.rho)}"
            )

        # Validate OTS hashes
        if len(self.hashes) != config.DIMENSION:
            raise ValueError(
                f"Invalid hashes length: expected {config.DIMENSION} hashes, got {len(self.hashes)}"
            )

        for i, hash_vector in enumerate(self.hashes):
            if len(hash_vector) != config.HASH_LEN_FE:
                raise ValueError(
                    f"Invalid hash {i} length: expected {config.HASH_LEN_FE} elements, "
                    f"got {len(hash_vector)}"
                )

        return bytes(self)

    @classmethod
    def from_bytes(cls, data: bytes, config: XmssConfig) -> Signature:
        """
        Deserialize a signature from bytes.

        Args:
            data: Binary representation of a signature.
            config: The XMSS configuration defining field lengths.

        Returns:
            Deserialized Signature instance.

        Raises:
            ValueError: If the data has incorrect length or format.
        """
        expected_length = config.SIGNATURE_LEN_BYTES

        if len(data) != expected_length:
            raise ValueError(
                f"Invalid signature length: expected {expected_length} bytes, got {len(data)} bytes"
            )

        # Calculate section sizes
        path_size = config.LOG_LIFETIME * config.HASH_LEN_FE * P_BYTES
        rho_size = config.RAND_LEN_FE * P_BYTES

        # Parse: path siblings || rho || hashes
        offset = 0
        path_data = data[offset : offset + path_size]
        offset += path_size
        rho_data = data[offset : offset + rho_size]
        offset += rho_size
        hashes_data = data[offset:]

        # Deserialize components
        siblings = _deserialize_digests(
            path_data,
            count=config.LOG_LIFETIME,
            elements_per_digest=config.HASH_LEN_FE,
        )
        rho = Fp.deserialize_list(rho_data, count=config.RAND_LEN_FE)
        hashes = _deserialize_digests(
            hashes_data,
            count=config.DIMENSION,
            elements_per_digest=config.HASH_LEN_FE,
        )

        return cls(
            path=HashTreeOpening(siblings=siblings),
            rho=rho,
            hashes=hashes,
        )


class SecretKey(StrictBaseModel):
    """
    The private component of a key pair. **MUST BE KEPT CONFIDENTIAL.**

    This object contains all the secret material and pre-computed data needed to
    generate signatures for any epoch within its active lifetime.
    """

    prf_key: PRFKey
    """The master secret key used to derive all one-time secrets."""

    parameter: Parameter
    """The public parameter `P`, stored for convenience during signing."""

    activation_epoch: Uint64
    """
    The first epoch for which this secret key is valid.

    Note: With top-bottom trees, this is aligned to a multiple of `sqrt(LIFETIME)`
    to ensure efficient tree partitioning.
    """

    num_active_epochs: Uint64
    """
    The number of consecutive epochs this key can be used for.

    Note: With top-bottom trees, this is rounded up to be a multiple of
    `sqrt(LIFETIME)`, with a minimum of `2 * sqrt(LIFETIME)`.
    """

    top_tree: HashSubTree
    """
    The top tree containing the root and top `LOG_LIFETIME/2` layers.

    This tree is always kept in memory and contains the roots of all bottom trees
    in its lowest layer. Its root is the public key's Merkle root.
    """

    left_bottom_tree_index: Uint64
    """
    The index of the left bottom tree in the sliding window.

    Bottom trees are numbered 0, 1, 2, ... where tree `i` covers epochs
    `[i * sqrt(LIFETIME), (i+1) * sqrt(LIFETIME))`.

    The prepared interval is:
    [left_bottom_tree_index * sqrt(LIFETIME), (left_bottom_tree_index + 2) * sqrt(LIFETIME))

    """

    left_bottom_tree: HashSubTree
    """
    The left bottom tree in the sliding window.

    This covers epochs:
    [left_bottom_tree_index * sqrt(LIFETIME), (left_bottom_tree_index + 1) * sqrt(LIFETIME))
    """

    right_bottom_tree: HashSubTree
    """
    The right bottom tree in the sliding window.

    This covers epochs:
    [(left_bottom_tree_index + 1) * sqrt(LIFETIME), (left_bottom_tree_index + 2) * sqrt(LIFETIME))

    Together with `left_bottom_tree`, this provides a prepared interval of
    exactly `2 * sqrt(LIFETIME)` consecutive epochs.
    """
