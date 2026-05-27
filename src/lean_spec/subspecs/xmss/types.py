"""Base types for the XMSS signature scheme."""

from typing import Final, NamedTuple

from lean_spec.subspecs.koalabear import Fp

from ...types import Uint64
from ...types.byte_arrays import BaseBytes
from ...types.collections import SSZList, SSZVector
from ...types.container import Container
from .constants import PRF_KEY_LENGTH, TARGET_CONFIG


class TreeTweak(NamedTuple):
    """Tweak that domain-separates Merkle node hashes by their position."""

    level: int
    """Height in the Merkle tree.

    Layer 0 is the leaf level.
    """

    index: Uint64
    """Node index within its level, counted from the left."""


class ChainTweak(NamedTuple):
    """Tweak that domain-separates Winternitz chain hashes by their position."""

    epoch: Uint64
    """Slot identifier for the one-time signature."""

    chain_index: int
    """Index of the chain within the one-time signature."""

    step: int
    """
    - Step number along the chain.
    - Steps are 1-indexed.
    - Step zero is the chain start.
    """


class PRFKey(BaseBytes):
    """The PRF master secret key.

    High-entropy byte string acting as the single root secret.
    Every one-time signing key is deterministically derived from this seed.
    """

    LENGTH = PRF_KEY_LENGTH


HASH_DIGEST_LENGTH: Final = TARGET_CONFIG.HASH_LEN_FE
"""Length of one hash digest in field elements.

Corresponds to the Poseidon1 output length used in the XMSS scheme."""

# Why: a bottom tree spans 2^(LOG_LIFETIME/2) leaves.
# Padding may add up to two extra siblings.
# Doubling that bound leaves room for future-proof layouts without resizing.
NODE_LIST_LIMIT: Final = 1 << (TARGET_CONFIG.LOG_LIFETIME // 2 + 1)
"""Maximum number of nodes that can be stored in a sparse Merkle tree layer."""


class HashDigestVector(SSZVector[Fp]):
    """A single hash digest as a fixed-size vector of field elements.

    The fixed size lets SSZ pack these back-to-back without per-element offsets.
    """

    LENGTH = HASH_DIGEST_LENGTH


class HashDigestList(SSZList[HashDigestVector]):
    """Variable-length list of hash digests."""

    LIMIT = NODE_LIST_LIMIT


class Parameter(SSZVector[Fp]):
    """The public parameter P.

    Unique, randomly generated value associated with a single key pair.
    Mixed into every hash to personalize the function and block cross-key attacks.
    Public knowledge.
    """

    LENGTH = TARGET_CONFIG.PARAMETER_LEN


class Randomness(SSZVector[Fp]):
    """The randomness rho used during signing.

    Variable input to the message hash so the signer can resample until a
    valid codeword is found.
    Included in the final signature so the verifier reproduces the hash.
    """

    LENGTH = TARGET_CONFIG.RAND_LEN_FE


class HashTreeOpening(Container):
    """A Merkle authentication path.

    Contains the minimal proof connecting a specific leaf to the Merkle root.
    Holds every sibling node along the path from the leaf to the tree top.
    """

    siblings: HashDigestList
    """SSZ-compliant list of sibling hashes, from bottom to top."""


class HashTreeLayer(Container):
    """A single horizontal slice of the sparse Merkle tree.

    The tree is sparse: only nodes computed for the active leaf range are stored.
    """

    start_index: Uint64
    """The starting index of the first node in this layer."""
    nodes: HashDigestList
    """SSZ-compliant list of hash digests stored for this layer."""


# Why: layers run from 0 (leaves) up to LOG_LIFETIME (root) inclusive.
LAYERS_LIMIT: Final = TARGET_CONFIG.LOG_LIFETIME + 1
"""Maximum number of layers in a subtree."""


class HashTreeLayers(SSZList[HashTreeLayer]):
    """Variable-length list of Merkle tree layers.

    Represents the layers of a subtree, from the lowest layer up to the root.
    Bottom and top trees each cover half the depth.
    The cap allows the full tree.
    """

    LIMIT = LAYERS_LIMIT
