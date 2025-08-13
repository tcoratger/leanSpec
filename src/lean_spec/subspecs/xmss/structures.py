"""Defines the data structures for the Generalized XMSS signature scheme."""

from typing import List

from pydantic import BaseModel, ConfigDict, Field

from ..koalabear import Fp
from .constants import HASH_LEN_FE, PARAMETER_LEN, RAND_LEN_FE


class HashTreeOpening(BaseModel):
    """
    A Merkle authentication path.

    It contains a list of sibling nodes required to reconstruct the path
    from a leaf node up to the Merkle root.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    siblings: List[List[Fp]] = Field(
        ..., description="List of sibling hashes, from bottom to top."
    )


class PublicKey(BaseModel):
    """The public key for the Generalized XMSS scheme."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    root: List[Fp] = Field(..., max_length=HASH_LEN_FE, min_length=HASH_LEN_FE)
    parameter: List[Fp] = Field(
        ..., max_length=PARAMETER_LEN, min_length=PARAMETER_LEN
    )


class Signature(BaseModel):
    """A signature in the Generalized XMSS scheme."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    path: HashTreeOpening
    rho: List[Fp] = Field(..., max_length=RAND_LEN_FE, min_length=RAND_LEN_FE)
    hashes: List[List[Fp]]


class SecretKey(BaseModel):
    """
    Placeholder for the secret key.

    Note: The full secret key structure is not specified here as it is not
    needed for verification.
    """

    pass
