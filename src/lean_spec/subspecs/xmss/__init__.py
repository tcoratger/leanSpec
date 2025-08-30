"""
This package provides a Python specification for the Generalized XMSS
hash-based signature scheme.

It exposes the core data structures and the main interface functions.
"""

from .constants import PROD_CONFIG, TEST_CONFIG
from .interface import GeneralizedXmssScheme
from .structures import (
    HashTree,
    HashTreeOpening,
    PublicKey,
    SecretKey,
    Signature,
)

__all__ = [
    "GeneralizedXmssScheme",
    "PublicKey",
    "Signature",
    "SecretKey",
    "HashTreeOpening",
    "HashTree",
    "PROD_CONFIG",
    "TEST_CONFIG",
]
