"""
This package provides a Python specification for the Generalized XMSS
hash-based signature scheme.

It exposes the core data structures and the main interface functions.
"""

from .containers import PublicKey, SecretKey
from .interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme

__all__ = [
    "GeneralizedXmssScheme",
    "PublicKey",
    "SecretKey",
    "TARGET_SIGNATURE_SCHEME",
]
