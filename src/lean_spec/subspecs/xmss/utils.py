"""Utility functions for the XMSS signature scheme."""

import secrets
from typing import List

from ..koalabear import Fp, P
from .constants import HASH_LEN_FE, PARAMETER_LEN, RAND_LEN_FE
from .structures import HashDigest, Parameter, Randomness


def rand_field_elements(length: int) -> List[Fp]:
    """Generates a random list of field elements."""
    # For each element, generate a secure random integer in the range [0, P-1].
    return [Fp(value=secrets.randbelow(P)) for _ in range(length)]


def rand_parameter() -> Parameter:
    """Generates a random public parameter."""
    return rand_field_elements(PARAMETER_LEN)


def rand_domain() -> HashDigest:
    """Generates a random hash digest."""
    return rand_field_elements(HASH_LEN_FE)


def rand_rho() -> Randomness:
    """Generates randomness `rho` for message encoding."""
    return rand_field_elements(RAND_LEN_FE)
