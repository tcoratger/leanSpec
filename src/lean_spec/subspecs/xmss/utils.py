"""Utility functions for the XMSS signature scheme."""

import secrets
from typing import List

from ..koalabear import Fp, P
from .constants import PROD_CONFIG, TEST_CONFIG, XmssConfig
from .structures import HashDigest, Parameter, Randomness


class Rand:
    """An instance of the random data generator for a given config."""

    def __init__(self, config: XmssConfig):
        """Initializes the generator with a specific parameter set."""
        self.config = config

    def field_elements(self, length: int) -> List[Fp]:
        """Generates a random list of field elements."""
        # For each element, generate a secure random integer
        # in the range [0, P-1].
        return [Fp(value=secrets.randbelow(P)) for _ in range(length)]

    def parameter(self) -> Parameter:
        """Generates a random public parameter."""
        return self.field_elements(self.config.PARAMETER_LEN)

    def domain(self) -> HashDigest:
        """Generates a random hash digest."""
        return self.field_elements(self.config.HASH_LEN_FE)

    def rho(self) -> Randomness:
        """Generates randomness `rho` for message encoding."""
        return self.field_elements(self.config.RAND_LEN_FE)


PROD_RAND = Rand(PROD_CONFIG)
"""An instance configured for production-level parameters."""

TEST_RAND = Rand(TEST_CONFIG)
"""A lightweight instance for test environments."""
