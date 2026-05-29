"""Byte-level prover binding for multi-signature aggregation.

Re-exports the Rust binding entry points used by the consensus layer.
The consensus layer owns the domain-typed wrapper containers.
"""

from lean_multisig_py import (
    aggregate_type_1,
    merge_many_type_1,
    setup_prover,
    split_type_2_by_msg,
    verify_type_1,
    verify_type_2_with_messages,
)

from lean_spec.config import LEAN_ENV

LOG_INV_RATE: int = 1 if LEAN_ENV == "test" else 2
"""Inverse-rate exponent forwarded to the SNARK backend.

A smaller rate trades verifier cost for prover speed.
Test mode favors prover speed.
"""

# The environment is fixed for the lifetime of the process.
# One setup call covers every aggregation, verification, split, and merge.
# Per-call invocations then default to the mode established here.
setup_prover(mode=LEAN_ENV)


__all__ = [
    "LOG_INV_RATE",
    "aggregate_type_1",
    "merge_many_type_1",
    "split_type_2_by_msg",
    "verify_type_1",
    "verify_type_2_with_messages",
]
