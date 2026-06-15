"""Tests for the SHAKE128-based pseudorandom function (PRF)."""

from lean_spec.spec.crypto.xmss.constants import (
    PRF_KEY_LENGTH,
    TEST_CONFIG,
)
from lean_spec.spec.crypto.xmss.prf import PRFKey
from lean_spec.spec.ssz import Uint64


def test_key_gen_is_random() -> None:
    """Freshly generated keys have the fixed length, are all distinct, and never trivial."""
    # A freshly generated key has the fixed key length.
    key = PRFKey.generate()
    assert len(key) == PRF_KEY_LENGTH

    # Generate many keys and require every one to be distinct.
    #
    # The set size equals the trial count only when no two keys collide.
    # This proves the generator is not deterministic across calls.
    num_trials = 10
    keys = {PRFKey.generate() for _ in range(num_trials)}
    assert len(keys) == num_trials

    # No generated key is a single byte repeated.
    #
    # A secure random generator producing such a key is astronomically unlikely.
    assert all(len(set(key)) > 1 for key in keys)


def test_apply_is_sensitive_to_inputs() -> None:
    """Changing any single input to chain-start derivation changes the output."""
    config = TEST_CONFIG

    # Generate a baseline output with a set of initial inputs.
    key1 = PRFKey(b"\x11" * PRF_KEY_LENGTH)
    epoch1 = Uint64(10)
    chain_index1 = Uint64(20)
    baseline_output = key1.derive_chain_start(config, epoch1, chain_index1)
    assert len(baseline_output) == config.HASH_LENGTH_FIELD_ELEMENTS

    # Test sensitivity to the key.
    key2 = PRFKey(b"\x22" * PRF_KEY_LENGTH)
    output_key_changed = key2.derive_chain_start(config, epoch1, chain_index1)
    assert baseline_output != output_key_changed

    # Test sensitivity to the epoch.
    epoch2 = Uint64(11)
    output_epoch_changed = key1.derive_chain_start(config, epoch2, chain_index1)
    assert baseline_output != output_epoch_changed

    # Test sensitivity to the chain_index.
    chain_index2 = Uint64(21)
    output_index_changed = key1.derive_chain_start(config, epoch1, chain_index2)
    assert baseline_output != output_index_changed
