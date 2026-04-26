"""Unit tests for the AttestationPool value object."""

from __future__ import annotations

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.forkchoice import AttestationPool, AttestationSignatureEntry
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import ByteListMiB, Bytes32
from tests.lean_spec.helpers import make_attestation_data, make_bytes32, make_mock_signature


def _proof(participants: list[int]) -> AggregatedSignatureProof:
    """Build a placeholder aggregated proof for the given validator indices."""
    return AggregatedSignatureProof(
        participants=ValidatorIndices(
            data=[ValidatorIndex(p) for p in participants]
        ).to_aggregation_bits(),
        proof_data=ByteListMiB(data=b""),
    )


def _data_at(slot_value: int, root_seed: int = 1) -> "make_attestation_data":  # type: ignore[name-defined]
    """Attestation data with target slot equal to the input slot."""
    return make_attestation_data(
        slot=Slot(slot_value),
        target_slot=Slot(slot_value),
        target_root=make_bytes32(root_seed),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )


def test_default_pool_is_empty() -> None:
    """Default-constructed pool has all three stages empty."""
    pool = AttestationPool()
    assert pool.signatures == {}
    assert pool.new_proofs == {}
    assert pool.known_proofs == {}


def test_prune_drops_target_at_finalized_slot() -> None:
    """Prune removes entries whose target slot equals the finalized slot."""
    data = _data_at(5)
    sig = AttestationSignatureEntry(ValidatorIndex(0), make_mock_signature())
    pool = AttestationPool(signatures={data: {sig}})

    pruned = pool.prune_finalized(Slot(5))

    assert pruned.signatures == {}


def test_prune_drops_target_before_finalized_slot() -> None:
    """Prune removes entries whose target slot is below the finalized slot."""
    data = _data_at(3)
    sig = AttestationSignatureEntry(ValidatorIndex(0), make_mock_signature())
    pool = AttestationPool(signatures={data: {sig}})

    pruned = pool.prune_finalized(Slot(5))

    assert pruned.signatures == {}


def test_prune_keeps_target_after_finalized_slot() -> None:
    """Prune retains entries whose target slot is above the finalized slot."""
    data = _data_at(10)
    sig = AttestationSignatureEntry(ValidatorIndex(0), make_mock_signature())
    pool = AttestationPool(signatures={data: {sig}})

    pruned = pool.prune_finalized(Slot(5))

    assert pruned.signatures == {data: {sig}}


def test_prune_filters_all_three_stages_atomically() -> None:
    """One prune call applies the same predicate to signatures, new and known proofs."""
    stale = _data_at(3, root_seed=1)
    fresh = _data_at(10, root_seed=2)
    sig_stale = AttestationSignatureEntry(ValidatorIndex(0), make_mock_signature())
    sig_fresh = AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())
    proof = _proof([0])

    pool = AttestationPool(
        signatures={stale: {sig_stale}, fresh: {sig_fresh}},
        new_proofs={stale: {proof}, fresh: {proof}},
        known_proofs={stale: {proof}, fresh: {proof}},
    )

    pruned = pool.prune_finalized(Slot(5))

    assert pruned == AttestationPool(
        signatures={fresh: {sig_fresh}},
        new_proofs={fresh: {proof}},
        known_proofs={fresh: {proof}},
    )


def test_add_signature_creates_first_entry() -> None:
    """First signature for a key initializes the inner set."""
    data = _data_at(1)
    sig = AttestationSignatureEntry(ValidatorIndex(0), make_mock_signature())

    pool = AttestationPool().add_signature(data, sig)

    assert pool.signatures == {data: {sig}}


def test_add_signature_appends_to_existing_entry() -> None:
    """Subsequent signatures for the same key union into the existing set."""
    data = _data_at(1)
    sig0 = AttestationSignatureEntry(ValidatorIndex(0), make_mock_signature())
    sig1 = AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())

    pool = AttestationPool().add_signature(data, sig0).add_signature(data, sig1)

    assert pool.signatures == {data: {sig0, sig1}}


def test_add_signature_does_not_mutate_previous_pool() -> None:
    """Returned pool owns a fresh dict and inner set; the prior pool is untouched."""
    data = _data_at(1)
    sig0 = AttestationSignatureEntry(ValidatorIndex(0), make_mock_signature())
    sig1 = AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())

    pool0 = AttestationPool().add_signature(data, sig0)
    pool1 = pool0.add_signature(data, sig1)

    # Mutating either resulting set must not bleed into the other.
    assert pool0.signatures == {data: {sig0}}
    assert pool1.signatures == {data: {sig0, sig1}}
    assert pool0.signatures[data] is not pool1.signatures[data]


def test_add_new_proof_creates_first_entry() -> None:
    """First proof for a key initializes the inner set in new_proofs."""
    data = _data_at(2)
    proof = _proof([0])

    pool = AttestationPool().add_new_proof(data, proof)

    assert pool.new_proofs == {data: {proof}}


def test_add_new_proof_does_not_touch_other_stages() -> None:
    """add_new_proof leaves signatures and known_proofs untouched."""
    data = _data_at(2)
    proof = _proof([0])

    pool = AttestationPool().add_new_proof(data, proof)

    assert pool.signatures == {}
    assert pool.known_proofs == {}


def test_add_block_proofs_targets_known_pool() -> None:
    """Block-included proofs land in known_proofs, bypassing new_proofs."""
    data = _data_at(2)
    proof = _proof([0])

    pool = AttestationPool().add_block_proofs({data: {proof}})

    assert pool.known_proofs == {data: {proof}}
    assert pool.new_proofs == {}


def test_add_block_proofs_unions_with_existing_known() -> None:
    """Repeated block batches union into the same data key in known_proofs."""
    data = _data_at(2)
    proof_a = _proof([0])
    proof_b = _proof([1])

    pool = AttestationPool(known_proofs={data: {proof_a}}).add_block_proofs({data: {proof_b}})

    assert pool.known_proofs == {data: {proof_a, proof_b}}


def test_migrate_new_to_known_unions_and_clears() -> None:
    """Migration unions new_proofs into known_proofs and empties new_proofs."""
    data = _data_at(3)
    proof_known = _proof([0])
    proof_new = _proof([1])
    pool = AttestationPool(
        new_proofs={data: {proof_new}},
        known_proofs={data: {proof_known}},
    )

    migrated = pool.migrate_new_to_known()

    assert migrated == AttestationPool(known_proofs={data: {proof_known, proof_new}})


def test_migrate_with_disjoint_keys_preserves_both() -> None:
    """Migration leaves keys that exist only in known_proofs untouched."""
    new_data = _data_at(3, root_seed=1)
    known_data = _data_at(4, root_seed=2)
    proof_new = _proof([0])
    proof_known = _proof([1])
    pool = AttestationPool(
        new_proofs={new_data: {proof_new}},
        known_proofs={known_data: {proof_known}},
    )

    migrated = pool.migrate_new_to_known()

    assert migrated == AttestationPool(
        known_proofs={known_data: {proof_known}, new_data: {proof_new}}
    )


def test_replace_after_aggregation_overwrites_new_pool() -> None:
    """Replacement is wholesale: pre-existing new_proofs entries are dropped.

    This pins the documented aggregate behavior: any data that did not
    produce a fresh proof this round disappears from new_proofs, even if
    it had a stale entry.
    """
    stale_data = _data_at(2, root_seed=1)
    fresh_data = _data_at(3, root_seed=2)
    stale_proof = _proof([0])
    fresh_proof = _proof([1])
    pool = AttestationPool(new_proofs={stale_data: {stale_proof}})

    aggregated = pool.replace_after_aggregation({fresh_data: {fresh_proof}})

    assert aggregated.new_proofs == {fresh_data: {fresh_proof}}


def test_replace_after_aggregation_keeps_unconsumed_signatures() -> None:
    """Gossip signatures whose data did not produce a fresh proof survive."""
    data_consumed = _data_at(2, root_seed=1)
    data_kept = _data_at(3, root_seed=2)
    sig_consumed = AttestationSignatureEntry(ValidatorIndex(0), make_mock_signature())
    sig_kept = AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())
    proof = _proof([0])

    pool = AttestationPool(
        signatures={data_consumed: {sig_consumed}, data_kept: {sig_kept}},
    )

    aggregated = pool.replace_after_aggregation({data_consumed: {proof}})

    assert aggregated.signatures == {data_kept: {sig_kept}}


def test_replace_after_aggregation_leaves_known_pool_untouched() -> None:
    """Aggregation does not touch known_proofs."""
    data = _data_at(2)
    known_proof = _proof([0])
    new_proof = _proof([1])
    pool = AttestationPool(known_proofs={data: {known_proof}})

    aggregated = pool.replace_after_aggregation({data: {new_proof}})

    assert aggregated.known_proofs == {data: {known_proof}}
