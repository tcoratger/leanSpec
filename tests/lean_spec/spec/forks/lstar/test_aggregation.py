"""Tests for attestation signature aggregation and greedy proof selection."""

from __future__ import annotations

from consensus_testing.keys import XmssKeyManager

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import AggregationBits, Checkpoint, Interval, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import AttestationSignatureEntry
from lean_spec.spec.forks.lstar.aggregation import select_proofs_for_coverage
from lean_spec.spec.forks.lstar.config import INTERVALS_PER_SLOT
from lean_spec.spec.forks.lstar.containers import (
    AttestationData,
    SignedAttestation,
    SingleMessageAggregate,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import ByteList512KiB, Bytes32
from tests.lean_spec.helpers import (
    make_attestation_data_simple,
    make_bytes32,
    make_store,
    make_store_with_attestation_signatures,
)


def _proof(validator_indices: list[int], distinguishing_bytes: bytes) -> SingleMessageAggregate:
    """
    Build a proof covering the given validators.

    Args:
        validator_indices: Validators this proof attests for.
        distinguishing_bytes: Proof payload that makes this object distinct.
            Also drives the canonical-bytes tie-break.
    """
    return SingleMessageAggregate(
        participants=AggregationBits.from_indices([ValidatorIndex(i) for i in validator_indices]),
        proof=ByteList512KiB(data=distinguishing_bytes),
    )


class TestSelectProofsForCoverage:
    """Test greedy proof selection over single-message aggregate proofs."""

    def test_picks_proof_with_most_coverage_first(self) -> None:
        """The proof adding the most uncovered validators is selected first."""
        wide = _proof([1, 2, 3], b"\xaa")
        narrow = _proof([4], b"\xbb")

        selected, covered = select_proofs_for_coverage({wide, narrow})

        assert selected == [wide, narrow]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3, 4)}

    def test_stops_when_remaining_proof_adds_no_new_validator(self) -> None:
        """A proof whose validators are already covered is never selected."""
        full = _proof([1, 2, 3], b"\xaa")
        subset = _proof([1, 2], b"\xbb")

        selected, covered = select_proofs_for_coverage({full, subset})

        assert selected == [full]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3)}

    def test_partial_overlap_picks_by_marginal_coverage(self) -> None:
        """Greedy scores by new coverage, then takes the next proof for its remainder."""
        # The second proof shares validator 3, so its marginal gain is only {4}.
        first = _proof([1, 2, 3], b"\xaa")
        overlapping = _proof([3, 4], b"\xbb")

        selected, covered = select_proofs_for_coverage({first, overlapping})

        assert selected == [first, overlapping]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3, 4)}

    def test_priority_pool_is_consumed_before_fallback(self) -> None:
        """A priority proof is chosen first even when a fallback proof covers more."""
        priority = _proof([1, 2], b"\xaa")
        fallback = _proof([1, 2, 3, 4, 5], b"\xbb")

        selected, covered = select_proofs_for_coverage({priority}, {fallback})

        assert selected == [priority, fallback]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3, 4, 5)}

    def test_fallback_proof_already_covered_by_priority_is_skipped(self) -> None:
        """A fallback proof adds nothing when priority already covers its validators."""
        priority = _proof([1, 2, 3], b"\xaa")
        redundant_fallback = _proof([1, 2], b"\xbb")

        selected, covered = select_proofs_for_coverage({priority}, {redundant_fallback})

        assert selected == [priority]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3)}

    def test_exhausting_priority_pool_early_still_processes_fallback(self) -> None:
        """Stopping one pool early still lets the next pool contribute."""
        # The priority subset adds nothing after the full proof, ending that pool.
        # The fallback must still be consulted afterward.
        full = _proof([1, 2, 3], b"\xaa")
        subset = _proof([1, 2], b"\xbb")
        fallback = _proof([4], b"\xcc")

        selected, covered = select_proofs_for_coverage({full, subset}, {fallback})

        assert selected == [full, fallback]
        assert covered == {ValidatorIndex(i) for i in (1, 2, 3, 4)}

    def test_none_and_empty_pools_are_skipped(self) -> None:
        """None or empty pools contribute nothing and select nothing."""
        assert select_proofs_for_coverage(None) == ([], set())
        assert select_proofs_for_coverage(set()) == ([], set())
        assert select_proofs_for_coverage(None, None) == ([], set())

    def test_tie_break_prefers_larger_canonical_encoding(self) -> None:
        """Tied proofs resolve to the one with the larger canonical encoding."""
        # Both cover the same single validator, so only one can be chosen.
        # The winner must be fixed by canonical bytes, not set iteration order.
        smaller = _proof([1], b"\x01")
        larger = _proof([1], b"\x02")

        # Precondition: the second proof really does encode larger.
        # If this ever flips, the assertion below is meaningless, so pin it.
        assert larger.encode_bytes() > smaller.encode_bytes()

        selected, covered = select_proofs_for_coverage({smaller, larger})

        assert selected == [larger]
        assert covered == {ValidatorIndex(1)}


class TestAggregateCommitteeSignatures:
    """
    Integration tests for committee signature aggregation.

    Tests that gossip signatures are correctly aggregated into proofs
    and stored for later use.
    """

    def test_aggregates_attestation_signatures_into_proof(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """
        Aggregation creates proofs from collected gossip signatures.

        Expected behavior:
        1. Extract attestations from stored signatures
        2. Aggregate signatures into a single proof
        3. Store resulting proofs for later use
        """
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_attestation_signatures(
            key_manager,
            num_validators=4,
            validator_index=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        # Perform aggregation
        updated_store, _ = spec.aggregate(store)

        # Verify proofs were created and stored keyed by attestation data
        assert attestation_data in updated_store.latest_new_aggregated_payloads, (
            "Aggregated proof should be stored for this attestation data"
        )
        proofs = updated_store.latest_new_aggregated_payloads[attestation_data]
        assert len(proofs) >= 1, "At least one proof should exist"

    def test_aggregated_proof_is_valid(self, key_manager: XmssKeyManager, spec: LstarSpec) -> None:
        """
        Created aggregated proof passes verification.

        The proof should be cryptographically valid and verifiable
        against the original public keys.
        """
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_attestation_signatures(
            key_manager,
            num_validators=4,
            validator_index=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        updated_store, _ = spec.aggregate(store)

        proofs = updated_store.latest_new_aggregated_payloads[attestation_data]
        proof = next(iter(proofs))

        # Extract participants from the proof
        participants = proof.participants.to_validator_indices()
        public_keys = [
            key_manager[validator_index].attestation_keypair.public_key
            for validator_index in participants
        ]

        # Verify proof is valid
        proof.verify(
            public_keys=public_keys,
            message=hash_tree_root(attestation_data),
            slot=attestation_data.slot,
        )

    def test_empty_attestation_signatures_produces_no_proofs(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """
        No proofs created when attestation_signatures is empty.

        This is the expected behavior when no attestations have been received.
        """
        store, _ = make_store_with_attestation_signatures(
            key_manager,
            num_validators=4,
            validator_index=ValidatorIndex(0),
            attesting_validators=[],  # No attesters
        )

        updated_store, _ = spec.aggregate(store)

        # Verify no proofs were created
        assert len(updated_store.latest_new_aggregated_payloads) == 0

    def test_multiple_attestation_data_grouped_separately(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """
        Signatures for different attestation data are aggregated separately.

        Each unique AttestationData should produce its own aggregated proof.
        """
        base_store = make_store(
            num_validators=4, key_manager=key_manager, validator_index=ValidatorIndex(0)
        )

        # Create two different attestation data (different slots)
        attestation_data_1 = spec.produce_attestation_data(base_store, Slot(1))
        # Create a second attestation data with different head
        attestation_data_2 = AttestationData(
            slot=Slot(1),
            head=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(1)),
            target=attestation_data_1.target,
            source=attestation_data_1.source,
        )

        # Validators 1 attests to data_1, validator 2 attests to data_2
        signature_1 = key_manager.sign_attestation_data(ValidatorIndex(1), attestation_data_1)
        signature_2 = key_manager.sign_attestation_data(ValidatorIndex(2), attestation_data_2)
        attestation_signatures = {
            attestation_data_1: {AttestationSignatureEntry(ValidatorIndex(1), signature_1)},
            attestation_data_2: {AttestationSignatureEntry(ValidatorIndex(2), signature_2)},
        }

        base_store.attestation_signatures = attestation_signatures
        store = base_store

        updated_store, _ = spec.aggregate(store)

        # Verify both attestation data have separate proofs
        assert attestation_data_1 in updated_store.latest_new_aggregated_payloads
        assert attestation_data_2 in updated_store.latest_new_aggregated_payloads


class TestTickIntervalAggregation:
    """
    Integration tests for interval-triggered aggregation.

    Tests that interval 2 (aggregation interval) correctly triggers
    signature aggregation for aggregator nodes.
    """

    def test_interval_2_triggers_aggregation_for_aggregator(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """
        Aggregation is triggered at interval 2 when is_aggregator=True.

        At interval 2, aggregator nodes collect and aggregate signatures.
        Non-aggregators skip this step.
        """
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_attestation_signatures(
            key_manager,
            num_validators=4,
            validator_index=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        # Set time to interval 1 (so next tick goes to interval 2)
        # time % INTERVALS_PER_SLOT determines current interval
        # We want to end up at interval 2 after tick
        store.time = Interval(1)

        # Tick to interval 2 as aggregator
        updated_store, _ = spec.tick_interval(store, has_proposal=False, is_aggregator=True)

        # Verify aggregation was performed
        assert attestation_data in updated_store.latest_new_aggregated_payloads, (
            "Aggregation should occur at interval 2 for aggregators"
        )

    def test_interval_2_skips_aggregation_for_non_aggregator(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """
        Aggregation is NOT triggered at interval 2 when is_aggregator=False.

        Non-aggregator nodes should not perform aggregation even at interval 2.
        """
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_attestation_signatures(
            key_manager,
            num_validators=4,
            validator_index=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        # Set time to interval 1
        store.time = Interval(1)

        # Tick to interval 2 as NON-aggregator
        updated_store, _ = spec.tick_interval(store, has_proposal=False, is_aggregator=False)

        # Verify aggregation was NOT performed
        assert attestation_data not in updated_store.latest_new_aggregated_payloads, (
            "Aggregation should NOT occur for non-aggregators"
        )

    def test_other_intervals_do_not_trigger_aggregation(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """
        Aggregation is NOT triggered at intervals other than 2.

        Only interval 2 should trigger aggregation, even for aggregators.
        """
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_attestation_signatures(
            key_manager,
            num_validators=4,
            validator_index=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        # Test intervals 0, 1, 3, 4 (skip 2)
        non_aggregation_intervals = [0, 1, 3, 4]

        for target_interval in non_aggregation_intervals:
            # Set time so next tick lands on target_interval
            # After tick, time becomes time+1, and interval = (time+1) % 5
            # So we need time+1 % 5 == target_interval
            # Therefore time = target_interval - 1 (mod 5)
            pre_tick_time = (target_interval - 1) % int(INTERVALS_PER_SLOT)
            store.time = Interval(pre_tick_time)
            test_store = store

            updated_store, _ = spec.tick_interval(
                test_store, has_proposal=False, is_aggregator=True
            )

            assert attestation_data not in updated_store.latest_new_aggregated_payloads, (
                f"Aggregation should NOT occur at interval {target_interval}"
            )

    def test_interval_0_accepts_attestations_with_proposal(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """
        Interval 0 accepts new attestations when has_proposal=True.

        This tests that interval 0 performs its own action (accepting attestations)
        rather than aggregation.
        """
        store = make_store(
            num_validators=4, key_manager=key_manager, validator_index=ValidatorIndex(0)
        )

        # Set time to interval 4 (so next tick wraps to interval 0)
        store.time = Interval(4)

        # Tick to interval 0 with proposal
        updated_store, _ = spec.tick_interval(store, has_proposal=True, is_aggregator=True)

        # Verify time advanced
        assert updated_store.time == Interval(5)
        # Interval should now be 0
        assert Interval(int(updated_store.time) % int(INTERVALS_PER_SLOT)) == Interval(0)


class TestEndToEndAggregationFlow:
    """
    End-to-end test for the complete aggregation flow.

    Tests the full path from gossip attestation reception through
    interval-triggered aggregation to proof storage.
    """

    def test_gossip_to_aggregation_to_storage(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """
        Complete flow: gossip attestation -> aggregation -> proof storage.

        Simulates:
        1. Validators send signed attestations via gossip
        2. Aggregator receives and stores signatures (same subnet)
        3. At interval 2, aggregator creates aggregated proof
        4. Proof is stored in latest_new_aggregated_payloads
        """
        num_validators = 4
        aggregator_id = ValidatorIndex(0)

        store = make_store(
            num_validators=num_validators, key_manager=key_manager, validator_index=aggregator_id
        )
        # Advance the clock to slot 1 so the attestation's slot has begun.
        store.time = Interval.from_slot(Slot(1))

        attestation_data = spec.produce_attestation_data(store, Slot(1))

        # Step 1: Receive gossip attestations from validators 1 and 2
        # (all in same subnet since ATTESTATION_COMMITTEE_COUNT=1 by default)
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        for validator_index in attesting_validators:
            signed_attestation = SignedAttestation(
                validator_index=validator_index,
                data=attestation_data,
                signature=key_manager.sign_attestation_data(validator_index, attestation_data),
            )
            store = spec.on_gossip_attestation(
                store,
                signed_attestation,
                is_aggregator=True,
            )

        # Verify signatures were stored
        signatures = store.attestation_signatures.get(attestation_data, set())
        stored_validators = {entry.validator_index for entry in signatures}
        for validator_index in attesting_validators:
            assert validator_index in stored_validators, (
                f"Signature for {validator_index} should be stored"
            )

        # Step 2: Advance to interval 2 (aggregation interval)
        store.time = Interval(1)
        store, _ = spec.tick_interval(store, has_proposal=False, is_aggregator=True)

        # Step 3: Verify aggregated proofs were created
        assert attestation_data in store.latest_new_aggregated_payloads, (
            "Aggregated proofs should exist after interval 2"
        )

        # Step 4: Verify the proof is valid
        proof = next(iter(store.latest_new_aggregated_payloads[attestation_data]))
        participants = proof.participants.to_validator_indices()
        public_keys = [
            key_manager[validator_index].attestation_keypair.public_key
            for validator_index in participants
        ]

        proof.verify(
            public_keys=public_keys,
            message=hash_tree_root(attestation_data),
            slot=attestation_data.slot,
        )


def test_aggregated_signatures_prefers_full_gossip_payload(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    store = make_store(num_validators=2, key_manager=container_key_manager)
    head_state = store.states[store.head]
    source = Checkpoint(root=make_bytes32(1), slot=Slot(0))
    attestation_data = make_attestation_data_simple(
        Slot(2), make_bytes32(3), make_bytes32(4), source=source
    )
    attestation_signatures = {
        attestation_data: {
            AttestationSignatureEntry(
                ValidatorIndex(i),
                container_key_manager.sign_attestation_data(ValidatorIndex(i), attestation_data),
            )
            for i in range(2)
        }
    }

    store.attestation_signatures = attestation_signatures
    _, results = spec.aggregate(store)

    assert len(results) == 1
    assert set(results[0].proof.participants.to_validator_indices()) == {
        ValidatorIndex(0),
        ValidatorIndex(1),
    }

    public_keys = [
        head_state.validators[ValidatorIndex(i)].get_attestation_public_key() for i in range(2)
    ]
    results[0].proof.verify(
        public_keys=public_keys,
        message=hash_tree_root(attestation_data),
        slot=attestation_data.slot,
    )


def test_aggregate_with_empty_attestation_signatures(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """Empty attestations list should return empty results."""
    store = make_store(num_validators=2, key_manager=container_key_manager)
    _, results = spec.aggregate(store)

    assert results == []


def test_aggregated_signatures_with_multiple_data_groups(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """Multiple attestation data groups should be processed independently."""
    store = make_store(num_validators=4, key_manager=container_key_manager)
    source = Checkpoint(root=make_bytes32(22), slot=Slot(0))
    attestation_data1 = make_attestation_data_simple(
        Slot(9), make_bytes32(23), make_bytes32(24), source=source
    )
    attestation_data2 = make_attestation_data_simple(
        Slot(10), make_bytes32(25), make_bytes32(26), source=source
    )

    attestation_signatures = {
        attestation_data1: {
            AttestationSignatureEntry(
                ValidatorIndex(0),
                container_key_manager.sign_attestation_data(ValidatorIndex(0), attestation_data1),
            ),
            AttestationSignatureEntry(
                ValidatorIndex(1),
                container_key_manager.sign_attestation_data(ValidatorIndex(1), attestation_data1),
            ),
        },
        attestation_data2: {
            AttestationSignatureEntry(
                ValidatorIndex(2),
                container_key_manager.sign_attestation_data(ValidatorIndex(2), attestation_data2),
            ),
            AttestationSignatureEntry(
                ValidatorIndex(3),
                container_key_manager.sign_attestation_data(ValidatorIndex(3), attestation_data2),
            ),
        },
    }

    store.attestation_signatures = attestation_signatures
    _, results = spec.aggregate(store)

    assert len(results) == 2

    for signed_attestation in results:
        participants = signed_attestation.proof.participants.to_validator_indices()
        public_keys = [
            container_key_manager[validator_index].attestation_keypair.public_key
            for validator_index in participants
        ]
        signed_attestation.proof.verify(
            public_keys=public_keys,
            message=hash_tree_root(signed_attestation.data),
            slot=signed_attestation.data.slot,
        )


def test_aggregate_with_no_signatures(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """
    Test edge case where the store has no attestation signatures or payloads.

    Returns empty results (no attestations can be aggregated without signatures).
    """
    store = make_store(num_validators=2, key_manager=container_key_manager)
    _, results = spec.aggregate(store)

    assert results == []
