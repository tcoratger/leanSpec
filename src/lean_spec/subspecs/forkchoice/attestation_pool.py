"""In-memory three-stage attestation pool used by the forkchoice store."""

from typing import NamedTuple

from lean_spec.subspecs.containers.attestation.attestation import AttestationData
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.types.base import StrictBaseModel


class AttestationSignatureEntry(NamedTuple):
    """One validator's gossip signature paired with its index."""

    validator_id: ValidatorIndex
    signature: Signature


class AttestationPool(StrictBaseModel):
    """Three-stage attestation evidence shared across the slot's interval cycle.

    Stages and their roles:

    - signatures: aggregator inbox of raw single-validator gossip signatures.
      Drained when aggregation runs.
    - new_proofs: aggregated proofs produced this round. Used as a current-slot
      availability signal for safe-target selection. Promoted at slot rollover.
    - known_proofs: aggregated proofs eligible to weigh head selection and
      reusable as building blocks for deeper aggregation.

    Block-included attestations bypass the new pool and land directly in known
    so they can influence fork choice without waiting for a stage migration.

    The pool is kept in memory only and never serialized to the wire, hence
    the plain strict-model base instead of an SSZ container.
    """

    signatures: dict[AttestationData, set[AttestationSignatureEntry]] = {}
    """Pending raw gossip signatures, grouped by attestation data."""

    new_proofs: dict[AttestationData, set[AggregatedSignatureProof]] = {}
    """Aggregated proofs from the current round, not yet weighted by fork choice."""

    known_proofs: dict[AttestationData, set[AggregatedSignatureProof]] = {}
    """Aggregated proofs already eligible to influence head selection."""

    def prune_finalized(self, finalized_slot: Slot) -> "AttestationPool":
        """Drop every entry whose target slot is not strictly above the finalized slot.

        An attestation whose target sits inside the finalized prefix can no
        longer change chain selection, so it is safe to forget.

        Args:
            finalized_slot: The current finalized slot. Used as a strict lower bound.

        Returns:
            A new pool with stale entries filtered out.
        """
        # Strict-greater predicate: an entry survives only if its target slot
        # sits strictly past the finalized boundary.
        #
        # Why strict: a target equal to the finalized slot is already absorbed
        # into the finalized prefix and cannot move the head.
        #
        # Inner sets are not mutated here, so the same set objects can be
        # reused in the new dicts without copying.
        return self.model_copy(
            update={
                "signatures": {
                    data: sigs
                    for data, sigs in self.signatures.items()
                    if data.target.slot > finalized_slot
                },
                "new_proofs": {
                    data: proofs
                    for data, proofs in self.new_proofs.items()
                    if data.target.slot > finalized_slot
                },
                "known_proofs": {
                    data: proofs
                    for data, proofs in self.known_proofs.items()
                    if data.target.slot > finalized_slot
                },
            }
        )

    def add_signature(
        self, data: AttestationData, entry: AttestationSignatureEntry
    ) -> "AttestationPool":
        """Record one validator's gossip signature into the aggregator inbox.

        Args:
            data: Attestation data the signature attests to.
            entry: Validator index plus its raw signature.

        Returns:
            A new pool with the signature added under the matching data key.
        """
        # Shallow-copy the outer dict and clone each inner set.
        #
        # Why: the previous pool must remain untouched for callers holding it.
        signatures = {k: set(v) for k, v in self.signatures.items()}

        # Append to the bucket for this attestation data, creating it if absent.
        signatures.setdefault(data, set()).add(entry)

        return self.model_copy(update={"signatures": signatures})

    def add_new_proof(
        self, data: AttestationData, proof: AggregatedSignatureProof
    ) -> "AttestationPool":
        """Record a freshly aggregated proof under the given attestation data.

        Args:
            data: Attestation data the proof covers.
            proof: Aggregated proof produced this round.

        Returns:
            A new pool with the proof added to the new-proofs stage.
        """
        # Same copy-on-write discipline as the signature path: the prior pool
        # is left intact for any caller still holding a reference.
        new_proofs = {k: set(v) for k, v in self.new_proofs.items()}

        # Place the proof into the bucket for this attestation data.
        new_proofs.setdefault(data, set()).add(proof)

        return self.model_copy(update={"new_proofs": new_proofs})

    def add_block_proofs(
        self,
        proofs_by_data: dict[AttestationData, set[AggregatedSignatureProof]],
    ) -> "AttestationPool":
        """Merge a batch of block-included proofs straight into the known pool.

        Block-included proofs skip the new stage on purpose: they have already
        been validated as part of the block and can immediately weigh head
        selection without waiting for a slot rollover.

        Args:
            proofs_by_data: Aggregated proofs grouped by attestation data.

        Returns:
            A new pool with the block proofs unioned into the known stage.
        """
        # Clone outer dict and inner sets up front.
        #
        # Why: the union step below mutates inner sets in place.
        known_proofs = {k: set(v) for k, v in self.known_proofs.items()}

        # Union each incoming bucket into the matching known bucket.
        for data, proofs in proofs_by_data.items():
            known_proofs.setdefault(data, set()).update(proofs)

        return self.model_copy(update={"known_proofs": known_proofs})

    def migrate_new_to_known(self) -> "AttestationPool":
        """Promote every new-stage proof into the known stage and clear the new stage.

        Called at the slot boundary that makes current-round aggregates
        eligible for fork-choice weighting.

        Returns:
            A new pool with an empty new stage and all proofs unioned into known.
        """
        # Clone the known stage as the merge target.
        #
        # Why a clone: the union below mutates the dict's inner sets.
        merged = {k: set(v) for k, v in self.known_proofs.items()}

        # Fold each new-stage bucket into the matching known bucket.
        for data, proofs in self.new_proofs.items():
            merged.setdefault(data, set()).update(proofs)

        # Reset the new stage; everything has been promoted.
        return self.model_copy(update={"known_proofs": merged, "new_proofs": {}})

    def replace_after_aggregation(
        self,
        new_proofs: dict[AttestationData, set[AggregatedSignatureProof]],
    ) -> "AttestationPool":
        """Swap in this round's aggregated proofs and drop the consumed signatures.

        The new stage is replaced wholesale rather than merged.

        Why a replace, not a merge:

        - Aggregation may early-exit on a lone child without producing a fresh
          proof for an attestation data that was present last round.
        - Re-emitting that stale aggregate would misrepresent the current
          round's evidence.
        - Any pre-existing entry that did not produce a fresh proof this round
          is therefore deliberately discarded.

        Gossip signatures whose attestation data appears in the supplied
        new-stage map are considered consumed and dropped. Signatures keyed
        on other attestation data survive so they can feed the next round.

        Args:
            new_proofs: The freshly produced aggregated proofs for this round.

        Returns:
            A new pool with the new stage replaced and consumed signatures removed.
        """
        # Keep only signatures that were not folded into a fresh proof.
        #
        # Why filter on data only: every signature under a consumed data
        # bucket has been absorbed into the new aggregate, so the entire
        # bucket is redundant.
        #
        # Inner sets stay intact; the filter is purely on the dict keys.
        signatures = {
            data: sigs for data, sigs in self.signatures.items() if data not in new_proofs
        }

        return self.model_copy(update={"new_proofs": new_proofs, "signatures": signatures})
