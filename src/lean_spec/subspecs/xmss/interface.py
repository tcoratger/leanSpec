"""Public interface for the Generalized XMSS signature scheme."""

from lean_spec.config import LEAN_ENV
from lean_spec.types import Bytes32, Slot, StrictBaseModel, Uint64

from .constants import PROD_CONFIG, TEST_CONFIG, XmssConfig
from .containers import KeyPair, PublicKey, SecretKey, Signature
from .encoding import target_sum_encode
from .field import random_parameter
from .merkle import HashSubTree, combined_path, verify_path
from .poseidon import PROD_POSEIDON, TEST_POSEIDON, PoseidonXmss
from .prf import prf_apply, prf_get_randomness, prf_key_gen
from .types import HashDigestList, HashDigestVector


def _expand_activation_time(
    log_lifetime: int, desired_activation_slot: int, desired_num_active_slots: int
) -> tuple[int, int]:
    """Align a requested activation interval to top-bottom tree boundaries.

    Phase 1: round start down to a multiple of sqrt(LIFETIME).
    Phase 2: round end up to a multiple of sqrt(LIFETIME).
    Phase 3: enforce a minimum duration of two bottom trees.
    Phase 4: clamp to the lifetime bound, shifting the interval if needed.

    Args:
        log_lifetime: Base-2 logarithm of the lifetime.
        desired_activation_slot: First slot requested.
        desired_num_active_slots: Number of slots requested.

    Returns:
        The pair (start_bottom_tree_index, end_bottom_tree_index).
        Actual slots covered are [start * C, end * C) where C = sqrt(LIFETIME).
    """
    # C = sqrt(LIFETIME).
    # c_mask rounds down to multiples of C.
    c = 1 << (log_lifetime // 2)
    c_mask = ~(c - 1)

    desired_end_slot = desired_activation_slot + desired_num_active_slots

    # Phase 1 + 2: snap the interval endpoints onto bottom-tree boundaries.
    start = desired_activation_slot & c_mask
    end = (desired_end_slot + c - 1) & c_mask

    # Phase 3: at least two bottom trees so the prepared window always fits.
    if end - start < 2 * c:
        end = start + 2 * c

    # Phase 4: clamp to [0, LIFETIME).
    lifetime = c * c
    if end > lifetime:
        duration = end - start
        if duration > lifetime:
            # The requested interval is wider than the lifetime.
            # Use the whole lifetime.
            start = 0
            end = lifetime
        else:
            # Shift the interval back so it ends exactly at the lifetime boundary.
            end = lifetime
            start = (lifetime - duration) & c_mask

    return (start // c, end // c)


class GeneralizedXmssScheme(StrictBaseModel):
    """Generalized XMSS signature scheme bound to one configuration."""

    config: XmssConfig
    """Configuration parameters for this instance."""

    poseidon: PoseidonXmss
    """Cached Poseidon1 engine used by every primitive in the scheme."""

    def key_gen(self, activation_slot: Slot, num_active_slots: Uint64) -> KeyPair:
        """Generate a fresh key pair active for an aligned slot range.

        Phase 1: align the requested interval to sqrt(LIFETIME) boundaries.
        Phase 2: draw the master PRF key and public parameter.
        Phase 3: materialize the two leftmost bottom trees.
        Phase 4: generate every other bottom tree, retaining only its root.
        Phase 5: build the top tree from all bottom-tree roots.

        The returned key may cover a wider interval than requested because
        of boundary alignment and the two-tree minimum window.

        Args:
            activation_slot: Requested first signable slot.
            num_active_slots: Requested number of signable slots.

        Returns:
            A KeyPair with both halves of the scheme.

        Raises:
            ValueError: When the requested range exceeds the lifetime.
        """
        config = self.config

        # The requested range must fit within the global lifetime.
        if int(activation_slot) + int(num_active_slots) > int(config.LIFETIME):
            raise ValueError("Activation range exceeds the key's lifetime.")

        # Phase 2: draw the master secret and the public parameter.
        parameter = random_parameter(config)
        prf_key = prf_key_gen()

        # Phase 1: align onto bottom-tree boundaries.
        start_bottom_tree_index, end_bottom_tree_index = _expand_activation_time(
            config.LOG_LIFETIME, int(activation_slot), int(num_active_slots)
        )
        leaves_per_bottom_tree = 1 << (config.LOG_LIFETIME // 2)
        actual_activation_slot = start_bottom_tree_index * leaves_per_bottom_tree
        actual_num_active_slots = (
            end_bottom_tree_index - start_bottom_tree_index
        ) * leaves_per_bottom_tree

        # Phase 3: build the two leftmost bottom trees and keep them resident.
        left_bottom_tree = HashSubTree.from_prf_key(
            poseidon=self.poseidon,
            config=config,
            prf_key=prf_key,
            bottom_tree_index=Uint64(start_bottom_tree_index),
            parameter=parameter,
        )
        right_bottom_tree = HashSubTree.from_prf_key(
            poseidon=self.poseidon,
            config=config,
            prf_key=prf_key,
            bottom_tree_index=Uint64(start_bottom_tree_index + 1),
            parameter=parameter,
        )

        bottom_tree_roots: list[HashDigestVector] = [
            left_bottom_tree.root(),
            right_bottom_tree.root(),
        ]

        # Phase 4: build every other bottom tree and remember only its root.
        for i in range(start_bottom_tree_index + 2, end_bottom_tree_index):
            tree = HashSubTree.from_prf_key(
                poseidon=self.poseidon,
                config=config,
                prf_key=prf_key,
                bottom_tree_index=Uint64(i),
                parameter=parameter,
            )
            bottom_tree_roots.append(tree.root())

        # Phase 5: assemble the top tree from all bottom-tree roots.
        top_tree = HashSubTree.new_top_tree(
            poseidon=self.poseidon,
            config=config,
            depth=config.LOG_LIFETIME,
            start_bottom_tree_index=Uint64(start_bottom_tree_index),
            parameter=parameter,
            bottom_tree_roots=bottom_tree_roots,
        )

        pk = PublicKey(root=top_tree.root(), parameter=parameter)
        sk = SecretKey(
            prf_key=prf_key,
            parameter=parameter,
            activation_slot=Slot(actual_activation_slot),
            num_active_slots=Uint64(actual_num_active_slots),
            top_tree=top_tree,
            left_bottom_tree_index=Uint64(start_bottom_tree_index),
            left_bottom_tree=left_bottom_tree,
            right_bottom_tree=right_bottom_tree,
        )
        return KeyPair(public_key=pk, secret_key=sk)

    def sign(self, sk: SecretKey, slot: Slot, message: Bytes32) -> Signature:
        """Produce a signature for a message at a specific slot.

        Phase 1: enforce that the slot is inside the activation and prepared windows.
        Phase 2: search for randomness rho whose encoding lands on the target-sum layer.
        Phase 3: walk each Winternitz chain to the released hash dictated by the codeword.
        Phase 4: build the combined Merkle path through the bottom and top trees.

        Signing is deterministic in (sk, slot, message).
        A secret key must never sign two different messages for the same slot.

        Args:
            sk: Secret key.
            slot: Signing slot.
            message: Message to sign.

        Returns:
            A signature carrying the OTS, the Merkle path, and the randomness.

        Raises:
            ValueError: When the slot is outside the activation or prepared window.
            RuntimeError: When no valid encoding is found within MAX_TRIES attempts.
        """
        config = self.config
        slot_int = int(slot)
        activation_int = int(sk.activation_slot)

        # Phase 1a: activation bound.
        if not (activation_int <= slot_int < activation_int + int(sk.num_active_slots)):
            raise ValueError("Key is not active for the specified slot.")

        # Phase 1b: prepared bound.
        # Without two adjacent bottom trees we cannot produce a path without
        # paying the cost of regenerating them on the fly.
        leaves_per_bottom_tree = 1 << (config.LOG_LIFETIME // 2)
        prepared_start = int(sk.left_bottom_tree_index) * leaves_per_bottom_tree
        prepared_end = prepared_start + 2 * leaves_per_bottom_tree
        if not (prepared_start <= slot_int < prepared_end):
            raise ValueError(
                f"Slot {slot} is outside the prepared interval "
                f"[{prepared_start}, {prepared_end}). "
                f"Call advance_preparation() to slide the window forward."
            )

        # Phase 2: deterministic search for valid randomness.
        # Randomness comes from the PRF so signing is reproducible.
        for attempts in range(config.MAX_TRIES):
            rho = prf_get_randomness(config, sk.prf_key, slot, message, Uint64(attempts))
            codeword = target_sum_encode(self.poseidon, config, sk.parameter, message, rho, slot)
            if codeword is not None:
                break
        else:
            raise RuntimeError(
                f"Failed to find a valid message encoding after {config.MAX_TRIES} tries."
            )

        # Sanity guard against an encoder returning the wrong number of digits.
        if len(codeword) != config.DIMENSION:
            raise RuntimeError("Encoding is broken: returned too many or too few chunks.")

        # Phase 3: walk each Winternitz chain to the released hash.
        ots_hashes: list[HashDigestVector] = []
        for chain_index, steps in enumerate(codeword):
            start_digest = prf_apply(config, sk.prf_key, slot, Uint64(chain_index))
            ots_digest = self.poseidon.hash_chain(
                config=config,
                parameter=sk.parameter,
                epoch=slot,
                chain_index=chain_index,
                start_step=0,
                num_steps=steps,
                start_digest=start_digest,
            )
            ots_hashes.append(ots_digest)

        # Phase 4: combined Merkle path through both trees.
        # The signed slot picks the bottom tree on the prepared window's left or right.
        boundary = (int(sk.left_bottom_tree_index) + 1) * leaves_per_bottom_tree
        bottom_tree = sk.left_bottom_tree if slot_int < boundary else sk.right_bottom_tree
        path = combined_path(sk.top_tree, bottom_tree, Uint64(int(slot)))

        return Signature(path=path, rho=rho, hashes=HashDigestList(data=ots_hashes))

    def verify(self, pk: PublicKey, slot: Slot, message: Bytes32, sig: Signature) -> bool:
        """Verify a signature against a public key, message, and slot.

        Phase 1: bound-check the slot.
        Phase 1 rejects without raising on bad input.
        Phase 2: recompute the codeword using the randomness carried by the signature.
        Phase 3: complete each Winternitz chain from the released hash to its endpoint.
        Phase 4: rebuild the Merkle root from the chain endpoints and the opening.

        Args:
            pk: Public key.
            slot: Signing slot claimed by the signature.
            message: Message claimed by the signature.
            sig: Signature to verify.

        Returns:
            True when the signature is valid against the public key, false otherwise.
        """
        config = self.config

        # Phase 1: bound check on the slot.
        # The slot is attacker-controlled, so a malformed value returns False
        # rather than panicking deep in the verification routine.
        if int(slot) >= int(config.LIFETIME):
            return False

        # Phase 2: rederive the codeword from the signature's randomness.
        # A failing aborting decode means the signature cannot be valid.
        codeword = target_sum_encode(self.poseidon, config, pk.parameter, message, sig.rho, slot)
        if codeword is None:
            return False

        # Phase 3: finish each chain from the released hash to its endpoint.
        chain_ends: list[HashDigestVector] = []
        for chain_index, xi in enumerate(codeword):
            # The signature provides the digest after xi steps along the chain.
            # We hash the remaining BASE - 1 - xi times to reach the endpoint.
            start_digest = sig.hashes[chain_index]
            end_digest = self.poseidon.hash_chain(
                config=config,
                parameter=pk.parameter,
                epoch=slot,
                chain_index=chain_index,
                start_step=xi,
                num_steps=config.BASE - 1 - xi,
                start_digest=start_digest,
            )
            chain_ends.append(end_digest)

        # Phase 4: rebuild and compare against the trusted root.
        return verify_path(
            poseidon=self.poseidon,
            config=config,
            parameter=pk.parameter,
            root=pk.root,
            position=slot,
            leaf_parts=chain_ends,
            opening=sig.path,
        )

    def get_activation_interval(self, sk: SecretKey) -> range:
        """Return the activation interval as a Python range.

        A signature is only valid for a slot inside this range.
        """
        start = int(sk.activation_slot)
        return range(start, start + int(sk.num_active_slots))

    def get_prepared_interval(self, sk: SecretKey) -> range:
        """Return the prepared interval as a Python range.

        The prepared interval is the slot window covered by the two resident bottom trees.
        A signer can sign any slot in this range without paying the cost of
        rebuilding a bottom tree from the PRF.
        """
        leaves_per_bottom_tree = 1 << (self.config.LOG_LIFETIME // 2)
        start = int(sk.left_bottom_tree_index) * leaves_per_bottom_tree
        return range(start, start + 2 * leaves_per_bottom_tree)

    def advance_preparation(self, sk: SecretKey) -> SecretKey:
        """Slide the prepared window one bottom tree forward.

        Phase 1: bail out when the next window would exceed the activation interval.
        Phase 2: regenerate the new right bottom tree from the PRF key.
        Phase 3: shift the previous right tree to the left slot.

        Returning the same key when no advancement is possible keeps callers simple.

        Args:
            sk: Secret key whose prepared window should advance.

        Returns:
            A secret key with the window shifted by one bottom tree.
        """
        leaves_per_bottom_tree = 1 << (self.config.LOG_LIFETIME // 2)
        left_index = int(sk.left_bottom_tree_index)

        # Phase 1: no advancement once the activation interval is fully consumed.
        next_prepared_end_slot = (left_index + 3) * leaves_per_bottom_tree
        activation_end = int(sk.activation_slot) + int(sk.num_active_slots)
        if next_prepared_end_slot > activation_end:
            return sk

        # Phase 2: rebuild the next bottom tree from the master PRF key.
        new_right_bottom_tree = HashSubTree.from_prf_key(
            poseidon=self.poseidon,
            config=self.config,
            prf_key=sk.prf_key,
            bottom_tree_index=Uint64(left_index + 2),
            parameter=sk.parameter,
        )

        # Phase 3: rotate the right tree into the left slot, advance the index.
        return sk.model_copy(
            update={
                "left_bottom_tree": sk.right_bottom_tree,
                "right_bottom_tree": new_right_bottom_tree,
                "left_bottom_tree_index": Uint64(left_index + 1),
            }
        )


PROD_SIGNATURE_SCHEME = GeneralizedXmssScheme(config=PROD_CONFIG, poseidon=PROD_POSEIDON)
"""Signature scheme instance with production parameters."""

TEST_SIGNATURE_SCHEME = GeneralizedXmssScheme(config=TEST_CONFIG, poseidon=TEST_POSEIDON)
"""Signature scheme instance with test parameters."""

TARGET_SIGNATURE_SCHEME = TEST_SIGNATURE_SCHEME if LEAN_ENV == "test" else PROD_SIGNATURE_SCHEME
"""Active scheme selected at import time from the LEAN_ENV environment variable."""
