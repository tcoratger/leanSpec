"""Tests for the consensus-testing XMSS key helpers."""

from __future__ import annotations

import json
from pathlib import Path

from consensus_testing.keys import compute_key_set_digest


def write_key_file(
    keys_directory: Path,
    validator_index: int,
    attestation_public_key_hex: str,
    proposal_public_key_hex: str,
) -> None:
    """Write a schema-correct key file for one validator into the directory."""
    key_file = keys_directory / f"{validator_index}.json"
    key_file.write_text(
        json.dumps(
            {
                "attestation_keypair": {
                    "public_key": attestation_public_key_hex,
                    "secret_key": "00",
                },
                "proposal_keypair": {
                    "public_key": proposal_public_key_hex,
                    "secret_key": "00",
                },
            }
        )
    )


class TestComputeKeySetDigest:
    """Tests for compute_key_set_digest."""

    def test_digest_matches_pinned_known_vector(self, tmp_path: Path) -> None:
        """Pin the digest construction for a two-validator set against a fixed vector."""
        # Validator 0 carries attestation public key "aa" and proposal public key "bb".
        write_key_file(tmp_path, 0, "aa", "bb")
        # Validator 1 carries attestation public key "cc" and proposal public key "dd".
        write_key_file(tmp_path, 1, "cc", "dd")

        # This literal guards the cross-fill identity of the key set.
        # It breaks if the field order, the stem.encode() index encoding,
        # or the public-key concatenation in the digest construction changes.
        assert compute_key_set_digest(tmp_path) == (
            "0xa3598935e1ece51623960444910050de5fc198c60429709ce028c22aa858d491"
        )

    def test_digest_sorts_by_numeric_stem_not_lexicographically(self, tmp_path: Path) -> None:
        """Prove the digest orders files by int(stem), so index 2 precedes index 10."""
        # Distinct public keys per index make the ordering observable in the digest.
        write_key_file(tmp_path, 2, "22", "2a")
        write_key_file(tmp_path, 10, "10", "1a")

        # The pinned literal is the digest for the numeric order 2 then 10.
        # A lexicographic regression would place "10" before "2" and yield
        # 0x4d211ad267596dac8f53a76a08935bd639a97f90c47b793a575226498ed62a8f instead.
        assert compute_key_set_digest(tmp_path) == (
            "0xd2b87780bf0b12efbd5b00899715598091a2cb1f21aadc0aa5adf2584d5813c0"
        )
