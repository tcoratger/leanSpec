"""
CLI for generating or downloading the pre-generated XMSS test keys.

Downloading Pre-generated Keys:

    python -m consensus_testing.keys_cli --download --scheme test    # test scheme
    python -m consensus_testing.keys_cli --download --scheme prod    # prod scheme

Regenerating Keys:

    python -m consensus_testing.keys_cli                   # defaults
    python -m consensus_testing.keys_cli --count 20        # more validators
    python -m consensus_testing.keys_cli --max-slot 200    # longer lifetime
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.request
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from pathlib import Path

from consensus_testing.keys import LEAN_ENV_TO_SCHEMES, get_keys_directory
from lean_spec.spec.crypto.xmss.containers import ValidatorKeyPair
from lean_spec.spec.crypto.xmss.interface import GeneralizedXmssScheme
from lean_spec.spec.forks import Slot
from lean_spec.spec.ssz import Uint64

KEY_DOWNLOAD_URLS = {
    "test": "https://github.com/leanEthereum/leansig-test-keys/releases/download/latest/test_scheme.tar.gz",
    "prod": "https://github.com/leanEthereum/leansig-test-keys/releases/download/latest/prod_scheme.tar.gz",
}
"""
GitHub release URLs for pre-generated key archives.

Keyed by scheme name ("test" or "prod").
Each URL points to a tar.gz containing per-validator JSON files.
"""

NUM_VALIDATORS: int = 8
"""
Default number of validator key pairs.

Eight validators is enough to exercise committee logic and 2/3 supermajority
thresholds while keeping key generation and test execution fast.
"""

CLI_DEFAULT_MAX_SLOT = Slot(100)
"""
Maximum slot when generating keys via CLI (inclusive).

One hundred slots provides ample signing headroom for typical test scenarios.
"""


def _generate_single_keypair(
    scheme: GeneralizedXmssScheme, num_slots: int, index: int
) -> ValidatorKeyPair:
    """
    Generate attestation and proposal key pairs for one validator.

    Defined at module level so it can be pickled for multiprocessing.

    Args:
        scheme: XMSS scheme instance to use for key generation.
        num_slots: Total number of slots the keys must cover.
        index: Validator index (used only for progress logging).

    Returns:
        Complete key pair with both attestation and proposal keys.
    """
    # Generate two independent key pairs: one for attestations, one for proposals.
    #
    # Separate keys allow signing both roles within the same slot
    # without exhausting a one-time leaf.
    start = time.monotonic()
    print(f"[key #{index}] generating attestation key...", flush=True)
    attestation_keypair = scheme.key_gen(Slot(0), Uint64(num_slots))

    elapsed = time.monotonic() - start
    print(
        f"[key #{index}] attestation key done ({elapsed:.0f}s), generating proposal key...",
        flush=True,
    )
    proposal_keypair = scheme.key_gen(Slot(0), Uint64(num_slots))

    elapsed = time.monotonic() - start
    print(f"[key #{index}] done ({elapsed:.0f}s)", file=sys.stderr, flush=True)

    return ValidatorKeyPair(
        attestation_keypair=attestation_keypair, proposal_keypair=proposal_keypair
    )


def _generate_keys(lean_env: str, count: int, max_slot: int) -> None:
    """
    Generate XMSS key pairs in parallel and write each to a separate file.

    Each validator gets its own JSON file to keep individual files small,
    which matters especially for production-scheme keys.

    Args:
        lean_env: Scheme name (e.g. "test" or "prod").
        count: Number of validator key pairs to generate.
        max_slot: Maximum signable slot (key lifetime = max_slot + 1 slots).
    """
    scheme = LEAN_ENV_TO_SCHEMES[lean_env]
    keys_directory = get_keys_directory(lean_env)
    num_slots = max_slot + 1
    num_workers = os.cpu_count() or 1

    print(
        f"Generating {count} XMSS key pairs for {lean_env} environment "
        f"({num_slots} slots) using {num_workers} cores..."
    )

    # Ensure the output directory exists.
    keys_directory.mkdir(parents=True, exist_ok=True)

    # Remove stale key files from previous runs that may have generated
    # a different number of keys.
    for old_file in keys_directory.glob("*.json"):
        old_file.unlink()

    # Generate key pairs in parallel across all CPU cores.
    # Results arrive in index order thanks to executor.map.
    gen_start = time.monotonic()
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        worker_func = partial(_generate_single_keypair, scheme, num_slots)
        for validator_index, key_pair in enumerate(executor.map(worker_func, range(count))):
            elapsed = time.monotonic() - gen_start
            print(
                f"[{validator_index + 1}/{count}] saved key #{validator_index} "
                f"({elapsed:.0f}s elapsed)"
            )

            key_file = keys_directory / f"{validator_index}.json"
            key_file.write_text(key_pair.model_dump_json(indent=2))

    total = time.monotonic() - gen_start
    print(f"Saved {count} key pairs to {keys_directory}/ ({total:.0f}s total)")


def download_keys(scheme: str) -> None:
    """
    Download pre-generated key pairs from a GitHub release.

    Downloads a tar.gz archive for the specified scheme, removes any
    existing keys for that scheme, and extracts the archive in place.

    Args:
        scheme: Scheme name ("test" or "prod").
    """
    base_directory = get_keys_directory(scheme).parent
    url = KEY_DOWNLOAD_URLS[scheme]

    print(f"Downloading {scheme} keys from {url}...")

    # Reserve a temp path; we open it explicitly below so the writer can close
    # before the reader opens.
    temporary_fd, temporary_name = tempfile.mkstemp(suffix=".tar.gz")
    os.close(temporary_fd)
    tmp_path = Path(temporary_name)

    try:
        # Close the writer before opening the reader.
        # Otherwise Python's userspace buffer can withhold the tail of the gzip stream.
        # That produces a near-end decompression failure that looks like a truncated download.
        with urllib.request.urlopen(url) as response, tmp_path.open("wb") as out:
            shutil.copyfileobj(response, out)

        # Remove any existing keys for this scheme before extracting.
        target_directory = base_directory / f"{scheme}_scheme"
        if target_directory.exists():
            shutil.rmtree(target_directory)
        base_directory.mkdir(parents=True, exist_ok=True)

        # Extract the archive into the base directory.
        # The archive root is the scheme directory itself.
        with tarfile.open(tmp_path, "r:gz") as tar:
            tar.extractall(path=base_directory, filter="data")

        print(f"Extracted {scheme} keys to {target_directory}/")
    finally:
        # Always clean up the temporary download file.
        tmp_path.unlink(missing_ok=True)

    print("Download complete!")


def main() -> None:
    """CLI entry point for generating or downloading test keys."""
    parser = argparse.ArgumentParser(
        description="Generate XMSS key pairs for consensus testing",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download pre-generated keys from a GitHub release",
    )
    parser.add_argument(
        "--scheme",
        choices=LEAN_ENV_TO_SCHEMES.keys(),
        default="test",
        help="XMSS scheme to use",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=NUM_VALIDATORS,
        help="Number of validator key pairs",
    )
    parser.add_argument(
        "--max-slot",
        type=int,
        default=int(CLI_DEFAULT_MAX_SLOT),
        help="Maximum slot (key lifetime = max_slot + 1)",
    )
    args = parser.parse_args()

    # Download pre-generated keys instead of generating locally.
    if args.download:
        download_keys(scheme=args.scheme)
        return

    # Generate fresh keys with the specified parameters.
    _generate_keys(lean_env=args.scheme, count=args.count, max_slot=args.max_slot)


if __name__ == "__main__":
    main()
