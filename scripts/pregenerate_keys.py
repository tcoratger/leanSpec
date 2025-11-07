"""Generate pre-computed XMSS keys for test validators.

This script dramatically reduces test execution time by pre-generating expensive
XMSS keys that can be loaded instantly from a JSON file.

Performance Impact:
    - Without pre-generated keys: ~13 minutes for full test suite
    - With pre-generated keys: ~5 minutes for full test suite
    - Key generation: ~2 seconds per validator
    - Key loading: <100ms for 100 validators

Usage:
    uv run python scripts/pregenerate_keys.py

The generated keys will be saved to fixtures/pregenerated_xmss_keys.json
and automatically loaded by XmssKeyManager during test execution.
"""

import base64
import json
from pathlib import Path

from lean_spec.subspecs.xmss.interface import DEFAULT_SIGNATURE_SCHEME


def generate_keys(num_validators: int = 100, max_slot: int = 100) -> None:
    """
    Generate and save XMSS keys for test validators.

    Parameters
    ----------
    num_validators : int, optional
        Number of validator keys to generate. Defaults to 100.
    max_slot : int, optional
        Maximum slot number for which keys remain valid. Defaults to 100.

    Notes:
    -----
    - Keys are deterministic (seed=0) for reproducible testing
    - Each key generation takes ~2 seconds
    - Public keys are base64-encoded for compact JSON representation
    - Secret keys use Pydantic's model_dump() for nested structure preservation
    """
    print(f"Generating {num_validators} XMSS validator keys (max_slot={max_slot})...")
    print("This will take approximately 2-3 minutes. Please wait...\n")

    keys_data = {}
    num_active_epochs = max_slot + 1

    for i in range(num_validators):
        # Show progress every 10 validators
        if i % 10 == 0:
            print(f"  Generating validator {i}/{num_validators}...")

        # Generate key pair with deterministic seed
        pk, sk = DEFAULT_SIGNATURE_SCHEME.key_gen(0, num_active_epochs)

        # Serialize to JSON-compatible format
        keys_data[str(i)] = {
            "public": base64.b64encode(pk.to_bytes(DEFAULT_SIGNATURE_SCHEME.config)).decode(
                "utf-8"
            ),
            "secret": sk.model_dump(),
        }

    # Ensure fixtures directory exists
    fixtures_dir = Path("fixtures")
    fixtures_dir.mkdir(exist_ok=True)

    # Write keys to JSON file
    output_path = fixtures_dir / "pregenerated_xmss_keys.json"
    with open(output_path, "w") as f:
        json.dump(keys_data, f, indent=2)

    print(f"\n✓ Successfully generated {num_validators} keys")
    print(f"✓ Saved to: {output_path}")
    print(f"✓ File size: {output_path.stat().st_size / 1024 / 1024:.2f} MB")
    print("\nKeys will be automatically loaded during test execution.")


if __name__ == "__main__":
    generate_keys()
