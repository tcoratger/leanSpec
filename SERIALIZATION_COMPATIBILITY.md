# XMSS Serialization Compatibility with Rust Reference

## Issue

GitHub Issue: https://github.com/ethereum/leanSpec/issues/172

The Python XMSS implementation must use the same serialization strategy as the Rust reference implementation to ensure interoperability and correctness.

## Current Status

### Rust Implementation

The Rust reference implementation (`leanSig`) uses serde's derive macros with bincode serialization:

```rust
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct GeneralizedXMSSSignature<IE: IncomparableEncoding, TH: TweakableHash> {
    path: HashTreeOpening<TH>,
    rho: IE::Randomness,
    hashes: Vec<TH::Domain>,
}
```

Bincode is a binary serialization format that:
1. Serializes structs field-by-field in declaration order
2. Adds length prefixes for variable-length collections (Vec, String, etc.)
3. Uses little-endian encoding for integers
4. Recursively serializes nested structures

### Python Implementation

The Python implementation currently uses manual field-by-field concatenation:

```python
def __bytes__(self) -> bytes:
    return (
        _serialize_digests(self.path.siblings)
        + Fp.serialize_list(self.rho)
        + _serialize_digests(self.hashes)
    )
```

This approach does NOT match bincode's format because:
- No length prefixes for variable-length fields
- No handling of bincode's metadata
- Different field names (siblings vs co_path)

## Test Data Generated

A Rust test was added to `/Users/tcoratger/Documents/ethereum/leanSig/src/signature/generalized_xmss.rs`:

```rust
#[test]
pub fn test_print_serialized_signature_for_python() {
    // ... test code that generates and prints serialized signature ...
}
```

Run with: `cd /Users/tcoratger/Documents/ethereum/leanSig && cargo test --lib test_print_serialized_signature_for_python -- --nocapture`

### Test Parameters

- Fixed RNG seed: 42
- Epoch: 2
- Message: `0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`
- Config (from Rust test_target_sum_poseidon):
  - LOG_LIFETIME: 6
  - BASE: 2
  - DIMENSION: 7 (note: actual output shows 163 hashes - parameter mismatch needs investigation)

### Generated Data

Public Key (60 bytes):
```
fc9a62904ffc69640f16fc98608b7dfc0a964c7afcce1e6a12fc65eca065fc4a737b7efc51921311fcb13b6643fcbea8d61ffc09057845fc689a286f
```

Signature (5942 bytes): See `test_rust_serialization_compat.py`

## Python Test Suite

Created: `tests/lean_spec/subspecs/xmss/test_rust_serialization_compat.py`

This file contains:
1. **Test data**: Hex-encoded bytes from Rust
2. **Skipped tests**: Placeholder tests that document what needs to work
3. **Documentation**: Detailed explanation of the compatibility requirements

Run with: `uv run pytest tests/lean_spec/subspecs/xmss/test_rust_serialization_compat.py -v`

## Next Steps

### 1. Understand Bincode Format

Study how bincode serializes the Rust structs:
- How are Vec lengths encoded? (likely as u64 little-endian)
- How are nested structs handled?
- What is the exact byte layout?

### 2. Implement Python Bincode Serialization

Create helper functions or a bincode-compatible serializer:

```python
def serialize_vec(items: list, item_serializer) -> bytes:
    """Serialize a vector with bincode-compatible length prefix."""
    length = len(items)
    # Bincode uses variable-length encoding for lengths
    length_bytes = length.to_bytes(8, 'little')  # u64 little-endian
    item_bytes = b''.join(item_serializer(item) for item in items)
    return length_bytes + item_bytes
```

### 3. Update Signature Serialization

Modify `Signature.__bytes__()` and `Signature.from_bytes()` in `containers.py`:

```python
def __bytes__(self) -> bytes:
    """Serialize using bincode-compatible format."""
    # Serialize path (HashTreeOpening)
    path_bytes = serialize_vec(
        self.path.siblings,
        lambda digest: Fp.serialize_list(digest)
    )

    # Serialize rho (fixed-size, no length prefix needed)
    rho_bytes = Fp.serialize_list(self.rho)

    # Serialize hashes (Vec<TH::Domain>)
    hashes_bytes = serialize_vec(
        self.hashes,
        lambda digest: Fp.serialize_list(digest)
    )

    return path_bytes + rho_bytes + hashes_bytes
```

### 4. Update PublicKey Serialization

Similar changes for `PublicKey.__bytes__()` and `PublicKey.from_bytes()`.

### 5. Handle Configuration Mismatches

The Rust test config doesn't match Python's TEST_CONFIG:
- Rust: DIMENSION=163 (from actual hash count), LOG_LIFETIME=6
- Python TEST_CONFIG: DIMENSION=4, LOG_LIFETIME=8

Either:
- Create a new Python config matching Rust's test config, OR
- Generate new Rust test data matching Python's TEST_CONFIG

### 6. Test and Validate

1. Un-skip tests in `test_rust_serialization_compat.py`
2. Run: `uv run pytest tests/lean_spec/subspecs/xmss/test_rust_serialization_compat.py -v`
3. Verify all tests pass
4. Add round-trip tests: Python → Rust → Python

## Resources

- [Bincode specification](https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md)
- [Serde documentation](https://serde.rs/)
- Rust reference: `/Users/tcoratger/Documents/ethereum/leanSig`
- Python implementation: `/Users/tcoratger/Documents/ethereum/leanSpec`

## Notes

- The field name mismatch (`siblings` in Python vs `co_path` in Rust) doesn't affect serialization since bincode uses field order, not names
- But it affects code clarity - consider renaming Python's `siblings` to `co_path` for consistency
- Bincode's variable-length integer encoding may be more complex than simple u64 - need to verify
- Consider adding a `bincode` Python library dependency, or implement a minimal compatible subset
