---
name: fill
description: Generate consensus layer test fixtures
---

# /fill - Generate Test Fixtures

Run the test filler to generate consensus layer test fixtures.

## Default Usage

```bash
uv run fill --fork=Devnet --clean -n auto
```

## Options

- `--fork=<name>` - Target fork (default: Devnet)
- `--clean` - Clean existing fixtures before generating
- `-n auto` - Auto-detect parallelization
- `--layer=<layer>` - Target layer (consensus is default, execution for future)

## Examples

- `/fill` - Run with defaults
- `/fill --fork=Electra` - Generate for Electra fork
- `/fill path/to/test.py` - Generate fixtures for specific test file
