---
name: test
description: Run unit tests with coverage
---

# /test - Run Unit Tests

Run pytest with coverage reporting.

## Default

```bash
uv run pytest
```

## Options

- `/test -v` - Verbose output
- `/test -k <pattern>` - Run matching tests
- `/test <path>` - Run specific test file/directory
- `/test --cov` - With coverage report

## Examples

- `/test` - Run all unit tests
- `/test tests/lean_spec/subspecs/ssz/` - Run SSZ tests only
- `/test -k "test_serialize"` - Run tests matching pattern
