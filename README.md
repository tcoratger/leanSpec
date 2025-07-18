# Lean Ethereum Specifications

The Lean Ethereum protocol specifications and cryptographic subspecifications.

## Quick Start

### Prerequisites

- Python 3.12 or later
- [uv](https://github.com/astral-sh/uv) package manager

### Setup

```bash
# Clone this repository
git clone https://github.com/leanEthereum/lean-spec leanSpec
cd leanSpec

# Install dependencies
uv sync --all-extras

# Run tests to verify setup
uv run pytest
```

### Project Structure

```
├── src/
│   ├── lean_spec/             # Main specification modules
│   │   ├── __init__.py
│   │   └── ...
│   └── subspecs/              # Sub-specifications (EIPs)
│       ├── poseidon2/         # Example implementation
│       │   ├── __init__.py
│       │   ├── poseidon2.py
│       │   └── ...
│       ├── ...
│       └── ...
├── tests/                     # Test suite
│   ├── lean_spec/             # Tests for main specs
│   └── subspecs/              # Tests for subspecs
├── docs/                      # Documentation
└── pyproject.toml             # Project configuration
```

### Workspace Commands

```bash
# Install package and required dependencies or re-sync workspace
uv sync

# Install package along with all dependencies, including optional / extras
uv sync --all-extras
```

## Development Workflow

### Running Tests

```bash
# Run all tests from workspace root
uv run pytest

# Run tests in parallel
uv run pytest -n auto
```

### Code Quality

```bash
# Check code style and errors
uv run ruff check src tests

# Auto-fix issues
uv run ruff check --fix src tests

# Format code
uv run ruff format src tests

# Type checking
uv run mypy src tests
```

### Using Tox

```bash
# Run all tox environments
uvx --with=tox-uv tox

# Run specific environment
uvx --with=tox-uv tox -e lint
```

### Documentation

```bash
# Serve docs locally (with auto-reload)
uv run mkdocs serve

# Build docs
uv run mkdocs build
```

## Writing Specifications

### Example: Writing Tests

```python
# tests/test_new_types.py
import pytest
from pydantic import ValidationError
from lean_spec.types import Withdrawal  # Example Pydantic model


TEST_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"


# Parametrized test - test multiple inputs
@pytest.mark.parametrize("amount", [0, 1, 1000, 2**64 - 1])
def test_withdrawal_amount(amount):
    withdrawal = Withdrawal(
            index=0,
            validator_index=1,
            address=TEST_ADDRESS,
            amount=amount,
    )
    assert withdrawal.amount == amount  # Check if amount is set correctly



# Exception testing
def test_withdrawal_amount_above_uint64_max():
    with pytest.raises(ValidationError) as e:
        Withdrawal(
            index=0,
            validator_index=1,
            address=TEST_ADDRESS,
            amount=2**64,  # Exceeds uint64 max
        )
    assert " amount " in str(e.value)
```

## Guide to Python Tools

- **Pydantic models**: Think of these as strongly-typed data structures that validate inputs automatically
- **pytest**: Testing framework - just name test files `test_*.py` and functions `test_*`
- **uv**: Fast Python package manager - like npm/yarn but for Python
- **ruff**: Linter and formatter
- **mypy**: Type checker that works with Pydantic models
- **tox**: Automation tool for running tests across multiple environments
- **mkdocs**: Documentation generator - write docs in Markdown, serve them locally

## Common Commands Reference

| Task                 | Command |
|----------------------|---------|
| Install dependencies | `uv sync --all-extras` |
| Run tests            | `uv run pytest` |
| Format code          | `uv run ruff format src tests` |
| Lint code            | `uv run ruff check src tests` |
| Fix lint errors      | `uv run ruff check --fix src tests` |
| Type check           | `uv run mypy src tests` |
| Run all tox checks   | `uvx --with=tox-uv tox` |
| Build docs           | `uv run mkdocs build` |
| Serve docs           | `uv run mkdocs serve` |


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

MIT License - see LICENSE file for details.
