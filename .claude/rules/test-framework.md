---
paths:
  - "tests/**/*.py"
  - "packages/testing/**/*.py"
---

# Test Framework Structure

**Two types of tests:**

1. **Unit tests** (`tests/lean_spec/`) - Standard pytest tests for implementation
2. **Spec tests** (`tests/consensus/`) - Generate JSON test vectors via fillers

**Test Filling Framework:**

- Pytest plugin in `packages/testing/src/framework/pytest_plugins/filler.py`
- Consensus fixture package: `consensus_testing`
- Write consensus spec tests using `state_transition_test` or `fork_choice_test` fixtures
- These fixtures are type aliases that create test vectors when called
- Run `uv run fill --fork=Lstar --clean -n auto` to generate consensus fixtures
- Output goes to `fixtures/consensus/{format}/{test_path}/...`

**Example spec test:**

```python
def test_block(state_transition_test: StateTransitionTestFiller) -> None:
    state_transition_test(
        pre=genesis_state,
        blocks=[block],
        post=StateExpectation(slot=Slot(1))  # Only check what matters
    )
```

**How it works:**

1. Test function receives a fixture class (not instance) as parameter
2. Calling it creates a `FixtureWrapper` that runs `make_fixture()`
3. `make_fixture()` executes the spec code (state transitions, fork choice steps)
4. Validates output against expectations (`StateExpectation`, `StoreChecks`)
5. Serializes to JSON via Pydantic's `model_dump(mode="json")`
6. Writes fixtures at session end to `fixtures/consensus/{format}/{test_path}/...`

**Package architecture:**

- `framework/` - Pytest plugin, CLI entry points, fork registry infrastructure
- `consensus_testing/` - Consensus fixtures, forks, builders
- Regular pytest runs (`uv run pytest`) ignore spec tests - they only run via `fill` command

**Serialization requirements:**

- All spec types (State, Block, Uint64, etc.) must be Pydantic models
- Custom types need `@field_serializer` or `model_serializer` for JSON output
- SSZ types typically serialize to hex strings (e.g., `"0x1234..."`)
- Fixture models inherit from `BaseConsensusFixture` (in
  `consensus_testing/test_fixtures/base.py`), which uses `CamelModel` for
  camelCase JSON output
- Test the serialization: `fixture.model_dump(mode="json")` must produce valid JSON

**Key fixture types:**

- `StateTransitionTest` - Tests state transitions with blocks
- `ForkChoiceTest` - Tests fork choice with steps (tick/block/attestation)
- Selective validation via `StateExpectation` and `StoreChecks` (only validates fields you specify)
