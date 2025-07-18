### What was wrong?

Related to Issue #

### How was it fixed?

## 🗒️ Description
<!-- Brief description of the changes introduced by this PR -->
<!-- Don't submit this PR if it could expose a mainnet bug, see SECURITY.md in the repo root for details -->

## 🔗 Related Issues or PRs
<!-- Reference any related issues using the GitHub issue number (e.g., Fixes #123). Default is N/A. -->
N/A.

## ✅ Checklist
<!-- Please check off all required items. For those that don't apply remove them accordingly. -->

- [ ] All: Ran fast `tox` checks to avoid unnecessary CI fails:
    ```console
    uvx --with=tox-uv tox -e check,pytest
    ```
- [ ] Considered adding appropriate tests for the changes.
- [ ] Considered adding an entry to [CHANGELOG.md](/ethereum/execution-spec-tests/blob/main/docs/CHANGELOG.md).
- [ ] Considered updating the online docs in the [./docs/](/ethereum/execution-spec-tests/blob/main/docs/) directory.
- [ ] Tests: Ran `mkdocs serve` locally and verified the auto-generated docs for new tests in the [Test Case Reference](https://eest.ethereum.org/main/tests/) are correctly formatted.
