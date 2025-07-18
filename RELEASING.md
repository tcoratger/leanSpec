# Release Process

## Quick Steps

1. **Run all checks**
   ```bash
   uvx --with=tox-uv tox -e check,pytest
   ```

2. **Update version in `pyproject.toml`**
   ```toml
   version = "X.Y.Z"
   ```

3. **Commit and tag**
   ```bash
   git add pyproject.toml
   git commit -m "Release vX.Y.Z"
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   ```

4. **Build**
   ```bash
   rm -rf dist/
   uv run python -m build
   ```

5. **Upload to PyPI**
   ```bash
   uv run twine upload dist/*
   ```

6. **Push**
   ```bash
   git push origin main --tags
   ```

## Version Scheme

We use [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`

- **PATCH**: Bug fixes (0.1.0 → 0.1.1)
- **MINOR**: New features (0.1.1 → 0.2.0)
- **MAJOR**: Breaking changes (0.2.0 → 1.0.0)

## First-time Setup

Configure PyPI credentials:
```bash
# Create ~/.pypirc or use API tokens
uv run twine upload --help
```
