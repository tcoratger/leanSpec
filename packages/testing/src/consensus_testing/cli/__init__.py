"""CLI tools for Ethereum test fixture generation."""

from pathlib import Path


def find_workspace_root() -> Path:
    """Walk up from the current directory to the one whose pyproject declares the uv workspace."""
    candidate = Path.cwd()
    while candidate != candidate.parent:
        pyproject = candidate / "pyproject.toml"
        if pyproject.exists() and "[tool.uv.workspace]" in pyproject.read_text():
            return candidate
        candidate = candidate.parent
    return Path.cwd()
