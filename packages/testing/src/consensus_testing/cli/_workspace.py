"""Locate the uv workspace root for the CLI commands."""

from pathlib import Path


def find_workspace_root() -> Path:
    """
    Walk upward to the first ancestor whose pyproject.toml declares the uv workspace.

    Pytest is invoked with this directory as its rootdir.
    Falls back to the filesystem root when no ancestor declares the workspace table.
    """
    root = Path.cwd()
    while root != root.parent:
        candidate = root / "pyproject.toml"
        if candidate.exists() and "[tool.uv.workspace]" in candidate.read_text():
            return root
        root = root.parent
    return root
