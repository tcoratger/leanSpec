"""CLI command for generating Lean Ethereum consensus test fixtures."""

import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import click

from consensus_testing.keys import compute_key_set_digest, get_keys_directory
from consensus_testing.keys_cli import PINNED_KEY_SET_DIGESTS, download_keys


@click.command(
    context_settings={
        "ignore_unknown_options": True,
        "allow_extra_args": True,
    }
)
@click.argument("pytest_args", nargs=-1, type=click.UNPROCESSED)
@click.option(
    "--output",
    "-o",
    default="fixtures",
    help="Output directory for generated fixtures",
)
@click.option(
    "--fork",
    required=True,
    help="Fork to generate fixtures for (e.g., Lstar)",
)
@click.option(
    "--clean",
    is_flag=True,
    help="Clean output directory before generating",
)
@click.option(
    "--scheme",
    type=click.Choice(["test", "prod"], case_sensitive=False),
    default="test",
    help="XMSS signature scheme (default: test)",
)
@click.option(
    "--crypto",
    type=click.Choice(["mocked", "real"], case_sensitive=False),
    default="mocked",
    help="Aggregation prover mode (default: mocked; pass real for the authoritative set)",
)
@click.pass_context
def fill(
    ctx: click.Context,
    pytest_args: Sequence[str],
    output: str,
    fork: str,
    clean: bool,
    scheme: str,
    crypto: str,
) -> None:
    """
    Generate consensus test fixtures from test specifications.

    Examples:
        # Generate consensus fixtures
        fill tests/consensus/devnet --fork=Lstar --clean -v

        # Use specific XMSS scheme (overrides LEAN_ENV env var)
        fill --fork=Lstar --scheme=prod --clean -v
    """
    # Why: the spec config reads this flag once, at import time.
    # The current process froze the old value when the package imported.
    # Only the pytest subprocess below starts fresh and sees this export.
    os.environ["LEAN_ENV"] = scheme.lower()

    # Crypto mode is independent of the scheme.
    # Both schemes mock by default and run the prover only when asked.
    crypto_mode = crypto.lower()

    # Check and download keys if needed
    keys_directory = get_keys_directory(scheme.lower())

    # Check if keys already exist, if not, download them
    if not (keys_directory.exists() and any(keys_directory.glob("*.json"))):
        click.echo(f"Test keys for '{scheme}' scheme not found. Downloading...")
        download_keys(scheme.lower())
    # Why: stale or modified local keys would silently change every vector.
    elif compute_key_set_digest(keys_directory) != PINNED_KEY_SET_DIGESTS[scheme.lower()]:
        click.echo(f"Local '{scheme}' keys do not match the pinned key set. Re-downloading...")
        download_keys(scheme.lower())

    config_path = Path(__file__).parent / "pytest_ini_files" / "pytest-fill.ini"
    # Find project root by looking for pyproject.toml with [tool.uv.workspace]
    project_root = Path.cwd()
    while project_root != project_root.parent:
        if (project_root / "pyproject.toml").exists():
            # Check if this is the workspace root
            pyproject = project_root / "pyproject.toml"
            if "[tool.uv.workspace]" in pyproject.read_text():
                break
        project_root = project_root.parent

    # Build pytest arguments
    args = [
        "-c",
        str(config_path),
        f"--rootdir={project_root}",
        f"--output={output}",
        f"--fork={fork}",
        f"--crypto={crypto_mode}",
    ]

    if clean:
        args.append("--clean")

    # Add all pytest args
    args.extend(pytest_args)

    # Add extra click context args
    args.extend(ctx.args)

    # Why a subprocess: a fresh interpreter imports the spec config anew.
    # Only then does the scheme exported above take effect.
    exit_code = subprocess.run([sys.executable, "-m", "pytest", *args]).returncode
    sys.exit(exit_code)


if __name__ == "__main__":
    fill()
