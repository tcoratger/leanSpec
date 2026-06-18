"""CLI command for generating Lean Ethereum consensus test fixtures."""

import os
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

import click

from consensus_testing.cli import find_workspace_root
from consensus_testing.keys import compute_key_set_digest, get_keys_directory
from consensus_testing.keys_cli import PINNED_KEY_SET_DIGESTS, download_keys


@click.command(
    context_settings={
        "ignore_unknown_options": True,
        "allow_extra_args": True,
    },
    epilog="""\
\b
Examples:
    # Generate consensus fixtures
    fill tests/consensus/devnet --fork=Lstar --clean -v
\b
    # Use specific XMSS scheme (overrides LEAN_ENV env var)
    fill --fork=Lstar --scheme=prod --clean -v
""",
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
@click.option(
    "--check-determinism/--no-check-determinism",
    default=True,
    help="After filling, regenerate the full fixture tree under two hash "
    "seeds and fail if the emitted bytes differ (default: on)",
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
    check_determinism: bool,
) -> None:
    """Generate consensus test fixtures from test specifications."""
    # The spec config reads this flag once at import time.
    # Only the pytest subprocess below starts fresh and sees this export.
    os.environ["LEAN_ENV"] = scheme.lower()

    # Crypto mode is independent of scheme: both schemes mock unless asked to run the prover.
    crypto_mode = crypto.lower()

    keys_directory = get_keys_directory(scheme.lower())

    # Download the keys if they are missing.
    if not (keys_directory.exists() and any(keys_directory.glob("*.json"))):
        click.echo(f"Test keys for '{scheme}' scheme not found. Downloading...")
        download_keys(scheme.lower())
    # Stale or modified local keys would silently change every vector.
    elif compute_key_set_digest(keys_directory) != PINNED_KEY_SET_DIGESTS[scheme.lower()]:
        click.echo(f"Local '{scheme}' keys do not match the pinned key set. Re-downloading...")
        download_keys(scheme.lower())

    config_path = Path(__file__).parent / "pytest_ini_files" / "pytest-fill.ini"
    # The project root is the workspace pyproject.toml.
    project_root = find_workspace_root()

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

    args.extend(pytest_args)
    args.extend(ctx.args)

    # A subprocess gives a fresh interpreter that imports the spec config anew.
    # Only then does the scheme exported above take effect.
    exit_code = subprocess.run([sys.executable, "-m", "pytest", *args]).returncode
    if exit_code != 0:
        sys.exit(exit_code)

    if check_determinism:
        verify_fixture_determinism(config_path, project_root, fork)

    sys.exit(0)


def verify_fixture_determinism(config_path: Path, project_root: Path, fork: str) -> None:
    """
    Regenerate the full fixture tree under two hash seeds and diff them.

    Byte-identical output under two seeds proves every vector is order-free.
    The mocked prover is forced, since the real prover emits randomized proofs by design.
    """
    consensus_tests = project_root / "tests" / "consensus"
    emitted_under_seed: list[Path] = []

    with tempfile.TemporaryDirectory() as scratch_root:
        for hash_seed in ("1", "2"):
            output_directory = Path(scratch_root) / f"seed-{hash_seed}"
            child_args = [
                "-c",
                str(config_path),
                f"--rootdir={project_root}",
                f"--output={output_directory}",
                f"--fork={fork}",
                "--crypto=mocked",
                "--clean",
                str(consensus_tests),
                "-n",
                "0",
                "-q",
            ]
            child_environment = {**os.environ, "PYTHONHASHSEED": hash_seed}
            child_exit_code = subprocess.run(
                [sys.executable, "-m", "pytest", *child_args],
                env=child_environment,
            ).returncode

            # Exit code 5 means no test was collected, so there is nothing to check.
            if child_exit_code == 5:
                click.echo("Determinism check skipped: no vectors selected.")
                return
            if child_exit_code != 0:
                click.echo(
                    "Determinism check could not regenerate the fixture tree.",
                    err=True,
                )
                sys.exit(child_exit_code)
            emitted_under_seed.append(output_directory)

        differing_fixtures = diff_fixture_trees(emitted_under_seed[0], emitted_under_seed[1])
        if differing_fixtures:
            click.echo(
                "Determinism check FAILED: vectors differ across hash seeds.",
                err=True,
            )
            for relative_path in differing_fixtures:
                click.echo(f"  differs: {relative_path}", err=True)
            sys.exit(1)

    click.echo("Determinism check passed: all vectors are byte-identical across hash seeds.")


def diff_fixture_trees(first_tree: Path, second_tree: Path) -> list[str]:
    """Return the relative paths of fixtures whose bytes differ between two trees."""
    first_files = {
        path.relative_to(first_tree): path for path in first_tree.rglob("*") if path.is_file()
    }
    second_files = {
        path.relative_to(second_tree): path for path in second_tree.rglob("*") if path.is_file()
    }
    return sorted(
        str(relative_path)
        for relative_path in first_files.keys() | second_files.keys()
        if relative_path not in first_files
        or relative_path not in second_files
        or first_files[relative_path].read_bytes() != second_files[relative_path].read_bytes()
    )


if __name__ == "__main__":
    fill()
