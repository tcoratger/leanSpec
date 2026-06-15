"""Tests for the consensus_testing package entry point."""

from __future__ import annotations

import typing

import consensus_testing


class TestPackageExports:
    """Tests for the public surface exported by the framework package."""

    def test_documented_public_symbols_are_importable(self) -> None:
        """Every name listed in the package's public export list resolves to an attribute."""
        missing_exports = [
            name for name in consensus_testing.__all__ if not hasattr(consensus_testing, name)
        ]
        assert missing_exports == []

    def test_filler_aliases_return_their_matching_fixture_type(self) -> None:
        """Each headline filler alias is a callable returning its paired fixture class."""
        _, state_transition_return_type = typing.get_args(
            consensus_testing.StateTransitionTestFiller
        )
        _, fork_choice_return_type = typing.get_args(consensus_testing.ForkChoiceTestFiller)
        assert state_transition_return_type is consensus_testing.StateTransitionFixture
        assert fork_choice_return_type is consensus_testing.ForkChoiceFixture

    def test_genesis_builders_are_exposed_as_callables(self) -> None:
        """The genesis builders documented for unit tests are present and callable."""
        assert callable(consensus_testing.make_genesis_state)
        assert callable(consensus_testing.make_genesis_store)
