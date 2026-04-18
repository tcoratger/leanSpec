"""Devnet5 fork specification — SKELETON."""

from ..devnet4.spec import Devnet4Spec


class Devnet5Spec(Devnet4Spec):
    """Devnet5 consensus specification."""

    @classmethod
    def name(cls) -> str:
        """Return the fork name."""
        return "devnet5"

    @classmethod
    def version(cls) -> int:
        """Return the fork version number."""
        return 5

    # Genesis — override if Devnet5State has new fields that need initialization.
    #
    # def generate_genesis(self, genesis_time: Uint64, validators: Validators) -> State:
    #     base = State.generate_genesis(genesis_time, validators)
    #     return Devnet5State(
    #         **base.model_dump(),
    #         new_field=SomeType.zero(),
    #     )

    # State transition — override only what changes.
    #
    # Example: if devnet5 changes attestation processing rules:
    #
    # def process_attestations(
    #     self, state: State, attestations: Iterable[AggregatedAttestation]
    # ) -> State:
    #     # New attestation logic for devnet5
    #     ...

    # State upgrade — migrate devnet4 state to devnet5 format.
    #
    # def upgrade_state(self, state: State) -> State:
    #     return Devnet5State(
    #         **state.model_dump(),
    #         new_field=SomeType.zero(),
    #     )
