"""Consensus test fixture format definitions (Pydantic models)."""

from consensus_testing.test_fixtures.api_endpoint import ApiEndpointFixture, ApiEndpointTest
from consensus_testing.test_fixtures.base import (
    BaseConsensusFixture,
    BaseTestSpec,
    ExpectedRejection,
    FixtureInfo,
)
from consensus_testing.test_fixtures.fork_choice import ForkChoiceFixture, ForkChoiceTest
from consensus_testing.test_fixtures.gossipsub_handler import (
    GossipsubHandlerFixture,
    GossipsubHandlerTest,
)
from consensus_testing.test_fixtures.justifiability import (
    JustifiabilityFixture,
    JustifiabilityTest,
)
from consensus_testing.test_fixtures.networking_codec import (
    NetworkingCodecFixture,
    NetworkingCodecTest,
)
from consensus_testing.test_fixtures.poseidon_permutation import (
    PoseidonPermutationFixture,
    PoseidonPermutationTest,
)
from consensus_testing.test_fixtures.slot_clock import SlotClockFixture, SlotClockTest
from consensus_testing.test_fixtures.ssz import SSZFixture, SSZTest
from consensus_testing.test_fixtures.state_transition import (
    StateTransitionFixture,
    StateTransitionTest,
)
from consensus_testing.test_fixtures.sync import SyncFixture, SyncTest
from consensus_testing.test_fixtures.verify_proofs import (
    DropMessageBinding,
    IncrementEmittedSlot,
    RebindToAlternateHeadRoot,
    SwapMessageBindings,
    SwapParticipantPublicKey,
    VerifyMultiMessageProofsFixture,
    VerifyMultiMessageProofsTest,
    VerifySingleMessageProofsFixture,
    VerifySingleMessageProofsTest,
)
from consensus_testing.test_fixtures.verify_signatures import (
    AppendPhantomAttestation,
    ClearFirstAttestationBits,
    CorruptProof,
    MutateStateRoot,
    SetProposerIndex,
    SwapFirstTwoAttestations,
    VerifySignaturesFixture,
    VerifySignaturesTest,
)

FIXTURE_FORMATS: tuple[type[BaseTestSpec], ...] = (
    ApiEndpointTest,
    ForkChoiceTest,
    GossipsubHandlerTest,
    JustifiabilityTest,
    NetworkingCodecTest,
    PoseidonPermutationTest,
    SlotClockTest,
    SSZTest,
    StateTransitionTest,
    SyncTest,
    VerifyMultiMessageProofsTest,
    VerifySignaturesTest,
    VerifySingleMessageProofsTest,
)
"""
Canonical registry of every consensus fixture format.

The pytest plugin registers one filler fixture per entry.
A new format becomes fillable by adding its class here.
"""

__all__ = [
    "FIXTURE_FORMATS",
    "BaseConsensusFixture",
    "BaseTestSpec",
    "ExpectedRejection",
    "FixtureInfo",
    "StateTransitionFixture",
    "StateTransitionTest",
    "ForkChoiceFixture",
    "ForkChoiceTest",
    "VerifySingleMessageProofsFixture",
    "VerifySingleMessageProofsTest",
    "VerifyMultiMessageProofsFixture",
    "VerifyMultiMessageProofsTest",
    "RebindToAlternateHeadRoot",
    "IncrementEmittedSlot",
    "SwapParticipantPublicKey",
    "SwapMessageBindings",
    "DropMessageBinding",
    "VerifySignaturesFixture",
    "VerifySignaturesTest",
    "SetProposerIndex",
    "ClearFirstAttestationBits",
    "CorruptProof",
    "AppendPhantomAttestation",
    "MutateStateRoot",
    "SwapFirstTwoAttestations",
    "SSZFixture",
    "SSZTest",
    "NetworkingCodecFixture",
    "NetworkingCodecTest",
    "GossipsubHandlerFixture",
    "GossipsubHandlerTest",
    "ApiEndpointFixture",
    "ApiEndpointTest",
    "SlotClockFixture",
    "SlotClockTest",
    "JustifiabilityFixture",
    "JustifiabilityTest",
    "PoseidonPermutationFixture",
    "PoseidonPermutationTest",
    "SyncFixture",
    "SyncTest",
]
