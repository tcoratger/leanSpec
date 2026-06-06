"""Consensus test fixture format definitions (Pydantic models)."""

from consensus_testing.test_fixtures.api_endpoint import ApiEndpointTest
from consensus_testing.test_fixtures.base import BaseConsensusFixture
from consensus_testing.test_fixtures.fork_choice import ForkChoiceTest
from consensus_testing.test_fixtures.gossipsub_handler import GossipsubHandlerTest
from consensus_testing.test_fixtures.justifiability import JustifiabilityTest
from consensus_testing.test_fixtures.networking_codec import NetworkingCodecTest
from consensus_testing.test_fixtures.poseidon_permutation import PoseidonPermutationTest
from consensus_testing.test_fixtures.slot_clock import SlotClockTest
from consensus_testing.test_fixtures.ssz import SSZTest
from consensus_testing.test_fixtures.state_transition import StateTransitionTest
from consensus_testing.test_fixtures.sync import SyncTest
from consensus_testing.test_fixtures.verify_proofs import (
    DropMessageBinding,
    IncrementEmittedSlot,
    RebindToAlternateHeadRoot,
    SwapMessageBindings,
    SwapParticipantPublicKey,
    VerifyMultiMessageProofsTest,
    VerifySingleMessageProofsTest,
)
from consensus_testing.test_fixtures.verify_signatures import (
    AppendPhantomAttestation,
    ClearFirstAttestationBits,
    CorruptProof,
    MutateStateRoot,
    SetProposerIndex,
    SwapFirstTwoAttestations,
    VerifySignaturesTest,
)

__all__ = [
    "BaseConsensusFixture",
    "StateTransitionTest",
    "ForkChoiceTest",
    "VerifySingleMessageProofsTest",
    "VerifyMultiMessageProofsTest",
    "RebindToAlternateHeadRoot",
    "IncrementEmittedSlot",
    "SwapParticipantPublicKey",
    "SwapMessageBindings",
    "DropMessageBinding",
    "VerifySignaturesTest",
    "SetProposerIndex",
    "ClearFirstAttestationBits",
    "CorruptProof",
    "AppendPhantomAttestation",
    "MutateStateRoot",
    "SwapFirstTwoAttestations",
    "SSZTest",
    "NetworkingCodecTest",
    "GossipsubHandlerTest",
    "ApiEndpointTest",
    "SlotClockTest",
    "JustifiabilityTest",
    "PoseidonPermutationTest",
    "SyncTest",
]
