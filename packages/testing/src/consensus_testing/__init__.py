"""Test tools for generating and consuming leanSpec consensus test vectors."""

from consensus_testing import forks
from consensus_testing.genesis import build_anchor, generate_pre_state
from consensus_testing.test_fixtures import (
    ApiEndpointTest,
    AppendPhantomAttestation,
    BaseConsensusFixture,
    ClearFirstAttestationBits,
    CorruptProof,
    DropMessageBinding,
    ForkChoiceTest,
    GossipsubHandlerTest,
    IncrementEmittedSlot,
    JustifiabilityTest,
    MutateStateRoot,
    NetworkingCodecTest,
    PoseidonPermutationTest,
    RebindToAlternateHeadRoot,
    SetProposerIndex,
    SlotClockTest,
    SSZTest,
    StateTransitionTest,
    SwapFirstTwoAttestations,
    SwapMessageBindings,
    SwapParticipantPublicKey,
    SyncTest,
    VerifyMultiMessageProofsTest,
    VerifySignaturesTest,
    VerifySingleMessageProofsTest,
)
from consensus_testing.test_types import (
    AggregatedAttestationCheck,
    AggregatedAttestationSpec,
    AttestationCheck,
    AttestationStep,
    BaseForkChoiceStep,
    BlockSpec,
    BlockStep,
    ForkChoiceStep,
    GossipAggregatedAttestationStep,
    GossipAttestationSpec,
    StateExpectation,
    StoreChecks,
    TickStep,
)

StateTransitionTestFiller = type[StateTransitionTest]
ForkChoiceTestFiller = type[ForkChoiceTest]
VerifySingleMessageProofsTestFiller = type[VerifySingleMessageProofsTest]
VerifyMultiMessageProofsTestFiller = type[VerifyMultiMessageProofsTest]
VerifySignaturesTestFiller = type[VerifySignaturesTest]
SSZTestFiller = type[SSZTest]
NetworkingCodecTestFiller = type[NetworkingCodecTest]
GossipsubHandlerTestFiller = type[GossipsubHandlerTest]
ApiEndpointTestFiller = type[ApiEndpointTest]
SlotClockTestFiller = type[SlotClockTest]
JustifiabilityTestFiller = type[JustifiabilityTest]
PoseidonPermutationTestFiller = type[PoseidonPermutationTest]
SyncTestFiller = type[SyncTest]

__all__ = [
    # Public API
    "AggregatedAttestationSpec",
    "GossipAttestationSpec",
    "BlockSpec",
    "forks",
    "build_anchor",
    "generate_pre_state",
    # Base types
    # Fixture classes
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
    # Test types
    "BaseForkChoiceStep",
    "TickStep",
    "BlockStep",
    "AttestationStep",
    "GossipAggregatedAttestationStep",
    "ForkChoiceStep",
    "StateExpectation",
    "StoreChecks",
    "AttestationCheck",
    "AggregatedAttestationCheck",
    # Type aliases for test function signatures
    "StateTransitionTestFiller",
    "ForkChoiceTestFiller",
    "VerifySingleMessageProofsTestFiller",
    "VerifyMultiMessageProofsTestFiller",
    "VerifySignaturesTestFiller",
    "SSZTestFiller",
    "NetworkingCodecTestFiller",
    "GossipsubHandlerTestFiller",
    "ApiEndpointTestFiller",
    "SlotClockTestFiller",
    "JustifiabilityTestFiller",
    "PoseidonPermutationTestFiller",
    "SyncTestFiller",
]
