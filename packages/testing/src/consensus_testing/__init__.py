"""Test tools for generating and consuming leanSpec consensus test vectors."""

from collections.abc import Callable

from consensus_testing import forks
from consensus_testing.genesis import build_anchor, generate_pre_state
from consensus_testing.test_fixtures import (
    FIXTURE_FORMATS,
    ApiEndpointFixture,
    ApiEndpointTest,
    AppendPhantomAttestation,
    BaseConsensusFixture,
    BaseTestSpec,
    ClearFirstAttestationBits,
    CorruptProof,
    DropMessageBinding,
    ExpectedRejection,
    FixtureInfo,
    ForkChoiceFixture,
    ForkChoiceTest,
    GossipsubHandlerFixture,
    GossipsubHandlerTest,
    IncrementEmittedSlot,
    JustifiabilityFixture,
    JustifiabilityTest,
    MutateStateRoot,
    NetworkingCodecFixture,
    NetworkingCodecTest,
    PoseidonPermutationFixture,
    PoseidonPermutationTest,
    RebindToAlternateHeadRoot,
    SetProposerIndex,
    SlotClockFixture,
    SlotClockTest,
    SSZFixture,
    SSZTest,
    StateTransitionFixture,
    StateTransitionTest,
    SwapFirstTwoAttestations,
    SwapMessageBindings,
    SwapParticipantPublicKey,
    SyncFixture,
    SyncTest,
    VerifyMultiMessageProofsFixture,
    VerifyMultiMessageProofsTest,
    VerifySignaturesFixture,
    VerifySignaturesTest,
    VerifySingleMessageProofsFixture,
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
    StoreSnapshot,
    TickStep,
)

StateTransitionTestFiller = Callable[..., StateTransitionFixture]
ForkChoiceTestFiller = Callable[..., ForkChoiceFixture]
VerifySingleMessageProofsTestFiller = Callable[..., VerifySingleMessageProofsFixture]
VerifyMultiMessageProofsTestFiller = Callable[..., VerifyMultiMessageProofsFixture]
VerifySignaturesTestFiller = Callable[..., VerifySignaturesFixture]
SSZTestFiller = Callable[..., SSZFixture]
NetworkingCodecTestFiller = Callable[..., NetworkingCodecFixture]
GossipsubHandlerTestFiller = Callable[..., GossipsubHandlerFixture]
ApiEndpointTestFiller = Callable[..., ApiEndpointFixture]
SlotClockTestFiller = Callable[..., SlotClockFixture]
JustifiabilityTestFiller = Callable[..., JustifiabilityFixture]
PoseidonPermutationTestFiller = Callable[..., PoseidonPermutationFixture]
SyncTestFiller = Callable[..., SyncFixture]

__all__ = [
    # Public API
    "AggregatedAttestationSpec",
    "GossipAttestationSpec",
    "BlockSpec",
    "forks",
    "build_anchor",
    "generate_pre_state",
    # Base types
    "FIXTURE_FORMATS",
    "BaseConsensusFixture",
    "BaseTestSpec",
    "ExpectedRejection",
    "FixtureInfo",
    # Spec and fixture classes
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
    # Test types
    "BaseForkChoiceStep",
    "TickStep",
    "BlockStep",
    "AttestationStep",
    "GossipAggregatedAttestationStep",
    "ForkChoiceStep",
    "StateExpectation",
    "StoreChecks",
    "StoreSnapshot",
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
