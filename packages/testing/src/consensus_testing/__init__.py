"""Test tools for generating and consuming leanSpec consensus test vectors."""

from typing import Type

from . import forks
from .genesis import build_anchor, generate_pre_state
from .test_fixtures import (
    ApiEndpointTest,
    BaseConsensusFixture,
    DiscoveryCryptoTest,
    ForkChoiceTest,
    GossipsubHandlerTest,
    JustifiabilityTest,
    NetworkingCodecTest,
    SlotClockTest,
    SSZTest,
    StateTransitionTest,
    VerifySignaturesTest,
    XmssChainTest,
)
from .test_types import (
    AggregatedAttestationCheck,
    AggregatedAttestationSpec,
    AttestationCheck,
    AttestationStep,
    BaseForkChoiceStep,
    BlockSpec,
    BlockStep,
    ForkChoiceStep,
    GossipAggregatedAttestationSpec,
    GossipAggregatedAttestationStep,
    GossipAttestationSpec,
    StateExpectation,
    StoreChecks,
    TickStep,
)

StateTransitionTestFiller = Type[StateTransitionTest]
ForkChoiceTestFiller = Type[ForkChoiceTest]
VerifySignaturesTestFiller = Type[VerifySignaturesTest]
SSZTestFiller = Type[SSZTest]
NetworkingCodecTestFiller = Type[NetworkingCodecTest]
GossipsubHandlerTestFiller = Type[GossipsubHandlerTest]
ApiEndpointTestFiller = Type[ApiEndpointTest]
SlotClockTestFiller = Type[SlotClockTest]
DiscoveryCryptoTestFiller = Type[DiscoveryCryptoTest]
JustifiabilityTestFiller = Type[JustifiabilityTest]
XmssChainTestFiller = Type[XmssChainTest]

__all__ = [
    # Public API
    "AggregatedAttestationSpec",
    "GossipAggregatedAttestationSpec",
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
    "VerifySignaturesTest",
    "SSZTest",
    "NetworkingCodecTest",
    "GossipsubHandlerTest",
    "ApiEndpointTest",
    "SlotClockTest",
    "DiscoveryCryptoTest",
    "JustifiabilityTest",
    "XmssChainTest",
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
    "VerifySignaturesTestFiller",
    "SSZTestFiller",
    "NetworkingCodecTestFiller",
    "GossipsubHandlerTestFiller",
    "ApiEndpointTestFiller",
    "SlotClockTestFiller",
    "DiscoveryCryptoTestFiller",
    "JustifiabilityTestFiller",
    "XmssChainTestFiller",
]
