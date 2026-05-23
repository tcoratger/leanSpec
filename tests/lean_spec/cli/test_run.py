"""Tests for the consensus node run sequence."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.cli import NodeBootstrap, parse_args
from lean_spec.cli.run import _build_event_source
from lean_spec.forks import DEFAULT_REGISTRY
from lean_spec.subspecs.chain.config import ATTESTATION_COMMITTEE_COUNT
from lean_spec.subspecs.genesis import GenesisConfig
from lean_spec.subspecs.networking.gossipsub import GossipTopic
from lean_spec.subspecs.validator import ValidatorRegistry
from lean_spec.subspecs.validator.registry import ValidatorEntry
from lean_spec.types import Slot, ValidatorIndex


@pytest.fixture
def genesis_yaml(tmp_path: Path) -> Path:
    """Write a minimal genesis YAML to a temporary path."""
    path = tmp_path / "genesis.yaml"
    path.write_text("GENESIS_TIME: 1000\nGENESIS_VALIDATORS: []\n")
    return path


def _make_event_source_mock() -> MagicMock:
    """Construct a mock event source that records gossip subscriptions."""
    event_source = MagicMock()
    event_source.set_network_name = MagicMock()
    event_source.subscribe_gossip_topic = MagicMock()
    return event_source


async def _run_build(boot: NodeBootstrap) -> tuple[MagicMock, list[str]]:
    """Run the event-source builder against a mocked transport and capture subscriptions."""
    event_source = _make_event_source_mock()
    with patch(
        "lean_spec.cli.run.LiveNetworkEventSource.create",
        new_callable=AsyncMock,
        return_value=event_source,
    ):
        await _build_event_source(boot)
    topics = [call.args[0] for call in event_source.subscribe_gossip_topic.call_args_list]
    return event_source, topics


class TestBuildEventSourceBlockTopic:
    """The block topic is always subscribed, regardless of validator state."""

    async def test_block_topic_subscribed_exactly_once(self, genesis_yaml: Path) -> None:
        """A bare boot configuration subscribes to the fork's block topic exactly once."""
        boot = NodeBootstrap.from_cli_args(parse_args(["--genesis", str(genesis_yaml)]))
        block_topic = GossipTopic.block(boot.fork.GOSSIP_DIGEST).to_topic_id()

        _, topics = await _run_build(boot)

        assert topics == [block_topic]


class TestBuildEventSourcePassive:
    """A passive (non-aggregator, no validators) node subscribes to no subnets."""

    async def test_no_subnet_subscription_for_empty_registry(self, genesis_yaml: Path) -> None:
        """A non-aggregator with no owned validators subscribes only to the block topic."""
        boot = NodeBootstrap.from_cli_args(parse_args(["--genesis", str(genesis_yaml)]))
        block_topic = GossipTopic.block(boot.fork.GOSSIP_DIGEST).to_topic_id()

        _, topics = await _run_build(boot)

        assert topics == [block_topic]


class TestBuildEventSourceOwnedValidator:
    """A node with one owned validator subscribes to its derived subnet."""

    async def test_single_validator_subscribes_to_block_and_subnet(
        self, genesis_yaml: Path
    ) -> None:
        """One owned validator adds exactly one attestation subnet topic."""
        km = XmssKeyManager.shared(max_slot=Slot(10))
        kp = km[ValidatorIndex(0)]
        registry = ValidatorRegistry()
        registry.add(
            ValidatorEntry(
                index=ValidatorIndex(0),
                attestation_secret_key=kp.attestation_keypair.secret_key,
                proposal_secret_key=kp.proposal_keypair.secret_key,
            )
        )

        # Skip the file-loading bootstrap path: it has its own tests.
        # Build the boot configuration directly so this test exercises only the run-time wiring.
        boot = NodeBootstrap(
            genesis=GenesisConfig.model_validate({"GENESIS_TIME": 1000, "GENESIS_VALIDATORS": []}),
            registry=registry,
            fork=DEFAULT_REGISTRY.current,
            bootnode_multiaddrs=(),
            listen_addr=None,
            checkpoint_sync_url=None,
            node_id="lean_spec_0",
            is_aggregator=False,
        )

        subnet_id = ValidatorIndex(0).compute_subnet_id(ATTESTATION_COMMITTEE_COUNT)
        block_topic = GossipTopic.block(boot.fork.GOSSIP_DIGEST).to_topic_id()
        subnet_topic = GossipTopic.attestation_subnet(
            boot.fork.GOSSIP_DIGEST, subnet_id
        ).to_topic_id()

        _, topics = await _run_build(boot)

        assert topics == [block_topic, subnet_topic]
