"""
Gossipsub handler test fixture for protocol behavior conformance.

Generates JSON test vectors that assert gossipsub protocol decisions.
Each vector captures an initial peer/mesh/cache state, an incoming RPC event,
and the expected outbound RPCs plus resulting mesh topology.

The fixture tests protocol logic only, not wire encoding or I/O.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, ClassVar
from unittest.mock import patch

from pydantic import Field

from consensus_testing.test_fixtures.base import BaseConsensusFixture
from lean_spec.node.networking import PeerId
from lean_spec.node.networking.gossipsub.behavior import GossipsubBehavior, PeerState
from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.parameters import GossipsubParameters
from lean_spec.node.networking.gossipsub.rpc import (
    RPC,
    ControlGraft,
    ControlIDontWant,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    Message,
)
from lean_spec.node.networking.gossipsub.types import MessageId, Timestamp, TopicId

# Sentinel that satisfies `outbound_stream is not None` checks.
# The patched _send_rpc never touches the stream, so any non-None value works.
_FAKE_STREAM: Any = object()


@dataclass
class _SendCapture:
    """Records each outbound RPC as a (peer, rpc) pair."""

    sent: list[tuple[PeerId, RPC]] = field(default_factory=list)

    async def __call__(self, peer_id: PeerId, rpc: RPC) -> None:
        self.sent.append((peer_id, rpc))


def _peer_id(name: str) -> PeerId:
    """Convert a short test name to a PeerId."""
    return PeerId.from_base58(name)


def _unhex(hex_str: str) -> bytes:
    """Decode a 0x-prefixed hex string to bytes."""
    return bytes.fromhex(hex_str.removeprefix("0x"))


def _serialize_rpcs(
    sent: list[tuple[PeerId, RPC]], peer_names: dict[PeerId, str]
) -> list[dict[str, Any]]:
    """
    Convert captured outbound RPCs to JSON-friendly dicts.

    Each entry in the output list represents one RPC sent to a peer.
    The structure mirrors the gossipsub RPC wire format:

    - toPeer: human-readable peer name
    - subscriptions: topic subscribe/unsubscribe changes (if any)
    - publish: forwarded messages with hex-encoded data (if any)
    - control: GRAFT, PRUNE, IWANT, IDONTWANT sub-messages (if any)

    Fixture consumers use this to assert exact outbound behavior.
    """
    serialized_rpcs = []
    for recipient_peer_id, rpc in sent:
        recipient_name = peer_names.get(recipient_peer_id, str(recipient_peer_id))
        serialized_rpc: dict[str, Any] = {"toPeer": recipient_name}

        if rpc.subscriptions:
            serialized_rpc["subscriptions"] = [
                {"subscribe": subscription.subscribe, "topicId": str(subscription.topic_id)}
                for subscription in rpc.subscriptions
            ]

        if rpc.publish:
            serialized_rpc["publish"] = [
                {"topic": str(message.topic), "data": "0x" + message.data.hex()}
                for message in rpc.publish
            ]

        # Only include control fields that carry sub-messages.
        if rpc.control and not rpc.control.is_empty():
            serialized_control: dict[str, Any] = {}
            if rpc.control.graft:
                serialized_control["graft"] = [
                    {"topicId": str(graft.topic_id)} for graft in rpc.control.graft
                ]
            if rpc.control.prune:
                serialized_control["prune"] = [
                    {"topicId": str(prune.topic_id), "backoff": prune.backoff}
                    for prune in rpc.control.prune
                ]
            if rpc.control.iwant:
                serialized_control["iwant"] = [
                    {"messageIds": ["0x" + message_id.hex() for message_id in iwant.message_ids]}
                    for iwant in rpc.control.iwant
                ]
            if rpc.control.idontwant:
                serialized_control["idontwant"] = [
                    {
                        "messageIds": [
                            "0x" + message_id.hex() for message_id in idontwant.message_ids
                        ]
                    }
                    for idontwant in rpc.control.idontwant
                ]
            serialized_rpc["control"] = serialized_control

        serialized_rpcs.append(serialized_rpc)
    return serialized_rpcs


def _serialize_meshes(
    behavior: GossipsubBehavior, peer_names: dict[PeerId, str]
) -> dict[str, list[str]]:
    """
    Snapshot the mesh topology after handler execution.

    Returns a dict mapping each topic to a sorted list of peer names.
    Sorting ensures deterministic output for fixture comparison.
    """
    return {
        str(topic): sorted(
            peer_names.get(peer_id, str(peer_id)) for peer_id in behavior.mesh.get_mesh_peers(topic)
        )
        for topic in behavior.mesh.subscriptions
    }


class GossipsubHandlerTest(BaseConsensusFixture):
    """
    Fixture for gossipsub handler behavior conformance.

    Tests protocol decisions: given initial state + incoming event,
    what RPCs are sent and how does the mesh change?

    JSON output: params, initialState, event, now, expected.
    """

    format_name: ClassVar[str] = "gossipsub_handler_test"
    description: ClassVar[str] = "Tests gossipsub handler protocol decisions"

    handler_name: str
    """Handler being tested: graft, prune, ihave, iwant, message."""

    params: dict[str, int]
    """Gossipsub parameters: d, dLow, dHigh, dLazy."""

    initial_state: dict[str, Any]
    """Initial behavior state: subscriptions, meshes, peers, caches."""

    event: dict[str, Any]
    """Incoming event: fromPeer + RPC content."""

    now: float = 1000.0
    """Current timestamp for backoff checks."""

    expected: dict[str, Any] = Field(default_factory=dict)
    """Expected output. Filled by make_fixture."""

    def make_fixture(self) -> "GossipsubHandlerTest":
        """Produce the completed fixture with expected outputs filled in."""
        self.expected = asyncio.run(self._execute())
        return self

    async def _execute(self) -> dict[str, Any]:
        """
        Run the handler against a fully-configured behavior instance.

        Builds the gossipsub behavior from fixture inputs, dispatches the
        incoming RPC, and returns the outbound RPCs and final mesh state.
        """
        gs_params = GossipsubParameters(
            d=self.params.get("d", 8),
            d_low=self.params.get("dLow", 6),
            d_high=self.params.get("dHigh", 12),
            d_lazy=self.params.get("dLazy", 6),
        )
        behavior = GossipsubBehavior(params=gs_params)

        # Intercept outbound RPCs instead of sending them over the network.
        capture = _SendCapture()
        behavior._send_rpc = capture  # type: ignore[assignment]

        # Map between human-readable test names and opaque peer identifiers.
        peer_names: dict[PeerId, str] = {}

        # Subscriptions define which topics the local node participates in.
        #
        # Handlers ignore messages for topics we are not subscribed to.
        for topic in self.initial_state.get("subscriptions", []):
            behavior.mesh.subscribe(TopicId(topic))

        # Register each peer with its subscriptions and protocol state.
        #
        # Peer properties like backoff timers and IDONTWANT sets directly
        # influence handler decisions (e.g., reject GRAFTs, skip forwarding).
        for peer_name, peer_config in self.initial_state.get("peers", {}).items():
            peer_id = _peer_id(peer_name)
            peer_names[peer_id] = peer_name
            peer_state = PeerState(
                peer_id=peer_id,
                subscriptions={
                    TopicId(topic_str) for topic_str in peer_config.get("subscriptions", [])
                },
                outbound_stream=_FAKE_STREAM if peer_config.get("withStream", True) else None,
            )

            # Backoff prevents re-GRAFTing a recently-pruned peer.
            for topic_str, expiry in peer_config.get("backoff", {}).items():
                peer_state.backoff[TopicId(topic_str)] = expiry

            # IDONTWANT suppresses forwarding to peers that already have the message.
            for message_id_hex in peer_config.get("dontWantIds", []):
                peer_state.dont_want_ids.add(MessageId(_unhex(message_id_hex)))
            behavior._peers[peer_id] = peer_state

        # Mesh topology determines who receives forwarded messages.
        #
        # Handlers check mesh membership for GRAFT acceptance, PRUNE removal,
        # and message forwarding decisions.
        for topic_str, mesh_peer_names in self.initial_state.get("meshes", {}).items():
            topic = TopicId(topic_str)
            for peer_name in mesh_peer_names:
                behavior.mesh.add_to_mesh(topic, _peer_id(peer_name))

        # Seen cache tracks previously-received message IDs.
        #
        # Duplicate messages are silently dropped; IHAVE for seen IDs
        # does not trigger an IWANT response.
        for message_id_hex in self.initial_state.get("seenMessageIds", []):
            behavior.seen_cache.add(MessageId(_unhex(message_id_hex)), Timestamp(self.now))

        # Message cache holds full message payloads for IWANT responses.
        #
        # When a peer requests a message via IWANT, the handler looks it up
        # here and sends the payload back.
        for cached_message in self.initial_state.get("cachedMessages", []):
            message = GossipsubMessage(
                topic=cached_message["topic"].encode("utf-8"),
                raw_data=_unhex(cached_message["data"]),
            )
            message._cached_id = MessageId(_unhex(cached_message["messageId"]))
            behavior.message_cache.put(TopicId(cached_message["topic"]), message)

        # Build the incoming RPC from the event.
        from_peer = _peer_id(self.event["fromPeer"])
        peer_names.setdefault(from_peer, self.event["fromPeer"])

        # Fix the clock so backoff and TTL checks are deterministic.
        with patch("time.time", return_value=self.now):
            await behavior._handle_rpc(from_peer, _build_event_rpc(self.event))

        return {
            "sentRpcs": _serialize_rpcs(capture.sent, peer_names),
            "meshAfter": _serialize_meshes(behavior, peer_names),
        }


def _build_event_rpc(event: dict[str, Any]) -> RPC:
    """
    Construct an RPC from the event dict supplied by the test fixture.

    The event dict describes one incoming message from a peer.
    Required key:

    - fromPeer: short name of the sending peer

    Optional keys (include one or more to build the RPC):

    - graft: list of dicts with topicId
    - prune: list of dicts with topicId and optional backoff
    - ihave: list of dicts with topicId and hex messageIds
    - iwant: list of dicts with hex messageIds
    - idontwant: list of dicts with hex messageIds
    - publish: list of dicts with topic and hex data
    """
    control_components: dict[str, list[Any]] = {}

    if "graft" in event:
        control_components["graft"] = [
            ControlGraft(topic_id=TopicId(graft["topicId"])) for graft in event["graft"]
        ]
    if "prune" in event:
        control_components["prune"] = [
            ControlPrune(topic_id=TopicId(prune["topicId"]), backoff=prune.get("backoff", 0))
            for prune in event["prune"]
        ]
    if "ihave" in event:
        control_components["ihave"] = [
            ControlIHave(
                topic_id=TopicId(ihave["topicId"]),
                message_ids=[
                    _unhex(message_id_hex) for message_id_hex in ihave.get("messageIds", [])
                ],
            )
            for ihave in event["ihave"]
        ]
    if "iwant" in event:
        control_components["iwant"] = [
            ControlIWant(
                message_ids=[
                    _unhex(message_id_hex) for message_id_hex in iwant.get("messageIds", [])
                ]
            )
            for iwant in event["iwant"]
        ]
    if "idontwant" in event:
        control_components["idontwant"] = [
            ControlIDontWant(
                message_ids=[
                    _unhex(message_id_hex) for message_id_hex in idontwant.get("messageIds", [])
                ]
            )
            for idontwant in event["idontwant"]
        ]

    return RPC(
        publish=[
            Message(
                topic=TopicId(message.get("topic", "")),
                data=_unhex(message["data"]) if message.get("data") else b"",
            )
            for message in event.get("publish", [])
        ],
        control=ControlMessage(**control_components) if control_components else None,
    )
