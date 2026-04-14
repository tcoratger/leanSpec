"""Networking codec test fixture for wire-format conformance testing."""

from typing import Any, ClassVar

from lean_spec.subspecs.containers.validator import SubnetId
from lean_spec.subspecs.networking.gossipsub.message import GossipsubMessage
from lean_spec.subspecs.networking.gossipsub.rpc import (
    RPC,
    ControlGraft,
    ControlIDontWant,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    Message,
    PrunePeerInfo,
    SubOpts,
)
from lean_spec.subspecs.networking.gossipsub.topic import GossipTopic, TopicKind
from lean_spec.subspecs.networking.gossipsub.types import TopicId
from lean_spec.subspecs.networking.varint import decode_varint, encode_varint

from .base import BaseConsensusFixture


def _to_hex(data: bytes) -> str:
    """Format raw bytes as a 0x-prefixed hex string."""
    return "0x" + data.hex()


def _from_hex(hex_str: str) -> bytes:
    """Parse a 0x-prefixed hex string into raw bytes."""
    return bytes.fromhex(hex_str.removeprefix("0x"))


class NetworkingCodecTest(BaseConsensusFixture):
    """Fixture for networking wire-format conformance.

    Verifies encode/decode roundtrips for networking codecs.

    JSON output: codecName, input, output.
    """

    format_name: ClassVar[str] = "networking_codec"
    description: ClassVar[str] = "Tests networking codec encode/decode roundtrip"

    codec_name: str
    """Codec under test: varint, gossip_topic, or gossip_message_id."""

    input: dict[str, Any]
    """Codec-specific input parameters."""

    output: dict[str, Any] = {}
    """Computed output. Filled by make_fixture."""

    def make_fixture(self) -> "NetworkingCodecTest":
        """Dispatch to the codec handler and produce computed output.

        Returns:
            A copy of this fixture with output populated.

        Raises:
            ValueError: If codec_name is unknown.
        """
        match self.codec_name:
            case "varint":
                output = self._make_varint()
            case "gossip_topic":
                output = self._make_gossip_topic()
            case "gossip_message_id":
                output = self._make_gossip_message_id()
            case "gossipsub_rpc":
                output = self._make_gossipsub_rpc()
            case _:
                raise ValueError(f"Unknown codec: {self.codec_name}")
        return self.model_copy(update={"output": output})

    def _make_varint(self) -> dict[str, Any]:
        """Encode a value as LEB128, decode it back, assert roundtrip."""
        value = self.input["value"]
        encoded = encode_varint(value)

        # Decode must recover the original value and consume all bytes.
        decoded, byte_length = decode_varint(encoded)
        assert decoded == value, f"Varint roundtrip: {value} -> {encoded.hex()} -> {decoded}"
        assert byte_length == len(encoded), f"Length: {byte_length} != {len(encoded)}"

        return {"encoded": _to_hex(encoded), "byteLength": byte_length}

    def _make_gossip_topic(self) -> dict[str, Any]:
        """Build a topic string from components, parse it back, assert roundtrip."""
        kind = TopicKind(self.input["kind"])
        fork_digest = self.input["forkDigest"]
        raw_subnet = self.input.get("subnetId")
        subnet_id = SubnetId(raw_subnet) if raw_subnet is not None else None

        topic = GossipTopic(kind=kind, fork_digest=fork_digest, subnet_id=subnet_id)
        topic_string = topic.to_topic_id()

        # Parse the string back to verify it reconstructs the same topic.
        parsed = GossipTopic.from_string(topic_string)
        assert parsed == topic, f"Topic roundtrip: {topic} -> {topic_string!r} -> {parsed}"

        return {"topicString": topic_string}

    def _make_gossip_message_id(self) -> dict[str, Any]:
        """Compute a 20-byte gossipsub message ID from topic, data, and domain."""
        topic = _from_hex(self.input["topic"])
        data = _from_hex(self.input["data"])
        domain = _from_hex(self.input["domain"])

        # SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]
        message_id = GossipsubMessage.compute_id(topic, data, domain=domain)

        return {"messageId": _to_hex(message_id)}

    def _make_gossipsub_rpc(self) -> dict[str, Any]:
        """Encode an RPC message as protobuf, decode it back, assert roundtrip."""
        rpc = _build_rpc(self.input)
        encoded = rpc.encode()

        # Decode and re-encode must produce identical bytes.
        re_encoded = RPC.decode(encoded).encode()
        assert encoded == re_encoded, "RPC roundtrip produced different bytes"

        return {"encoded": _to_hex(encoded)}


def _build_rpc(d: dict[str, Any]) -> RPC:
    """Build an RPC from a JSON-friendly dict."""
    subs = [_build_sub_opts(s) for s in d.get("subscriptions", [])]
    msgs = [_build_message(m) for m in d.get("publish", [])]
    ctrl = _build_control(d["control"]) if d.get("control") else None
    return RPC(subscriptions=subs, publish=msgs, control=ctrl)


def _build_sub_opts(d: dict[str, Any]) -> SubOpts:
    """Build a SubOpts from a dict."""
    return SubOpts(subscribe=d["subscribe"], topic_id=TopicId(d["topicId"]))


def _build_message(d: dict[str, Any]) -> Message:
    """Build a Message from a dict. Bytes fields are hex-encoded."""
    return Message(
        from_peer=_from_hex(d["fromPeer"]) if d.get("fromPeer") else b"",
        data=_from_hex(d["data"]) if d.get("data") else b"",
        seqno=_from_hex(d["seqno"]) if d.get("seqno") else b"",
        topic=TopicId(d.get("topic", "")),
        signature=_from_hex(d["signature"]) if d.get("signature") else b"",
        key=_from_hex(d["key"]) if d.get("key") else b"",
    )


def _build_control(d: dict[str, Any]) -> ControlMessage:
    """Build a ControlMessage from a dict."""
    return ControlMessage(
        ihave=[_build_ihave(x) for x in d.get("ihave", [])],
        iwant=[_build_iwant(x) for x in d.get("iwant", [])],
        graft=[ControlGraft(topic_id=TopicId(x["topicId"])) for x in d.get("graft", [])],
        prune=[_build_prune(x) for x in d.get("prune", [])],
        idontwant=[_build_idontwant(x) for x in d.get("idontwant", [])],
    )


def _build_ihave(d: dict[str, Any]) -> ControlIHave:
    """Build a ControlIHave from a dict."""
    return ControlIHave(
        topic_id=TopicId(d.get("topicId", "")),
        message_ids=[_from_hex(mid) for mid in d.get("messageIds", [])],
    )


def _build_iwant(d: dict[str, Any]) -> ControlIWant:
    """Build a ControlIWant from a dict."""
    return ControlIWant(message_ids=[_from_hex(mid) for mid in d.get("messageIds", [])])


def _build_prune(d: dict[str, Any]) -> ControlPrune:
    """Build a ControlPrune from a dict."""
    peers = [_build_prune_peer(p) for p in d.get("peers", [])]
    return ControlPrune(
        topic_id=TopicId(d.get("topicId", "")),
        peers=peers,
        backoff=d.get("backoff", 0),
    )


def _build_prune_peer(p: dict[str, Any]) -> PrunePeerInfo:
    """Build a PrunePeerInfo from a dict."""
    return PrunePeerInfo(
        peer_id=_from_hex(p["peerId"]) if p.get("peerId") else b"",
        signed_peer_record=(_from_hex(p["signedPeerRecord"]) if p.get("signedPeerRecord") else b""),
    )


def _build_idontwant(d: dict[str, Any]) -> ControlIDontWant:
    """Build a ControlIDontWant from a dict."""
    return ControlIDontWant(message_ids=[_from_hex(mid) for mid in d.get("messageIds", [])])
