"""Networking codec test fixture for wire-format conformance testing."""

from typing import Any, ClassVar

from lean_spec.snappy import compress, decompress, frame_compress, frame_decompress
from lean_spec.subspecs.containers.validator import SubnetId
from lean_spec.subspecs.networking.discovery.codec import decode_message, encode_message
from lean_spec.subspecs.networking.discovery.messages import (
    Distance,
    FindNode,
    IPv4,
    IPv6,
    Nodes,
    Ping,
    Pong,
    Port,
    RequestId,
    TalkReq,
    TalkResp,
)
from lean_spec.subspecs.networking.enr.enr import ENR
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
from lean_spec.subspecs.networking.reqresp.codec import (
    ResponseCode,
    decode_request,
    encode_request,
)
from lean_spec.subspecs.networking.transport.peer_id import KeyType, PeerId, PublicKeyProto
from lean_spec.subspecs.networking.types import SeqNumber
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
            case "reqresp_request":
                output = self._make_reqresp_request()
            case "reqresp_response":
                output = self._make_reqresp_response()
            case "enr":
                output = self._make_enr()
            case "peer_id":
                output = self._make_peer_id()
            case "discv5_message":
                output = self._make_discv5_message()
            case "snappy_block":
                output = self._make_snappy_block()
            case "snappy_frame":
                output = self._make_snappy_frame()
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

    def _make_reqresp_request(self) -> dict[str, Any]:
        """Encode an SSZ request as varint + snappy, decode it back, assert roundtrip."""
        ssz_data = _from_hex(self.input["sszData"])
        encoded = encode_request(ssz_data)

        # Decode must recover the original SSZ bytes.
        decoded = decode_request(encoded)
        assert decoded == ssz_data, "Request roundtrip produced different bytes"

        return {"encoded": _to_hex(encoded)}

    def _make_reqresp_response(self) -> dict[str, Any]:
        """Encode an SSZ response with code, decode it back, assert roundtrip."""
        code = ResponseCode(self.input["responseCode"])
        ssz_data = _from_hex(self.input["sszData"])
        encoded = code.encode(ssz_data)

        # Decode must recover both the response code and SSZ bytes.
        decoded_code, decoded_data = ResponseCode.decode(encoded)
        assert decoded_code == code, f"Code mismatch: {decoded_code} != {code}"
        assert decoded_data == ssz_data, "Response roundtrip produced different bytes"

        return {"encoded": _to_hex(encoded)}

    def _make_snappy_block(self) -> dict[str, Any]:
        """Compress with raw Snappy block format, decompress, assert roundtrip."""
        data = _from_hex(self.input["data"])
        compressed = compress(data)

        decompressed = decompress(compressed)
        assert decompressed == data, "Snappy block roundtrip produced different bytes"

        return {
            "compressed": _to_hex(compressed),
            "compressedLength": len(compressed),
            "uncompressedLength": len(data),
        }

    def _make_snappy_frame(self) -> dict[str, Any]:
        """Compress with Snappy framing format (Ethereum wire format), decompress, roundtrip."""
        data = _from_hex(self.input["data"])
        framed = frame_compress(data)

        decompressed = frame_decompress(framed)
        assert decompressed == data, "Snappy frame roundtrip produced different bytes"

        return {
            "framed": _to_hex(framed),
            "framedLength": len(framed),
            "uncompressedLength": len(data),
        }

    def _make_enr(self) -> dict[str, Any]:
        """Parse an ENR string, re-serialize, assert roundtrip, extract properties."""
        enr_string = self.input["enrString"]
        enr = ENR.from_string(enr_string)

        # Text roundtrip: parse → serialize → must match original.
        assert enr.to_string() == enr_string, "ENR text roundtrip failed"

        # RLP roundtrip: serialize → parse → serialize → must match.
        rlp_bytes = enr.to_rlp()
        assert ENR.from_rlp(rlp_bytes).to_rlp() == rlp_bytes, "ENR RLP roundtrip failed"

        # Extract all properties into the output.
        output: dict[str, Any] = {
            "rlp": _to_hex(rlp_bytes),
            "seq": int(enr.seq),
            "identityScheme": enr.identity_scheme,
        }

        if enr.node_id:
            output["nodeId"] = _to_hex(enr.node_id)
        if enr.public_key:
            output["publicKey"] = _to_hex(enr.public_key)
        if enr.ip4:
            output["ip4"] = enr.ip4
        if enr.udp_port is not None:
            output["udpPort"] = int(enr.udp_port)
        if enr.udp6_port is not None:
            output["udp6Port"] = int(enr.udp6_port)
        if enr.ip6:
            output["ip6"] = enr.ip6
        if enr.quic_port is not None:
            output["quicPort"] = int(enr.quic_port)
        if enr.quic6_port is not None:
            output["quic6Port"] = int(enr.quic6_port)
        if (ma := enr.multiaddr()) is not None:
            output["multiaddr"] = str(ma)
        if (eth2 := enr.eth2_data) is not None:
            output["eth2Data"] = {
                "forkDigest": _to_hex(eth2.fork_digest),
                "nextForkVersion": _to_hex(eth2.next_fork_version),
                "nextForkEpoch": int(eth2.next_fork_epoch),
            }
        if (subnets := enr.attestation_subnets) is not None:
            output["attestationSubnets"] = [int(s) for s in subnets.subscribed_subnets()]
        if (sync := enr.sync_committee_subnets) is not None:
            output["syncCommitteeSubnets"] = [int(s) for s in sync.subscribed_subnets()]
        output["isAggregator"] = enr.is_aggregator
        output["signatureValid"] = enr.verify_signature()
        output["isValid"] = enr.is_valid()

        return output

    def _make_peer_id(self) -> dict[str, Any]:
        """Derive a PeerId from a public key, output protobuf encoding and Base58 string."""
        key_type_map = {
            "ed25519": KeyType.ED25519,
            "secp256k1": KeyType.SECP256K1,
            "ecdsa": KeyType.ECDSA,
            "rsa": KeyType.RSA,
        }
        key_type = key_type_map[self.input["keyType"]]
        key_data = _from_hex(self.input["publicKey"])

        proto = PublicKeyProto(key_type=key_type, key_data=key_data)
        encoded_proto = proto.encode()
        peer_id = PeerId.from_public_key(proto)
        peer_id_str = str(peer_id)

        # Roundtrip: Base58 decode → re-encode must match.
        roundtrip = PeerId.from_base58(peer_id_str)
        assert roundtrip == peer_id, "PeerId Base58 roundtrip failed"

        return {
            "protobufEncoded": _to_hex(encoded_proto),
            "peerId": peer_id_str,
        }

    def _make_discv5_message(self) -> dict[str, Any]:
        """Encode a discv5 message as type byte + RLP, decode it back, assert roundtrip."""
        msg = _build_discv5_message(self.input)
        encoded = encode_message(msg)

        # Decode and re-encode must produce identical bytes.
        re_encoded = encode_message(decode_message(encoded))
        assert encoded == re_encoded, "Discv5 message roundtrip produced different bytes"

        return {"encoded": _to_hex(encoded)}


def _build_discv5_message(
    d: dict[str, Any],
) -> Ping | Pong | FindNode | Nodes | TalkReq | TalkResp:
    """Build a discv5 message dataclass from a JSON-friendly dict."""
    request_id = RequestId(data=_from_hex(d["requestId"]))
    match d["type"]:
        case "ping":
            return Ping(request_id=request_id, enr_seq=SeqNumber(d["enrSeq"]))
        case "pong":
            ip_bytes = _from_hex(d["recipientIp"])
            ip = IPv4(ip_bytes) if len(ip_bytes) == 4 else IPv6(ip_bytes)
            return Pong(
                request_id=request_id,
                enr_seq=SeqNumber(d["enrSeq"]),
                recipient_ip=ip,
                recipient_port=Port(d["recipientPort"]),
            )
        case "findnode":
            return FindNode(
                request_id=request_id,
                distances=[Distance(x) for x in d["distances"]],
            )
        case "nodes":
            return Nodes(
                request_id=request_id,
                total=d["total"],
                enrs=[_from_hex(e) for e in d.get("enrs", [])],
            )
        case "talkreq":
            return TalkReq(
                request_id=request_id,
                protocol=_from_hex(d["protocol"]),
                request=_from_hex(d["request"]),
            )
        case "talkresp":
            return TalkResp(
                request_id=request_id,
                response=_from_hex(d["response"]),
            )
        case _:
            raise ValueError(f"Unknown discv5 message type: {d['type']}")


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
