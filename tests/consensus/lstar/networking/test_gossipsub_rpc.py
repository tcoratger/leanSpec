"""Test vectors for gossipsub RPC protobuf encoding."""

import pytest

from consensus_testing import (
    GossipsubRpcRoundtrip,
    NetworkingCodecTestFiller,
    RpcControlSpec,
    RpcGraftSpec,
    RpcIDontWantSpec,
    RpcIHaveSpec,
    RpcIWantSpec,
    RpcMessageSpec,
    RpcPruneSpec,
    RpcSubscriptionSpec,
)

pytestmark = pytest.mark.valid_until("Lstar")

TOPIC_A = "/leanconsensus/0x12345678/block/ssz_snappy"
TOPIC_B = "/leanconsensus/0x12345678/aggregation/ssz_snappy"
MESSAGE_ID_1 = "0x" + "aa" * 20
MESSAGE_ID_2 = "0x" + "bb" * 20
MESSAGE_ID_3 = "0x" + "cc" * 20


# --- SubOpts ---


def test_sub_opts_subscribe(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """SubOpts encoding for a topic subscription."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[RpcSubscriptionSpec(subscribe=True, topic_id=TOPIC_A)], publish=[]
        ),
    )


def test_sub_opts_unsubscribe(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """SubOpts encoding for a topic unsubscription."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[RpcSubscriptionSpec(subscribe=False, topic_id=TOPIC_A)], publish=[]
        ),
    )


def test_sub_opts_empty_topic(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """SubOpts with an empty topic string."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[RpcSubscriptionSpec(subscribe=True, topic_id="")], publish=[]
        ),
    )


# --- Message ---


def test_message_topic_only(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Published message with only the topic field set."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(subscriptions=[], publish=[RpcMessageSpec(topic=TOPIC_A)]),
    )


def test_message_all_fields(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Published message with every optional field populated."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[
                RpcMessageSpec(
                    from_peer="0x" + "01" * 32,
                    data="0xdeadbeef",
                    seqno="0x0000000000000001",
                    topic=TOPIC_A,
                    signature="0x" + "ff" * 64,
                    key="0x" + "02" * 33,
                )
            ],
        ),
    )


def test_message_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Published message with no fields set. Encodes as zero bytes."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(subscriptions=[], publish=[RpcMessageSpec()]),
    )


# --- ControlGraft ---


def test_graft_single_topic(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """GRAFT requesting mesh membership for one topic."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(graft=[RpcGraftSpec(topic_id=TOPIC_A)]),
        ),
    )


def test_graft_empty_topic(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """GRAFT with an empty topic string."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[], publish=[], control=RpcControlSpec(graft=[RpcGraftSpec(topic_id="")])
        ),
    )


# --- ControlIHave ---


def test_ihave_single_id(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """IHAVE advertising one cached message ID."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(
                ihave=[RpcIHaveSpec(topic_id=TOPIC_A, message_ids=[MESSAGE_ID_1])]
            ),
        ),
    )


def test_ihave_multiple_ids(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """IHAVE advertising three cached message IDs."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(
                ihave=[
                    RpcIHaveSpec(
                        topic_id=TOPIC_A, message_ids=[MESSAGE_ID_1, MESSAGE_ID_2, MESSAGE_ID_3]
                    )
                ]
            ),
        ),
    )


def test_ihave_empty_ids(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """IHAVE with a topic but no message IDs."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(ihave=[RpcIHaveSpec(topic_id=TOPIC_A, message_ids=[])]),
        ),
    )


# --- ControlIWant ---


def test_iwant_single_id(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """IWANT requesting one message by ID."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(iwant=[RpcIWantSpec(message_ids=[MESSAGE_ID_1])]),
        ),
    )


def test_iwant_multiple_ids(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """IWANT requesting two messages by ID."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(iwant=[RpcIWantSpec(message_ids=[MESSAGE_ID_1, MESSAGE_ID_2])]),
        ),
    )


# --- ControlPrune ---


def test_prune_topic_only(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """PRUNE with topic but no peer exchange or backoff."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(prune=[RpcPruneSpec(topic_id=TOPIC_A)]),
        ),
    )


def test_prune_with_backoff(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """PRUNE with a 60-second backoff duration."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(prune=[RpcPruneSpec(topic_id=TOPIC_A, backoff=60)]),
        ),
    )


def test_prune_with_two_minute_backoff(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    PRUNE with a 120-second backoff duration.

    Peer exchange records are not part of the lean wire format.
    The previous version of this vector carried them in its input
    where the untyped builder silently dropped them.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(prune=[RpcPruneSpec(topic_id=TOPIC_A, backoff=120)]),
        ),
    )


# --- ControlIDontWant ---


def test_idontwant_single_id(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """IDONTWANT declining one message. Gossipsub v1.2 extension."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(idontwant=[RpcIDontWantSpec(message_ids=[MESSAGE_ID_1])]),
        ),
    )


def test_idontwant_multiple_ids(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """IDONTWANT declining two messages."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(
                idontwant=[RpcIDontWantSpec(message_ids=[MESSAGE_ID_1, MESSAGE_ID_2])]
            ),
        ),
    )


# --- ControlMessage ---


def test_control_single_graft(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Control message containing only a single GRAFT."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(graft=[RpcGraftSpec(topic_id=TOPIC_A)]),
        ),
    )


def test_control_all_types(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Control message with one of each control type."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(
                ihave=[RpcIHaveSpec(topic_id=TOPIC_A, message_ids=[MESSAGE_ID_1])],
                iwant=[RpcIWantSpec(message_ids=[MESSAGE_ID_2])],
                graft=[RpcGraftSpec(topic_id=TOPIC_A)],
                prune=[RpcPruneSpec(topic_id=TOPIC_B, backoff=60)],
                idontwant=[RpcIDontWantSpec(message_ids=[MESSAGE_ID_3])],
            ),
        ),
    )


def test_control_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Empty control message. All repeated fields empty, encodes to zero bytes."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(subscriptions=[], publish=[], control=RpcControlSpec()),
    )


# --- Full RPC ---


def test_rpc_subscriptions_only(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """RPC with only subscription changes."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[
                RpcSubscriptionSpec(subscribe=True, topic_id=TOPIC_A),
                RpcSubscriptionSpec(subscribe=True, topic_id=TOPIC_B),
            ],
            publish=[],
        ),
    )


def test_rpc_publish_only(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """RPC with only published messages."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[
                RpcMessageSpec(topic=TOPIC_A, data="0xdeadbeef"),
                RpcMessageSpec(topic=TOPIC_B, data="0xcafebabe"),
            ],
        ),
    )


def test_rpc_control_only(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """RPC with only control messages."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(
                graft=[RpcGraftSpec(topic_id=TOPIC_A)],
                prune=[RpcPruneSpec(topic_id=TOPIC_B, backoff=60)],
            ),
        ),
    )


def test_rpc_full(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """RPC with subscriptions, published messages, and control all present."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[RpcSubscriptionSpec(subscribe=True, topic_id=TOPIC_A)],
            publish=[RpcMessageSpec(topic=TOPIC_A, data="0xdeadbeef")],
            control=RpcControlSpec(
                graft=[RpcGraftSpec(topic_id=TOPIC_B)],
                idontwant=[RpcIDontWantSpec(message_ids=[MESSAGE_ID_1])],
            ),
        ),
    )


def test_rpc_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """Empty RPC. No subscriptions, messages, or control."""
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(subscriptions=[], publish=[]),
    )
