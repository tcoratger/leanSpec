"""
Tests for multistream-select 1.0 protocol negotiation.

Wire format:
    Message = [varint length][payload + '\\n']
    - Length includes the trailing newline
    - Maximum message size: 1024 bytes

Protocol flow:
    1. Both sides send multistream header: /multistream/1.0.0
    2. Client proposes a protocol
    3. Server echoes (accept) or sends "na" (reject)

Reference: https://github.com/multiformats/multistream-select
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from lean_spec.subspecs.networking.transport.quic.stream_adapter import (
    MULTISTREAM_PROTOCOL_ID,
    NA,
    NegotiationError,
    QuicStreamAdapter,
)
from lean_spec.subspecs.networking.varint import decode_varint, encode_varint

GOSSIPSUB_ID = "/meshsub/1.1.0"
GOSSIPSUB_V12_ID = "/meshsub/1.2.0"
STATUS_ID = "/leanconsensus/req/status/1/ssz_snappy"
BLOCKS_BY_ROOT_ID = "/leanconsensus/req/blocks_by_root/1/ssz_snappy"


class TestConstants:
    """Tests for protocol constants."""

    def test_protocol_id(self) -> None:
        """Protocol ID matches spec."""
        assert MULTISTREAM_PROTOCOL_ID == "/multistream/1.0.0"

    def test_na_constant(self) -> None:
        """NA rejection string."""
        assert NA == "na"


class TestNegotiateClient:
    """Tests for client-side negotiation."""

    async def test_client_accepts_first_protocol(self) -> None:
        """Client successfully negotiates first proposed protocol."""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            await _read_message(server)
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            protocol = await _read_message(server)
            await _write_message(server, protocol)

        task = asyncio.create_task(server_task())
        result = await client.negotiate_client([GOSSIPSUB_ID])
        await task
        assert result == GOSSIPSUB_ID

    async def test_client_tries_multiple_protocols(self) -> None:
        """Client tries protocols until one is accepted."""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            await _read_message(server)
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            await _read_message(server)
            await _write_message(server, NA)
            protocol = await _read_message(server)
            await _write_message(server, protocol)

        task = asyncio.create_task(server_task())
        result = await client.negotiate_client([GOSSIPSUB_V12_ID, GOSSIPSUB_ID])
        await task
        assert result == GOSSIPSUB_ID

    async def test_client_all_rejected(self) -> None:
        """Client raises error when all protocols rejected."""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            await _read_message(server)
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            await _read_message(server)
            await _write_message(server, NA)
            await _read_message(server)
            await _write_message(server, NA)

        task = asyncio.create_task(server_task())
        with pytest.raises(NegotiationError, match="No protocols accepted"):
            await client.negotiate_client(["/proto1", "/proto2"])
        await task

    async def test_client_empty_protocols(self) -> None:
        """Client raises error when no protocols provided."""
        stream, _ = _create_stream_pair()
        with pytest.raises(NegotiationError, match="No protocols to negotiate"):
            await stream.negotiate_client([])

    async def test_client_invalid_header(self) -> None:
        """Client raises error on invalid header."""
        client, server = _create_stream_pair()
        await _write_message(server, "/wrong/1.0.0")

        with pytest.raises(NegotiationError, match="Invalid multistream header"):
            await client.negotiate_client([GOSSIPSUB_ID])


class TestNegotiateServer:
    """Tests for server-side negotiation."""

    async def test_server_accepts_supported_protocol(self) -> None:
        """Server accepts protocol it supports."""
        server, client = _create_stream_pair()

        async def client_task() -> None:
            await _write_message(client, MULTISTREAM_PROTOCOL_ID)
            await _read_message(client)
            await _write_message(client, GOSSIPSUB_ID)
            await _read_message(client)

        task = asyncio.create_task(client_task())
        result = await server.negotiate_server({GOSSIPSUB_ID, STATUS_ID})
        await task
        assert result == GOSSIPSUB_ID

    async def test_server_rejects_unsupported_then_accepts(self) -> None:
        """Server rejects unsupported protocols."""
        server, client = _create_stream_pair()

        async def client_task() -> None:
            await _write_message(client, MULTISTREAM_PROTOCOL_ID)
            await _read_message(client)
            await _write_message(client, GOSSIPSUB_V12_ID)
            response1 = await _read_message(client)
            assert response1 == NA
            await _write_message(client, GOSSIPSUB_ID)
            response2 = await _read_message(client)
            assert response2 == GOSSIPSUB_ID

        task = asyncio.create_task(client_task())
        result = await server.negotiate_server({GOSSIPSUB_ID})
        await task
        assert result == GOSSIPSUB_ID

    async def test_server_empty_supported(self) -> None:
        """Server raises error when no supported protocols."""
        stream, _ = _create_stream_pair()
        with pytest.raises(NegotiationError, match="No supported protocols"):
            await stream.negotiate_server(set())

    async def test_server_invalid_header(self) -> None:
        """Server raises error on invalid client header."""
        server, client = _create_stream_pair()
        await _write_message(client, "/wrong/1.0.0")

        with pytest.raises(NegotiationError, match="Invalid multistream header"):
            await server.negotiate_server({GOSSIPSUB_ID})


class TestLazyClient:
    """Tests for lazy client negotiation."""

    async def test_lazy_client_single_protocol(self) -> None:
        """Lazy client sends header and proposal together."""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            header = await _read_message(server)
            assert header == MULTISTREAM_PROTOCOL_ID
            protocol = await _read_message(server)
            assert protocol == GOSSIPSUB_ID
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            await _write_message(server, protocol)

        task = asyncio.create_task(server_task())
        result = await client.negotiate_lazy_client(GOSSIPSUB_ID)
        await task
        assert result == GOSSIPSUB_ID

    async def test_lazy_client_rejected(self) -> None:
        """Lazy client raises error when protocol rejected."""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            await _read_message(server)
            await _read_message(server)
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            await _write_message(server, NA)

        task = asyncio.create_task(server_task())
        with pytest.raises(NegotiationError, match="Protocol rejected"):
            await client.negotiate_lazy_client("/unsupported")
        await task

    async def test_lazy_client_invalid_header(self) -> None:
        """Lazy client raises error on invalid server header."""
        client, server = _create_stream_pair()
        await _write_message(server, "/wrong/1.0.0")

        with pytest.raises(NegotiationError, match="Invalid multistream header"):
            await client.negotiate_lazy_client(GOSSIPSUB_ID)


class TestMessageFormat:
    """Tests for wire message format."""

    async def test_message_format(self) -> None:
        """Messages are length-prefixed with trailing newline."""
        stream, peer = _create_stream_pair()
        await _write_message(peer, STATUS_ID)

        raw = await stream.read(100)
        expected_payload = STATUS_ID.encode("utf-8") + b"\n"
        expected_len = len(expected_payload)
        assert raw[0] == expected_len
        assert raw[1:] == expected_payload

    async def test_message_roundtrip(self) -> None:
        """Write then read returns original message."""
        stream, peer = _create_stream_pair()
        await _write_message(peer, BLOCKS_BY_ROOT_ID)
        received = await _read_message(stream)
        assert received == BLOCKS_BY_ROOT_ID


class TestFullNegotiation:
    """Integration tests for full negotiation scenarios."""

    async def test_bidirectional_negotiation(self) -> None:
        """Client and server negotiate successfully."""
        client, server = _create_stream_pair()

        async def client_task() -> str:
            return await client.negotiate_client([GOSSIPSUB_ID, STATUS_ID])

        async def server_task() -> str:
            return await server.negotiate_server({GOSSIPSUB_ID, BLOCKS_BY_ROOT_ID})

        client_result, server_result = await asyncio.gather(
            client_task(),
            server_task(),
        )
        assert client_result == GOSSIPSUB_ID
        assert server_result == GOSSIPSUB_ID

    async def test_negotiate_status(self) -> None:
        """Negotiate status protocol."""
        client, server = _create_stream_pair()

        async def client_task() -> str:
            return await client.negotiate_client([STATUS_ID])

        async def server_task() -> str:
            return await server.negotiate_server({STATUS_ID})

        client_result, server_result = await asyncio.gather(
            client_task(),
            server_task(),
        )
        assert client_result == STATUS_ID
        assert server_result == STATUS_ID

    async def test_negotiate_with_fallback(self) -> None:
        """Client falls back to second option when first rejected."""
        client, server = _create_stream_pair()

        async def client_task() -> str:
            return await client.negotiate_client([GOSSIPSUB_V12_ID, GOSSIPSUB_ID])

        async def server_task() -> str:
            return await server.negotiate_server({GOSSIPSUB_ID})

        client_result, server_result = await asyncio.gather(
            client_task(),
            server_task(),
        )
        assert client_result == GOSSIPSUB_ID
        assert server_result == GOSSIPSUB_ID


@dataclass
class _MockStream:
    """In-memory stream for testing.

    Two instances cross-connected via asyncio queues simulate a
    bidirectional QUIC stream pair.
    """

    _read_queue: asyncio.Queue[bytes] = field(default_factory=asyncio.Queue)
    _write_queue: asyncio.Queue[bytes] | None = None

    async def read(self) -> bytes:
        """Read next chunk from the queue."""
        return await self._read_queue.get()

    async def write(self, data: bytes) -> None:
        """Write data to the peer's read queue."""
        if self._write_queue is not None:
            self._write_queue.put_nowait(data)

    async def finish_write(self) -> None:
        """Signal end of writing."""

    async def close(self) -> None:
        """Close the stream."""


def _create_stream_pair() -> tuple[QuicStreamAdapter, QuicStreamAdapter]:
    """Create a cross-connected pair of QuicStreamAdapters for testing.

    Data written to one adapter is readable from the other.
    """
    a_to_b: asyncio.Queue[bytes] = asyncio.Queue()
    b_to_a: asyncio.Queue[bytes] = asyncio.Queue()

    stream_a = _MockStream(_read_queue=b_to_a, _write_queue=a_to_b)
    stream_b = _MockStream(_read_queue=a_to_b, _write_queue=b_to_a)

    return QuicStreamAdapter(stream_a), QuicStreamAdapter(stream_b)  # type: ignore[arg-type]


async def _write_message(stream: QuicStreamAdapter, message: str) -> None:
    """Write a multistream message to a stream."""
    payload = message.encode("utf-8") + b"\n"
    length_prefix = encode_varint(len(payload))
    stream.write(length_prefix + payload)
    await stream.drain()


async def _read_message(stream: QuicStreamAdapter) -> str:
    """Read a multistream message from a stream."""
    length_bytes = bytearray()
    while True:
        byte = await stream.read(1)
        if not byte:
            raise NegotiationError("Connection closed")
        length_bytes.append(byte[0])
        if byte[0] & 0x80 == 0:
            break

    length, _ = decode_varint(bytes(length_bytes))
    payload = await stream.readexactly(length)

    if not payload.endswith(b"\n"):
        raise NegotiationError("Message must end with newline")

    return payload[:-1].decode("utf-8")
