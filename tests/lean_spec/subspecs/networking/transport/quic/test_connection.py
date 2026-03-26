"""Tests for QUIC connection, stream, and multiaddr utilities.

Tests verify behavior against RFC 9000 (QUIC) and the libp2p-QUIC/multiaddr specs.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from lean_spec.subspecs.networking.transport.peer_id import PeerId
from lean_spec.subspecs.networking.transport.quic.connection import (
    ConnectionTerminated,
    HandshakeCompleted,
    LibP2PQuicProtocol,
    QuicConnection,
    QuicStream,
    QuicStreamResetError,
    QuicTransportError,
    StreamDataReceived,
    StreamReset,
    is_quic_multiaddr,
    parse_multiaddr,
)
from lean_spec.subspecs.networking.types import ProtocolId

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def peer_a() -> PeerId:
    """Peer ID derived from the Base58 string 'peerA'."""
    return PeerId.from_base58("peerA")


@pytest.fixture
def mock_protocol() -> MagicMock:
    """Mock aioquic protocol with stream tracking and transmit."""
    protocol = MagicMock()
    protocol._quic = MagicMock()
    protocol._quic._streams = {}
    protocol.transmit = MagicMock()
    return protocol


@pytest.fixture
def quic_stream(mock_protocol: MagicMock) -> QuicStream:
    """A QuicStream backed by the mock protocol on stream ID 0."""
    return QuicStream(_protocol=mock_protocol, _stream_id=0)


@pytest.fixture
def quic_connection(mock_protocol: MagicMock, peer_a: PeerId) -> QuicConnection:
    """A QuicConnection backed by the mock protocol."""
    return QuicConnection(
        _protocol=mock_protocol,
        _peer_id=peer_a,
        _remote_addr="/ip4/127.0.0.1/udp/9000/quic-v1",
    )


# ---------------------------------------------------------------------------
# Multiaddr detection — per the multiaddr spec, protocol names are
# case-sensitive and always lowercase.
# ---------------------------------------------------------------------------


class TestIsQuicMultiaddr:
    """Tests for QUIC multiaddr detection per the multiaddr spec."""

    @pytest.mark.parametrize(
        ("multiaddr", "expected"),
        [
            # Valid QUIC multiaddrs (lowercase per spec)
            ("/ip4/127.0.0.1/udp/9000/quic-v1", True),
            ("/ip4/10.0.0.1/udp/4001/quic", True),
            ("/ip4/0.0.0.0/udp/9000/quic-v1/p2p/peerA", True),
            ("/ip6/::1/udp/9000/quic-v1", True),
            # Not QUIC
            ("/ip4/127.0.0.1/tcp/9000", False),
            ("/ip4/127.0.0.1/udp/9000", False),
            ("", False),
            # Uppercase is NOT valid per multiaddr spec — protocol names are
            # case-sensitive and defined in lowercase.
            ("/ip4/127.0.0.1/udp/9000/QUIC-V1", False),
            ("/ip4/127.0.0.1/udp/9000/QUIC", False),
            ("/ip4/127.0.0.1/udp/9000/Quic-V1", False),
        ],
        ids=[
            "quic-v1",
            "quic-legacy",
            "quic-v1-with-peer",
            "ipv6-quic-v1",
            "tcp-not-quic",
            "udp-only-not-quic",
            "empty-string",
            "uppercase-rejected",
            "uppercase-legacy-rejected",
            "mixed-case-rejected",
        ],
    )
    def test_detection(self, multiaddr: str, expected: bool) -> None:
        """Multiaddr is correctly classified as QUIC or non-QUIC."""
        assert is_quic_multiaddr(multiaddr) == expected


# ---------------------------------------------------------------------------
# Multiaddr parsing
# ---------------------------------------------------------------------------


class TestParseMultiaddr:
    """Tests for multiaddr parsing into components."""

    def test_standard_quic_v1(self) -> None:
        """Standard QUIC-v1 multiaddr yields host, port, transport, and no peer."""
        assert parse_multiaddr("/ip4/127.0.0.1/udp/9000/quic-v1") == (
            "127.0.0.1",
            9000,
            "quic",
            None,
        )

    def test_ipv6_quic_v1(self) -> None:
        """IPv6 QUIC multiaddr is parsed correctly per the libp2p-QUIC spec."""
        assert parse_multiaddr("/ip6/::1/udp/9000/quic-v1") == (
            "::1",
            9000,
            "quic",
            None,
        )

    def test_with_peer_id(self, peer_a: PeerId) -> None:
        """Multiaddr with p2p component includes the parsed peer ID."""
        host, port, transport, parsed_peer = parse_multiaddr(
            "/ip4/10.0.0.1/udp/4001/quic-v1/p2p/peerA"
        )
        assert (host, port, transport) == ("10.0.0.1", 4001, "quic")
        assert parsed_peer == peer_a

    def test_legacy_quic(self) -> None:
        """Legacy 'quic' tag is recognized as transport 'quic'."""
        assert parse_multiaddr("/ip4/192.168.1.1/udp/5000/quic") == (
            "192.168.1.1",
            5000,
            "quic",
            None,
        )

    def test_missing_host_raises(self) -> None:
        """Missing ip4/ip6 component raises ValueError."""
        with pytest.raises(ValueError, match=r"No host in multiaddr"):
            parse_multiaddr("/udp/9000/quic-v1")

    def test_missing_port_raises(self) -> None:
        """Missing udp component raises ValueError."""
        with pytest.raises(ValueError, match=r"No port in multiaddr"):
            parse_multiaddr("/ip4/127.0.0.1/quic-v1")

    def test_unknown_components_skipped(self) -> None:
        """Unknown protocol components are silently skipped."""
        assert parse_multiaddr("/ip4/127.0.0.1/unknown/foo/udp/9000/quic-v1") == (
            "127.0.0.1",
            9000,
            "quic",
            None,
        )

    def test_no_quic_tag_returns_none_transport(self) -> None:
        """Multiaddr without quic/quic-v1 component returns None transport."""
        host, port, transport, _ = parse_multiaddr("/ip4/10.0.0.1/udp/3000")
        assert (host, port, transport) == ("10.0.0.1", 3000, None)


# ---------------------------------------------------------------------------
# QuicStream — read behavior per RFC 9000 Section 3
#
# - Data arrives in order per-stream.
# - FIN (end_stream=True) signals graceful half-close — all data delivered.
# - RESET_STREAM signals abrupt termination — data may be lost.
# ---------------------------------------------------------------------------


class TestQuicStreamRead:
    """Tests for reading data from a QUIC stream."""

    async def test_read_returns_buffered_data(self, quic_stream: QuicStream) -> None:
        """Data placed in the buffer is returned by read."""
        quic_stream._receive_data(b"hello")
        assert await quic_stream.read() == b"hello"

    async def test_read_returns_empty_on_fin(self, quic_stream: QuicStream) -> None:
        """FIN (graceful half-close) causes read to return empty bytes."""
        quic_stream._receive_end()
        assert await quic_stream.read() == b""
        # Per RFC 9000, stream is in "Data Read" terminal state.
        assert await quic_stream.read() == b""

    async def test_read_preserves_order(self, quic_stream: QuicStream) -> None:
        """Per RFC 9000, QUIC delivers data in order within a stream."""
        quic_stream._receive_data(b"first")
        quic_stream._receive_data(b"second")
        assert await quic_stream.read() == b"first"
        assert await quic_stream.read() == b"second"

    async def test_read_data_then_fin(self, quic_stream: QuicStream) -> None:
        """Data followed by FIN returns all data, then signals end."""
        quic_stream._receive_data(b"payload")
        quic_stream._receive_end()
        assert await quic_stream.read() == b"payload"
        assert await quic_stream.read() == b""

    async def test_read_after_close_returns_empty(self, quic_stream: QuicStream) -> None:
        """Reading a closed stream returns empty immediately."""
        await quic_stream.close()
        assert await quic_stream.read() == b""


# ---------------------------------------------------------------------------
# QuicStream — RESET_STREAM handling per RFC 9000 Section 3.2
#
# RESET_STREAM is an error/abort, NOT a clean end-of-stream.
# Data may have been lost. The application must be notified.
# ---------------------------------------------------------------------------


class TestQuicStreamReset:
    """Tests for RESET_STREAM error propagation."""

    async def test_reset_raises_on_read(self, quic_stream: QuicStream) -> None:
        """After reset, read raises an error with the error code from the peer."""
        quic_stream._receive_reset(error_code=42)
        with pytest.raises(QuicStreamResetError) as exc_info:
            await quic_stream.read()
        assert exc_info.value.stream_id == 0
        assert exc_info.value.error_code == 42

    async def test_reset_after_data_raises_after_consuming(self, quic_stream: QuicStream) -> None:
        """Data buffered before reset is delivered, then reset error is raised."""
        quic_stream._receive_data(b"partial")
        quic_stream._receive_reset(error_code=7)
        # Buffered data is still returned.
        assert await quic_stream.read() == b"partial"
        # Next read surfaces the reset error.
        with pytest.raises(QuicStreamResetError) as exc_info:
            await quic_stream.read()
        assert exc_info.value.error_code == 7

    async def test_repeated_reads_after_reset_raise(self, quic_stream: QuicStream) -> None:
        """Subsequent reads after reset continue to raise."""
        quic_stream._receive_reset(error_code=0)
        with pytest.raises(QuicStreamResetError):
            await quic_stream.read()
        with pytest.raises(QuicStreamResetError):
            await quic_stream.read()

    def test_reset_error_is_subclass_of_transport_error(self) -> None:
        """Reset error inherits from the base transport error."""
        assert issubclass(QuicStreamResetError, QuicTransportError)


# ---------------------------------------------------------------------------
# QuicStream — write behavior per RFC 9000 Section 3
#
# After FIN is sent (or stream is closed), further writes must fail.
# ---------------------------------------------------------------------------


class TestQuicStreamWrite:
    """Tests for writing data to a QUIC stream."""

    async def test_write_sends_data_and_transmits(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Writing sends data to the QUIC layer and flushes pending frames."""
        await quic_stream.write(b"hello")
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"hello")
        mock_protocol.transmit.assert_called_once()

    async def test_write_after_fin_raises(self, quic_stream: QuicStream) -> None:
        """Per RFC 9000, no data can be sent after FIN (write-side closed)."""
        quic_stream._write_closed = True
        with pytest.raises(QuicTransportError, match=r"Stream write side is closed"):
            await quic_stream.write(b"data")


# ---------------------------------------------------------------------------
# QuicStream — half-close (FIN) per RFC 9000 Section 3
#
# Sending FIN closes the write side. Read side stays open.
# ---------------------------------------------------------------------------


class TestQuicStreamFinishWrite:
    """Tests for half-close via FIN."""

    async def test_finish_write_sends_fin(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Half-close sends a STREAM frame with FIN bit (end_stream=True)."""
        await quic_stream.finish_write()
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"", end_stream=True)
        mock_protocol.transmit.assert_called_once()
        assert quic_stream._write_closed is True
        # Read side stays open (half-close per RFC 9000).
        assert quic_stream._read_closed is False

    async def test_finish_write_is_idempotent(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Sending FIN twice would be a protocol error; idempotency prevents this."""
        await quic_stream.finish_write()
        await quic_stream.finish_write()
        mock_protocol._quic.send_stream_data.assert_called_once()


# ---------------------------------------------------------------------------
# QuicStream — full close (both directions)
# ---------------------------------------------------------------------------


class TestQuicStreamClose:
    """Tests for full stream close (both directions)."""

    async def test_close_sets_all_flags_and_sends_fin(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Closing marks both directions closed and sends FIN."""
        await quic_stream.close()
        assert quic_stream._closed is True
        assert quic_stream._write_closed is True
        assert quic_stream._read_closed is True
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"", end_stream=True)
        mock_protocol.transmit.assert_called_once()

    async def test_close_is_idempotent(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Second close is a no-op — prevents double-FIN."""
        await quic_stream.close()
        await quic_stream.close()
        mock_protocol._quic.send_stream_data.assert_called_once()


# ---------------------------------------------------------------------------
# QuicConnection — event handling per RFC 9000
#
# - StreamDataReceived: data from peer, may create new remote-initiated stream
# - StreamReset: abrupt stream termination by peer
# - ConnectionTerminated: all streams implicitly closed (RFC 9000 Section 10)
# ---------------------------------------------------------------------------


class TestQuicConnectionHandleEvent:
    """Tests for QUIC event dispatch on the connection."""

    def test_stream_data_creates_new_incoming_stream(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Per RFC 9000, receiving data on unknown stream ID creates a remote-initiated stream."""
        event = StreamDataReceived(data=b"hello", end_stream=False, stream_id=4)

        quic_connection._handle_event(event)

        assert 4 in quic_connection._streams
        assert quic_connection._incoming_streams.qsize() == 1
        incoming = quic_connection._incoming_streams.get_nowait()
        assert incoming.stream_id == 4
        assert incoming._read_buffer.get_nowait() == b"hello"

    def test_stream_data_delivers_to_existing_stream(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Data on existing stream is delivered without creating a new one."""
        existing = QuicStream(_protocol=mock_protocol, _stream_id=4)
        quic_connection._streams[4] = existing

        event = StreamDataReceived(data=b"more", end_stream=False, stream_id=4)
        quic_connection._handle_event(event)

        assert quic_connection._incoming_streams.qsize() == 0
        assert existing._read_buffer.get_nowait() == b"more"

    def test_stream_data_with_fin_delivers_data_and_signals_end(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """FIN bit delivers final data and signals graceful half-close."""
        event = StreamDataReceived(data=b"final", end_stream=True, stream_id=8)

        quic_connection._handle_event(event)

        stream = quic_connection._streams[8]
        assert stream._read_buffer.get_nowait() == b"final"
        # FIN sentinel
        assert stream._read_buffer.get_nowait() == b""

    def test_stream_reset_signals_error_not_eof(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Per RFC 9000 Section 3.2, RESET_STREAM is an error, not clean EOF.

        The stream must surface the error code to the application, and
        subsequent reads must raise rather than returning empty bytes.
        """
        existing = QuicStream(_protocol=mock_protocol, _stream_id=4)
        quic_connection._streams[4] = existing

        event = StreamReset(error_code=42, stream_id=4)
        quic_connection._handle_event(event)

        assert existing._reset_error is not None
        assert existing._reset_error.error_code == 42
        assert existing._reset_error.stream_id == 4

    def test_stream_reset_unknown_stream_ignored(self, quic_connection: QuicConnection) -> None:
        """Reset for unknown stream ID is silently ignored (may already be cleaned up)."""
        event = StreamReset(error_code=0, stream_id=999)
        # Must not raise.
        quic_connection._handle_event(event)

    def test_connection_terminated_closes_all_streams(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Per RFC 9000 Section 10, connection termination closes all streams."""
        s1 = QuicStream(_protocol=mock_protocol, _stream_id=0)
        s2 = QuicStream(_protocol=mock_protocol, _stream_id=4)
        quic_connection._streams = {0: s1, 4: s2}

        event = ConnectionTerminated(error_code=0, frame_type=None, reason_phrase="done")
        quic_connection._handle_event(event)

        assert quic_connection._closed is True
        # All streams receive end signal.
        assert s1._read_buffer.get_nowait() == b""
        assert s2._read_buffer.get_nowait() == b""


# ---------------------------------------------------------------------------
# QuicConnection — open/accept/close
# ---------------------------------------------------------------------------


class TestQuicConnectionOpenStream:
    """Tests for opening new streams on a connection."""

    async def test_open_stream_when_closed_raises(self, quic_connection: QuicConnection) -> None:
        """Opening a stream on a closed connection raises an error."""
        quic_connection._closed = True
        with pytest.raises(QuicTransportError, match=r"Connection is closed"):
            await quic_connection.open_stream(ProtocolId("/test/1.0"))


class TestQuicConnectionAcceptStream:
    """Tests for accepting incoming streams."""

    async def test_accept_stream_when_closed_raises(self, quic_connection: QuicConnection) -> None:
        """Accepting a stream on a closed connection raises an error."""
        quic_connection._closed = True
        with pytest.raises(QuicTransportError, match=r"Connection is closed"):
            await quic_connection.accept_stream()

    async def test_accept_stream_returns_queued(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Accepting a stream returns one that was queued via event handling."""
        event = StreamDataReceived(data=b"init", end_stream=False, stream_id=12)
        quic_connection._handle_event(event)

        stream = await quic_connection.accept_stream()
        assert stream.stream_id == 12


class TestQuicConnectionClose:
    """Tests for closing a QUIC connection."""

    async def test_close_marks_closed_and_closes_streams(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Closing sends CONNECTION_CLOSE and closes all streams."""
        s1 = QuicStream(_protocol=mock_protocol, _stream_id=0)
        s2 = QuicStream(_protocol=mock_protocol, _stream_id=4)
        quic_connection._streams = {0: s1, 4: s2}

        await quic_connection.close()

        assert quic_connection._closed is True
        assert s1._closed is True
        assert s2._closed is True
        mock_protocol._quic.close.assert_called_once()
        mock_protocol.transmit.assert_called()

    async def test_close_is_idempotent(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Second close is a no-op — prevents double CONNECTION_CLOSE."""
        await quic_connection.close()
        await quic_connection.close()
        mock_protocol._quic.close.assert_called_once()


# ---------------------------------------------------------------------------
# LibP2PQuicProtocol — handshake, event routing, buffering
#
# Per libp2p-QUIC spec, ALPN protocol is "libp2p".
# Events between handshake completion and connection assignment must be buffered.
# ---------------------------------------------------------------------------


class TestLibP2PQuicProtocol:
    """Tests for the custom QUIC protocol event handler."""

    @pytest.fixture
    def protocol(self) -> LibP2PQuicProtocol:
        """A protocol with mocked parent internals (bypasses aioquic constructor)."""
        proto = LibP2PQuicProtocol.__new__(LibP2PQuicProtocol)
        proto.connection = None
        proto.peer_identity = None
        proto.handshake_complete = asyncio.Event()
        proto._buffered_events = []
        proto._on_handshake = None
        proto._quic = MagicMock()
        proto._quic._streams = {}
        proto.transmit = MagicMock()
        return proto

    def test_handshake_completed_sets_event(self, protocol: LibP2PQuicProtocol) -> None:
        """Handshake completion is signaled so the connection wrapper can proceed."""
        event = HandshakeCompleted(
            alpn_protocol="libp2p", early_data_accepted=False, session_resumed=False
        )
        protocol.quic_event_received(event)
        assert protocol.handshake_complete.is_set()

    def test_server_handshake_invokes_callback(self, protocol: LibP2PQuicProtocol) -> None:
        """Server-side callback is invoked on first handshake (before connection is set)."""
        callback = MagicMock()
        protocol._on_handshake = callback

        event = HandshakeCompleted(
            alpn_protocol="libp2p", early_data_accepted=False, session_resumed=False
        )
        protocol.quic_event_received(event)
        callback.assert_called_once_with(protocol)

    def test_callback_skipped_when_connection_already_exists(
        self, protocol: LibP2PQuicProtocol, mock_protocol: MagicMock, peer_a: PeerId
    ) -> None:
        """Callback is NOT invoked if connection is already assigned (client-side reconnect)."""
        callback = MagicMock()
        protocol._on_handshake = callback
        protocol.connection = QuicConnection(
            _protocol=mock_protocol,
            _peer_id=peer_a,
            _remote_addr="/ip4/127.0.0.1/udp/9000/quic-v1",
        )

        event = HandshakeCompleted(
            alpn_protocol="libp2p", early_data_accepted=False, session_resumed=False
        )
        protocol.quic_event_received(event)
        callback.assert_not_called()

    def test_events_forwarded_to_connection(
        self, protocol: LibP2PQuicProtocol, mock_protocol: MagicMock, peer_a: PeerId
    ) -> None:
        """Events are forwarded to the connection when it is assigned."""
        conn = QuicConnection(
            _protocol=mock_protocol,
            _peer_id=peer_a,
            _remote_addr="/ip4/127.0.0.1/udp/9000/quic-v1",
        )
        protocol.connection = conn

        event = StreamDataReceived(data=b"hello", end_stream=False, stream_id=0)
        protocol.quic_event_received(event)

        assert 0 in conn._streams
        assert conn._streams[0]._read_buffer.get_nowait() == b"hello"

    def test_events_buffered_between_handshake_and_connection(
        self, protocol: LibP2PQuicProtocol
    ) -> None:
        """Events after handshake but before connection assignment are buffered.

        This addresses a real race: the peer may open streams immediately after
        TLS completes, before the application creates the connection wrapper.
        """
        handshake = HandshakeCompleted(
            alpn_protocol="libp2p", early_data_accepted=False, session_resumed=False
        )
        protocol.quic_event_received(handshake)

        stream_event = StreamDataReceived(data=b"buffered", end_stream=False, stream_id=0)
        protocol.quic_event_received(stream_event)

        # HandshakeCompleted itself falls through to the buffering path, plus stream event.
        assert len(protocol._buffered_events) == 2
        assert protocol._buffered_events[1] is stream_event

    def test_events_before_handshake_dropped(self, protocol: LibP2PQuicProtocol) -> None:
        """Events before handshake are dropped (no app data before TLS per QUIC)."""
        event = StreamDataReceived(data=b"early", end_stream=False, stream_id=0)
        protocol.quic_event_received(event)
        assert len(protocol._buffered_events) == 0

    def test_replay_forwards_and_clears_buffered_events(
        self, protocol: LibP2PQuicProtocol, mock_protocol: MagicMock, peer_a: PeerId
    ) -> None:
        """Replaying delivers buffered events to the connection and clears the buffer."""
        handshake = HandshakeCompleted(
            alpn_protocol="libp2p", early_data_accepted=False, session_resumed=False
        )
        protocol.quic_event_received(handshake)

        e1 = StreamDataReceived(data=b"first", end_stream=False, stream_id=0)
        protocol.quic_event_received(e1)
        e2 = StreamDataReceived(data=b"second", end_stream=False, stream_id=0)
        protocol.quic_event_received(e2)

        conn = QuicConnection(
            _protocol=mock_protocol,
            _peer_id=peer_a,
            _remote_addr="/ip4/127.0.0.1/udp/9000/quic-v1",
        )
        protocol.connection = conn
        protocol._replay_buffered_events()

        assert protocol._buffered_events == []
        assert 0 in conn._streams
        assert conn._streams[0]._read_buffer.qsize() == 2

    def test_replay_noop_without_connection(self, protocol: LibP2PQuicProtocol) -> None:
        """Replay is a no-op when connection is not yet assigned."""
        protocol._buffered_events = [MagicMock()]
        protocol._replay_buffered_events()
        assert len(protocol._buffered_events) == 1

    def test_replay_noop_when_empty(
        self, protocol: LibP2PQuicProtocol, mock_protocol: MagicMock, peer_a: PeerId
    ) -> None:
        """Replay is a no-op when there are no buffered events."""
        protocol.connection = QuicConnection(
            _protocol=mock_protocol,
            _peer_id=peer_a,
            _remote_addr="/ip4/127.0.0.1/udp/9000/quic-v1",
        )
        protocol._replay_buffered_events()
        assert protocol._buffered_events == []
