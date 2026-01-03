"""Tests for networking type definitions."""

from lean_spec.subspecs.networking.types import (
    DisconnectReason,
    DomainType,
    ForkDigest,
    NodeId,
    PeerState,
    ResponseCode,
    SeqNumber,
    SubnetId,
    ValidationResult,
)
from lean_spec.types import Uint64
from lean_spec.types.byte_arrays import Bytes4, Bytes32


class TestDomainType:
    """Tests for DomainType."""

    def test_valid_domain(self) -> None:
        """Valid 4-byte domains are accepted."""
        valid: DomainType = Bytes4(b"\x00\x00\x00\x00")
        assert len(valid) == 4

        valid2: DomainType = Bytes4(b"\x01\x00\x00\x00")
        assert len(valid2) == 4


class TestNodeId:
    """Tests for NodeId."""

    def test_valid_node_id(self) -> None:
        """Valid 32-byte node IDs are accepted."""
        valid: NodeId = Bytes32(b"\x00" * 32)
        assert len(valid) == 32

    def test_node_id_from_hex(self) -> None:
        """NodeId can be created from hex string."""
        hex_str = "a" * 64
        node_id: NodeId = Bytes32(bytes.fromhex(hex_str))
        assert len(node_id) == 32


class TestForkDigest:
    """Tests for ForkDigest."""

    def test_valid_fork_digest(self) -> None:
        """Valid 4-byte fork digests are accepted."""
        valid: ForkDigest = Bytes4(b"\x12\x34\x56\x78")
        assert len(valid) == 4


class TestSubnetId:
    """Tests for SubnetId."""

    def test_valid_subnet_ids(self) -> None:
        """Valid subnet IDs (0-63) are accepted."""
        for i in range(64):
            subnet: SubnetId = Uint64(i)
            assert Uint64(0) <= subnet < Uint64(64)

    def test_boundary_values(self) -> None:
        """Boundary values are handled correctly."""
        min_subnet: SubnetId = Uint64(0)
        max_subnet: SubnetId = Uint64(63)
        assert min_subnet == Uint64(0)
        assert max_subnet == Uint64(63)


class TestSeqNumber:
    """Tests for SeqNumber (SSZ Uint64)."""

    def test_valid_seq_numbers(self) -> None:
        """Valid sequence numbers are accepted."""
        seq: SeqNumber = Uint64(0)
        assert seq >= Uint64(0)

        seq2: SeqNumber = Uint64(42)
        assert seq2 == Uint64(42)

    def test_large_seq_number(self) -> None:
        """Large sequence numbers near max are valid."""
        large_seq: SeqNumber = Uint64(2**64 - 2)
        assert large_seq == Uint64(2**64 - 2)


class TestResponseCode:
    """Tests for ResponseCode enumeration."""

    def test_success_code(self) -> None:
        """SUCCESS is code 0."""
        assert ResponseCode.SUCCESS == 0

    def test_error_codes(self) -> None:
        """Error codes have expected values."""
        assert ResponseCode.INVALID_REQUEST == 1
        assert ResponseCode.SERVER_ERROR == 2
        assert ResponseCode.RESOURCE_UNAVAILABLE == 3
        assert ResponseCode.RATE_LIMITED == 4


class TestDisconnectReason:
    """Tests for DisconnectReason enumeration."""

    def test_normal_disconnect_codes(self) -> None:
        """Normal disconnect codes have expected values."""
        assert DisconnectReason.CLIENT_SHUTDOWN == 1
        assert DisconnectReason.IRRELEVANT_NETWORK == 2
        assert DisconnectReason.FAULT_OR_ERROR == 3

    def test_extended_disconnect_codes(self) -> None:
        """Extended disconnect codes have expected values."""
        assert DisconnectReason.UNABLE_TO_VERIFY == 128
        assert DisconnectReason.TOO_MANY_PEERS == 129
        assert DisconnectReason.SCORE_TOO_LOW == 250
        assert DisconnectReason.BANNED == 251


class TestPeerState:
    """Tests for PeerState enumeration."""

    def test_state_progression(self) -> None:
        """Peer states can be compared for progression."""
        states = [
            PeerState.DISCONNECTED,
            PeerState.CONNECTING,
            PeerState.CONNECTED,
            PeerState.HANDSHAKING,
            PeerState.ACTIVE,
            PeerState.DISCONNECTING,
        ]
        # All states are distinct
        assert len(set(states)) == 6


class TestValidationResult:
    """Tests for ValidationResult enumeration."""

    def test_all_results_distinct(self) -> None:
        """All validation results are distinct."""
        results = [ValidationResult.ACCEPT, ValidationResult.REJECT, ValidationResult.IGNORE]
        assert len(set(results)) == 3

    def test_accept_for_valid_messages(self) -> None:
        """ACCEPT is used for valid messages."""
        result = ValidationResult.ACCEPT
        assert result == ValidationResult.ACCEPT

    def test_reject_for_invalid_messages(self) -> None:
        """REJECT is used for invalid messages."""
        result = ValidationResult.REJECT
        assert result == ValidationResult.REJECT

    def test_ignore_for_duplicates(self) -> None:
        """IGNORE is used for duplicates."""
        result = ValidationResult.IGNORE
        assert result == ValidationResult.IGNORE
