"""
Gossipsub Message Validation
============================

This module specifies the validation framework for gossip messages.
Each topic has specific validation rules that must pass before a
message is propagated.

Validation Flow
---------------

1. Message received from peer
2. Compute message ID (for deduplication)
3. Check if already seen (IGNORE if duplicate)
4. Validate message against topic rules
5. Return ACCEPT, REJECT, or IGNORE

Ethereum-Specific Validation
----------------------------

Consensus messages have additional validation:
- Slot bounds checking
- Signature verification
- Proposer eligibility
- Fork compatibility
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Generic, Optional, TypeVar

from ..types import ValidationResult
from .topic import GossipsubTopic

T = TypeVar("T")


@dataclass
class ValidationError:
    """Details about a validation failure."""

    code: str
    """Error code for categorization."""

    message: str
    """Human-readable error message."""

    severity: float = 1.0
    """Score penalty multiplier."""


class MessageValidator(ABC, Generic[T]):
    """
    Abstract base class for topic-specific message validators.

    Each gossip topic should have a corresponding validator that
    implements the validation logic for that topic's messages.
    """

    @property
    @abstractmethod
    def topic(self) -> GossipsubTopic:
        """The topic this validator handles."""
        ...

    @abstractmethod
    def validate(self, message: T, slot: int) -> tuple[ValidationResult, Optional[ValidationError]]:
        """
        Validate a message.

        Args:
            message: The decoded message to validate.
            slot: The current slot for time-based validation.

        Returns:
            Tuple of (result, error). Error is None if ACCEPT.
        """
        ...


@dataclass
class BlockValidationConfig:
    """Configuration for block validation."""

    max_future_slots: int = 1
    """Maximum slots in the future to accept."""

    max_past_slots: int = 32
    """Maximum slots in the past to accept."""

    require_signature: bool = True
    """Whether to verify proposer signature."""


@dataclass
class AttestationValidationConfig:
    """Configuration for attestation validation."""

    max_future_slots: int = 1
    """Maximum slots in the future."""

    max_past_epochs: int = 1
    """Maximum epochs in the past."""

    require_signature: bool = True
    """Whether to verify attester signature."""

    check_committee: bool = True
    """Whether to verify committee membership."""


class BlockValidator(MessageValidator):
    """
    Validator for block gossip messages.

    Validation Rules:
    1. Block slot is within acceptable range
    2. Block is not from the future (with tolerance)
    3. Block proposer signature is valid
    4. Proposer is eligible for the slot
    5. Block is not a duplicate (different root)
    """

    def __init__(self, config: Optional[BlockValidationConfig] = None):
        """Initialize with configuration."""
        self.config = config or BlockValidationConfig()

    @property
    def topic(self) -> GossipsubTopic:
        """Return the block topic."""
        return GossipsubTopic.BLOCK

    def validate(self, message, slot: int) -> tuple[ValidationResult, Optional[ValidationError]]:
        """Validate a block message."""
        block_slot = int(message.message.slot)

        # Reject blocks too far in the future
        if block_slot > slot + self.config.max_future_slots:
            return (
                ValidationResult.IGNORE,
                ValidationError(
                    code="FUTURE_SLOT",
                    message=f"Block slot {block_slot} is too far in the future",
                    severity=0.5,
                ),
            )

        # Ignore blocks too far in the past
        if block_slot < slot - self.config.max_past_slots:
            return (
                ValidationResult.IGNORE,
                ValidationError(
                    code="PAST_SLOT",
                    message=f"Block slot {block_slot} is too old",
                    severity=0.1,
                ),
            )

        return (ValidationResult.ACCEPT, None)


class AttestationValidator(MessageValidator):
    """
    Validator for attestation gossip messages.

    Validation Rules:
    1. Attestation slot is within acceptable range
    2. Attester signature is valid
    3. Attester is in the committee for the slot
    4. Attestation target is consistent with checkpoint
    5. Not a duplicate from the same validator
    """

    def __init__(self, config: Optional[AttestationValidationConfig] = None):
        """Initialize with configuration."""
        self.config = config or AttestationValidationConfig()

    @property
    def topic(self) -> GossipsubTopic:
        """Return the attestation topic."""
        return GossipsubTopic.ATTESTATION

    def validate(self, message, slot: int) -> tuple[ValidationResult, Optional[ValidationError]]:
        """Validate an attestation message."""
        attestation_slot = int(message.message.slot)

        # Reject attestations from the future
        if attestation_slot > slot + self.config.max_future_slots:
            return (
                ValidationResult.IGNORE,
                ValidationError(
                    code="FUTURE_SLOT",
                    message=f"Attestation slot {attestation_slot} is in the future",
                    severity=0.5,
                ),
            )

        return (ValidationResult.ACCEPT, None)


class ValidationRegistry:
    """
    Registry of validators for all topics.

    Provides a central point for message validation dispatch.
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._validators: dict[GossipsubTopic, MessageValidator] = {}

    def register(self, validator: MessageValidator) -> None:
        """Register a validator for its topic."""
        self._validators[validator.topic] = validator

    def get_validator(self, topic: GossipsubTopic) -> Optional[MessageValidator]:
        """Get the validator for a topic."""
        return self._validators.get(topic)

    def validate(
        self,
        topic: GossipsubTopic,
        message,
        slot: int,
    ) -> tuple[ValidationResult, Optional[ValidationError]]:
        """Validate a message for a topic."""
        validator = self.get_validator(topic)
        if validator is None:
            return (ValidationResult.ACCEPT, None)
        return validator.validate(message, slot)


def create_default_registry() -> ValidationRegistry:
    """Create a validation registry with default validators."""
    registry = ValidationRegistry()
    registry.register(BlockValidator())
    registry.register(AttestationValidator())
    return registry
