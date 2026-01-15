"""Validator service module for producing blocks and attestations."""

from .registry import ValidatorRegistry
from .service import ValidatorService

__all__ = [
    "ValidatorService",
    "ValidatorRegistry",
]
