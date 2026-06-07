"""Base definitions for consensus test formats: input specs and emitted fixtures."""

import hashlib
import json
from abc import abstractmethod
from functools import cached_property
from typing import Any, ClassVar, Self

from pydantic import Field

from consensus_testing.rejection import classify_rejection
from lean_spec.base import CamelModel
from lean_spec.config import LEAN_ENV
from lean_spec.spec.forks import RejectionReason


class FixtureInfo(CamelModel):
    """Metadata envelope emitted alongside every fixture."""

    model_config = CamelModel.model_config | {"frozen": True}

    comment: str = "`leanSpec` generated test"
    """Provenance note for consumers."""

    test_id: str
    """Unique identifier for the test case."""

    description: str
    """Human-readable description of the test."""

    fixture_format: str
    """Name of the fixture format that produced this vector."""

    key_set_digest: str
    """
    Digest of the XMSS key set used during generation.

    Why: consumers can detect vectors generated from a different key set.
    """


class ExpectedRejection(CamelModel):
    """
    Author-side expectation that an input must be rejected.

    One channel for every format's negative path.
    The reason is the language-neutral contract clients assert against.
    The optional substring pins the rejection to a specific spec assertion.
    """

    model_config = CamelModel.model_config | {"frozen": True}

    reason: RejectionReason
    """Reason the vector's input must be rejected."""

    message_substring: str | None = None
    """
    Substring the raised exception message must contain.

    When None, any exception classified to the expected reason is accepted.
    Fill-time self-check only; never serialized into vectors.
    """


class BaseConsensusFixture(CamelModel):
    """
    Base class for all consensus test fixtures.

    A fixture is the frozen, serializable result of generating a test.
    Input specs produce one; nothing mutates it afterwards.

    Provides:
    - JSON serialization with custom encoders
    - Hash generation for fixtures
    - Common metadata handling
    """

    model_config = CamelModel.model_config | {"frozen": True}

    format_name: ClassVar[str] = ""
    """The name of this fixture format (e.g., 'state_transition_test')."""

    network: str | None = None
    """The fork/network this fixture is valid for (e.g., 'Devnet', 'Shanghai')."""

    lean_env: str = Field(default=LEAN_ENV)
    """The target lean environment (e.g. 'test' or 'prod')."""

    info: FixtureInfo | None = Field(default=None, exclude=True)
    """Metadata about the test (description, fork, etc.)."""

    rejection_reason: RejectionReason | None = None
    """
    Language-neutral reason the vector's input must be rejected.

    Filled during generation for negative vectors.
    This is the field clients assert against.
    """

    def with_info(self, info: FixtureInfo, network: str) -> Self:
        """
        Return a copy carrying the metadata envelope and network name.

        Args:
            info: Metadata envelope for the emitted vector.
            network: Name of the fork this vector is valid for.
        """
        return self.model_copy(update={"info": info, "network": network})

    @cached_property
    def json_dict(self) -> dict[str, Any]:
        """
        Return the JSON representation of the fixture.

        Excludes the metadata envelope and converts snake_case to camelCase.
        """
        return self.to_json(exclude_none=True)

    @cached_property
    def hash(self) -> str:
        """
        Generate a deterministic hash for this fixture.

        The hash is computed from the JSON representation to ensure
        consistency across runs.
        """
        json_str = json.dumps(
            self.json_dict,
            sort_keys=True,
            separators=(",", ":"),
        )
        fixture_digest = hashlib.sha256(json_str.encode("utf-8")).hexdigest()
        return f"0x{fixture_digest}"

    def json_dict_with_info(self) -> dict[str, Any]:
        """
        Return JSON representation with the metadata envelope included.

        Returns:
            Dictionary ready for JSON serialization.

        Raises:
            AssertionError: When the metadata envelope was never attached.
        """
        assert self.info is not None, "fixture is missing its metadata envelope"
        dict_with_info = self.json_dict.copy()
        dict_with_info["_info"] = {"hash": self.hash, **self.info.to_json()}
        return dict_with_info


class BaseTestSpec(CamelModel):
    """
    Base class for author-facing test input specs.

    A spec is the frozen description a test author writes.
    Generating it runs the spec code and returns a separate fixture object.
    """

    model_config = CamelModel.model_config | {"frozen": True}

    format_name: ClassVar[str] = ""
    """The name of this fixture format (e.g., 'state_transition_test')."""

    description: ClassVar[str] = "Unknown fixture format"
    """Human-readable description of what this fixture tests."""

    expected_rejection: ExpectedRejection | None = None
    """
    Expected rejection for invalid tests.

    If set, the input must be rejected during processing.
    The test passes only if the rejection matches.
    Never serialized: the emitted contract is the fixture's reason field.
    """

    @abstractmethod
    def generate(self) -> BaseConsensusFixture:
        """
        Run the spec code and return the emitted fixture.

        Raises:
            AssertionError: If processing disagrees with the authored expectations.
        """

    def assert_expected_outcome(self, exception_raised: Exception | None) -> None:
        """
        Compare a self-verification outcome against the configured expectation.

        A spec that self-verifies its own output catches the verifier exception.
        It then hands the caught exception here to decide pass or fail.

        Args:
            exception_raised: The exception the verifier raised, or None on success.

        Raises:
            AssertionError: When the outcome disagrees with the expectation.
        """
        # No expectation means the input is honest and must process cleanly.
        if self.expected_rejection is None:
            if exception_raised is not None:
                raise AssertionError(f"Verifier rejected an honest input: {exception_raised}")
            return

        # An expectation that produced no exception means the flaw went undetected.
        if exception_raised is None:
            raise AssertionError(
                f"Expected rejection {self.expected_rejection.reason} but processing succeeded"
            )

        # A wrong message means the rejection fired for the wrong reason.
        expected_substring = self.expected_rejection.message_substring
        if expected_substring is not None and expected_substring not in str(exception_raised):
            raise AssertionError(
                f"Expected exception message containing {expected_substring!r} "
                f"but got '{exception_raised}'"
            )

    def resolve_rejection_reason(self, exception_raised: Exception) -> RejectionReason:
        """
        Classify a rejection and check it against the authored expectation.

        Args:
            exception_raised: The exception the spec raised for the invalid input.

        Returns:
            The reason emitted into the test vector.

        Raises:
            AssertionError: When the classification contradicts the authored reason.
        """
        classified_reason = classify_rejection(exception_raised)
        if (
            self.expected_rejection is not None
            and classified_reason is not self.expected_rejection.reason
        ):
            raise AssertionError(
                f"Rejection classified as {classified_reason} "
                f"but the test expects {self.expected_rejection.reason}"
            )
        return classified_reason
