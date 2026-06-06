"""Base fixture definitions for consensus test formats."""

import hashlib
import json
from functools import cached_property
from typing import Any, ClassVar

from framework.forks import BaseFork
from pydantic import Field

from consensus_testing.keys import XmssKeyManager
from lean_spec.base import CamelModel
from lean_spec.config import LEAN_ENV
from lean_spec.spec.forks import RejectionReason


class BaseConsensusFixture(CamelModel):
    """
    Base class for all consensus test fixtures.

    Provides:
    - JSON serialization with custom encoders
    - Hash generation for fixtures
    - Common metadata handling
    """

    # Fixture format metadata
    format_name: ClassVar[str] = ""
    """The name of this fixture format (e.g., 'state_transition_test')."""

    description: ClassVar[str] = "Unknown fixture format"
    """Human-readable description of what this fixture tests."""

    # Instance fields
    network: str | None = None
    """The fork/network this fixture is valid for (e.g., 'Devnet', 'Shanghai')."""

    lean_env: str = Field(default=LEAN_ENV)
    """The target lean environment (e.g. 'test' or 'prod')."""

    info: dict[str, Any] = Field(default_factory=dict, alias="_info")
    """Metadata about the test (description, fork, etc.)."""

    expect_exception: type[Exception] | None = Field(default=None, exclude=True)
    """
    Expected exception type for invalid tests.

    If set, the fixture expects this exception during processing.
    The test passes only if the exception is raised.

    Excluded from JSON output: a Python class name means nothing to
    other-language clients. It remains a fill-time self-check only.
    """

    rejection_reason: RejectionReason | None = None
    """
    Language-neutral reason the vector's input must be rejected.

    Filled during generation for negative vectors.
    This is the field clients assert against.
    """

    def assert_expected_outcome(
        self,
        exception_raised: Exception | None,
        expected_message: str | None = None,
    ) -> None:
        """
        Compare a self-verification outcome against the configured expectation.

        A fixture that self-verifies its own output catches the verifier exception.
        It then hands the caught exception here to decide pass or fail.

        Args:
            exception_raised: The exception the verifier raised, or None on success.
            expected_message: Optional exact message the exception must carry.

        Raises:
            AssertionError: When the outcome disagrees with the expectation.
        """
        # No expectation means the bundle is honest and must verify.
        if self.expect_exception is None:
            if exception_raised is not None:
                raise AssertionError(f"Verifier rejected an honest bundle: {exception_raised}")
        # An expectation that produced no exception means the tamper went undetected.
        elif exception_raised is None:
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} but verification succeeded"
            )
        # A wrong exception type means the rejection fired for the wrong reason.
        elif not isinstance(exception_raised, self.expect_exception):
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} but got "
                f"{type(exception_raised).__name__}: {exception_raised}"
            )
        # A wrong message means the rejection fired for the wrong reason.
        elif expected_message is not None and str(exception_raised) != expected_message:
            raise AssertionError(
                f"Expected exception message '{expected_message}' but got '{exception_raised}'"
            )

    @cached_property
    def json_dict(self) -> dict[str, Any]:
        """
        Return the JSON representation of the fixture.

        Excludes the `info` field and converts snake_case to camelCase.
        """
        return self.to_json(
            exclude_none=True,
            exclude={"info"},
        )

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
        h = hashlib.sha256(json_str.encode("utf-8")).hexdigest()
        return f"0x{h}"

    def json_dict_with_info(self) -> dict[str, Any]:
        """
        Return JSON representation with the info field included.

        Returns:
            Dictionary ready for JSON serialization.
        """
        dict_with_info = self.json_dict.copy()
        dict_with_info["_info"] = {"hash": self.hash, **self.info}
        return dict_with_info

    def fill_info(
        self,
        test_id: str,
        description: str,
        fork: BaseFork,
    ) -> None:
        """
        Fill metadata information for this fixture.

        Args:
            test_id: Unique identifier for the test case.
            description: Human-readable description of the test.
            fork: The fork this test is valid for.
        """
        if "comment" not in self.info:
            self.info["comment"] = "`leanSpec` generated test"
        self.info["testId"] = test_id
        self.info["description"] = description
        self.info["fixtureFormat"] = self.format_name

        # Why: consumers can detect vectors generated from a different key set.
        self.info["keySetDigest"] = XmssKeyManager.shared().key_set_digest()

        # Set network field on the fixture itself
        self.network = fork.name()
