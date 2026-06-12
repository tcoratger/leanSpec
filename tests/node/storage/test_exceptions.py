"""Tests for the storage exception hierarchy."""

from __future__ import annotations

from lean_spec.node.storage.exceptions import (
    StorageCorruptionError,
    StorageError,
    StorageReadError,
    StorageWriteError,
)


class TestStorageExceptionHierarchy:
    """Tests for the inheritance structure of storage exceptions."""

    def test_base_error_subclasses_only_exception(self) -> None:
        """The base storage error derives from the builtin Exception and nothing else."""
        assert StorageError.__bases__ == (Exception,)

    def test_read_error_subclasses_base_error(self) -> None:
        """The read error derives directly from the storage base error."""
        assert StorageReadError.__bases__ == (StorageError,)

    def test_write_error_subclasses_base_error(self) -> None:
        """The write error derives directly from the storage base error."""
        assert StorageWriteError.__bases__ == (StorageError,)

    def test_corruption_error_subclasses_base_error(self) -> None:
        """The corruption error derives directly from the storage base error."""
        assert StorageCorruptionError.__bases__ == (StorageError,)

    def test_every_specific_error_is_catchable_as_base_error(self) -> None:
        """Each specific storage error is reachable through the common base type."""
        assert issubclass(StorageReadError, StorageError)
        assert issubclass(StorageWriteError, StorageError)
        assert issubclass(StorageCorruptionError, StorageError)


class TestStorageExceptionMessages:
    """Tests for message handling on storage exceptions."""

    def test_read_error_reports_its_message(self) -> None:
        """The read error reports the exact message it was raised with."""
        raised = StorageReadError("block 0x1234 not found")
        assert str(raised) == "block 0x1234 not found"

    def test_write_error_reports_its_message(self) -> None:
        """The write error reports the exact message it was raised with."""
        raised = StorageWriteError("database is locked")
        assert str(raised) == "database is locked"

    def test_corruption_error_reports_its_message(self) -> None:
        """The corruption error reports the exact message it was raised with."""
        raised = StorageCorruptionError("stored block failed SSZ deserialization")
        assert str(raised) == "stored block failed SSZ deserialization"
