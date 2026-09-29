"""Result types and parsers for the output of the fixed remote commands.

Nothing here talks to SSH: it only interprets bytes that
``ReadOnlyPolicy``-built commands printed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from ecomops.core.exceptions import SSHTransportError


@dataclass(frozen=True)
class RemoteReadResult:
    data: bytes
    byte_count: int
    truncated: bool


@dataclass(frozen=True)
class RemoteFileStat:
    size_bytes: int
    modified_at: datetime
    is_regular_file: bool
    is_directory: bool = False


@dataclass(frozen=True)
class RemoteFileEntry:
    name: str
    size_bytes: int
    modified_at: datetime


@dataclass(frozen=True)
class RemoteListing:
    entries: list[RemoteFileEntry]
    truncated: bool


FailureReason = Literal["not_found", "permission_denied", "unknown"]


class RemoteCommandFailedError(SSHTransportError):
    """Raised when the fixed remote command exits with a non-zero status.

    ``reason`` is classified from the command's error output, which itself is
    never returned or logged (it can contain remote paths).
    """

    def __init__(self, message: str, *, reason: FailureReason = "unknown") -> None:
        super().__init__(message)
        self.reason: FailureReason = reason


@dataclass(frozen=True)
class RemoteFileMissing:
    """A file check that failed, with the classified reason."""

    reason: FailureReason


def classify_failure(stderr: bytes) -> FailureReason:
    """Map a failed command's error output to a reason; the text is discarded."""
    if b"Permission denied" in stderr:
        return "permission_denied"
    if b"No such file or directory" in stderr:
        return "not_found"
    return "unknown"


def parse_stat(data: bytes, *, expected_lines: int) -> RemoteFileStat:
    refused = RemoteFileStat(
        size_bytes=0,
        modified_at=datetime.fromtimestamp(0, tz=UTC),
        is_regular_file=False,
    )
    lines = data.decode("utf-8", errors="replace").splitlines()
    if len(lines) != expected_lines:
        return refused
    rows = [line.split(" ") for line in lines]
    if any(len(row) != 3 for row in rows):
        return refused
    if any(row[0] != "d" for row in rows[:-1]):
        return refused
    file_type, size, mtime = rows[-1]
    if file_type not in {"f", "d"}:
        return refused
    try:
        return RemoteFileStat(
            size_bytes=int(size),
            modified_at=datetime.fromtimestamp(float(mtime), tz=UTC),
            is_regular_file=file_type == "f",
            is_directory=file_type == "d",
        )
    except ValueError:
        return refused


def parse_listing_line(line: bytes) -> RemoteFileEntry | None:
    parts = line.decode("utf-8", errors="replace").split(" ", 2)
    if len(parts) != 3:
        return None
    mtime, size, name = parts
    if not name or "/" in name or any(ord(char) < 32 for char in name):
        return None
    try:
        return RemoteFileEntry(
            name=name,
            size_bytes=int(size),
            modified_at=datetime.fromtimestamp(float(mtime), tz=UTC),
        )
    except ValueError:
        return None
