from __future__ import annotations

import importlib
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, cast

from ecomops.config.loader import validate_file_permissions
from ecomops.config.schema import SSHConnectionConfig
from ecomops.core.exceptions import (
    ConfigurationError,
    SSHPermissionDeniedError,
    SSHTransportError,
)

from .read_only import MAX_LIST_ENTRIES, MAX_READ_LINES, ReadOnlyPolicy

_LOGGER = logging.getLogger(__name__)
_RECV_CHUNK_SIZE = 64
_STAT_MAX_BYTES = 256
_STDERR_MAX_BYTES = 512
_LIST_ENTRY_MAX_BYTES = 512


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


class _Channel(Protocol):
    def settimeout(self, timeout: float) -> None: ...

    def exec_command(self, command: str) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def recv_stderr(self, size: int) -> bytes: ...

    def exit_status_ready(self) -> bool: ...

    def recv_exit_status(self) -> int: ...

    def close(self) -> None: ...


class _Transport(Protocol):
    def open_session(self, timeout: float | None = None) -> _Channel: ...


class _SSHClient(Protocol):
    def load_system_host_keys(self) -> None: ...

    def load_host_keys(self, filename: str) -> None: ...

    def set_missing_host_key_policy(self, policy: object) -> None: ...

    def connect(self, **kwargs: object) -> None: ...

    def get_transport(self) -> _Transport | None: ...

    def close(self) -> None: ...


class _ParamikoModule(Protocol):
    def SSHClient(self) -> _SSHClient: ...

    def RejectPolicy(self) -> object: ...


class ParamikoSSHClient:
    """Read one bounded tail through a direct, non-interactive SSH channel."""

    def __init__(
        self,
        connection: SSHConnectionConfig,
        *,
        paramiko_module: _ParamikoModule | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._connection = connection
        self._paramiko = paramiko_module or _load_paramiko()
        self._monotonic = monotonic

    def read_tail(
        self,
        path: str,
        *,
        max_lines: int,
        max_bytes: int,
        timeout_seconds: int,
        password: str | None = None,
    ) -> RemoteReadResult:
        if isinstance(max_lines, bool) or not isinstance(max_lines, int):
            raise ValueError("max_lines must be a positive integer")
        if max_lines <= 0 or max_lines > MAX_READ_LINES:
            raise ValueError(f"max_lines must be between 1 and {MAX_READ_LINES}")
        if max_bytes <= 0:
            raise ValueError("max_bytes must be greater than zero")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        command = ReadOnlyPolicy.build_tail_bytes_command(path, max_bytes)
        return self._execute(
            command,
            max_lines=max_lines,
            max_bytes=max_bytes,
            timeout_seconds=timeout_seconds,
            password=password,
            failure_message="Remote tail command failed",
        )

    def stat_file(
        self,
        path: str,
        *,
        timeout_seconds: int,
        password: str | None = None,
        parents: Sequence[str] = (),
    ) -> RemoteFileStat | RemoteFileMissing:
        """Return metadata without following symlinks, or why it is unavailable.

        ``parents`` are folders between the allowed log folder and ``path``;
        if any of them, or ``path`` itself, is a symlink, the result has
        ``is_regular_file=False`` and ``is_directory=False``.
        """
        command = ReadOnlyPolicy.build_file_check_command(path, parents)
        try:
            result = self._execute(
                command,
                max_lines=len(parents) + 1,
                max_bytes=_STAT_MAX_BYTES * (len(parents) + 1),
                timeout_seconds=timeout_seconds,
                password=password,
                failure_message="Remote file check command failed",
            )
        except RemoteCommandFailedError as error:
            return RemoteFileMissing(reason=error.reason)
        return _parse_stat(result.data, expected_lines=len(parents) + 1)

    def list_files(
        self,
        directory: str,
        pattern: str,
        *,
        timeout_seconds: int,
        password: str | None = None,
    ) -> RemoteListing:
        """List regular files matching ``pattern`` directly inside ``directory``."""
        command = ReadOnlyPolicy.build_list_command(directory, pattern)
        result = self._execute(
            command,
            max_lines=MAX_LIST_ENTRIES,
            max_bytes=MAX_LIST_ENTRIES * _LIST_ENTRY_MAX_BYTES,
            timeout_seconds=timeout_seconds,
            password=password,
            failure_message="Remote listing command failed",
        )
        entries = [
            entry
            for line in result.data.splitlines()
            if (entry := _parse_listing_line(line)) is not None
        ]
        return RemoteListing(entries=entries, truncated=result.truncated)

    def _execute(
        self,
        command: str,
        *,
        max_lines: int,
        max_bytes: int,
        timeout_seconds: int,
        password: str | None,
        failure_message: str,
    ) -> RemoteReadResult:
        """Run one command built by ``ReadOnlyPolicy`` over a fresh channel."""
        deadline = self._monotonic() + timeout_seconds
        client: _SSHClient | None = None
        channel: _Channel | None = None

        try:
            client = self._paramiko.SSHClient()
            client.load_system_host_keys()
            if self._connection.known_hosts_path is not None:
                validate_file_permissions(self._connection.known_hosts_path)
                client.load_host_keys(str(self._connection.known_hosts_path))
            client.set_missing_host_key_policy(self._paramiko.RejectPolicy())
            client.connect(
                **self._connection_arguments(
                    _remaining_timeout(deadline, self._monotonic),
                    password=password,
                )
            )

            transport = client.get_transport()
            if transport is None:
                raise SSHTransportError("SSH connection did not provide a transport")
            channel = transport.open_session(
                timeout=_remaining_timeout(deadline, self._monotonic)
            )
            channel.settimeout(_remaining_timeout(deadline, self._monotonic))
            channel.exec_command(command)
            return _read_bounded_channel(
                channel,
                max_lines=max_lines,
                max_bytes=max_bytes,
                deadline=deadline,
                monotonic=self._monotonic,
                failure_message=failure_message,
            )
        except (ConfigurationError, SSHTransportError):
            raise
        except Exception as error:
            _LOGGER.debug("SSH remote log read failed")
            if _is_permission_error(error):
                raise SSHPermissionDeniedError("SSH permission denied") from error
            raise SSHTransportError("SSH connection or read failed") from error
        finally:
            _close_quietly(channel, "channel")
            _close_quietly(client, "client")

    def _connection_arguments(
        self, timeout_seconds: float, *, password: str | None = None
    ) -> dict[str, object]:
        arguments: dict[str, object] = {
            "hostname": self._connection.host,
            "port": self._connection.port,
            "username": self._connection.user,
            "timeout": timeout_seconds,
            "banner_timeout": timeout_seconds,
            "auth_timeout": timeout_seconds,
            "channel_timeout": timeout_seconds,
            "allow_agent": password is None and self._connection.key_path is None,
            "look_for_keys": password is None and self._connection.key_path is None,
        }
        if password is not None:
            arguments["password"] = password
        if self._connection.key_path is not None:
            arguments["key_filename"] = str(self._connection.key_path)
        return arguments


def _load_paramiko() -> _ParamikoModule:
    return cast(_ParamikoModule, importlib.import_module("paramiko"))


def _remaining_timeout(deadline: float, monotonic: Callable[[], float]) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise SSHTransportError("SSH operation timed out")
    return remaining


def _is_permission_error(error: Exception) -> bool:
    return isinstance(error, PermissionError) or error.__class__.__name__ in {
        "AuthenticationException",
        "BadAuthenticationType",
        "PasswordRequiredException",
    }


def _close_quietly(resource: _Channel | _SSHClient | None, name: str) -> None:
    if resource is None:
        return
    try:
        resource.close()
    except Exception:
        _LOGGER.debug("SSH %s cleanup failed", name)


def _read_bounded_channel(
    channel: _Channel,
    *,
    max_lines: int,
    max_bytes: int,
    deadline: float,
    monotonic: Callable[[], float],
    failure_message: str,
) -> RemoteReadResult:
    chunks: list[bytes] = []
    byte_count = 0
    newline_count = 0
    truncated = False
    completed = False

    while byte_count < max_bytes:
        try:
            channel.settimeout(_remaining_timeout(deadline, monotonic))
        except SSHTransportError:
            truncated = True
            break
        try:
            chunk = channel.recv(min(_RECV_CHUNK_SIZE, max_bytes - byte_count))
        except TimeoutError:
            truncated = True
            break

        if not chunk:
            completed = True
            if channel.exit_status_ready() and channel.recv_exit_status() != 0:
                raise RemoteCommandFailedError(
                    failure_message, reason=_failure_reason(channel)
                )
            break

        chunks.append(chunk)
        byte_count += len(chunk)
        newline_count += chunk.count(b"\n")
        if newline_count > max_lines:
            truncated = True
            break

    if byte_count == max_bytes:
        truncated = True

    data = b"".join(chunks)
    lines = data.splitlines(keepends=True)
    if not completed and lines and not lines[-1].endswith((b"\n", b"\r")):
        lines = lines[:-1]
    if len(lines) > max_lines:
        truncated = True
        lines = lines[-max_lines:]

    return RemoteReadResult(
        data=b"".join(lines), byte_count=byte_count, truncated=truncated
    )


def _failure_reason(channel: _Channel) -> FailureReason:
    """Classify a failed command from at most ``_STDERR_MAX_BYTES`` of stderr."""
    stderr = b""
    try:
        while len(stderr) < _STDERR_MAX_BYTES:
            chunk = channel.recv_stderr(_STDERR_MAX_BYTES - len(stderr))
            if not chunk:
                break
            stderr += chunk
    except (TimeoutError, OSError):
        return "unknown"
    if b"Permission denied" in stderr:
        return "permission_denied"
    if b"No such file or directory" in stderr:
        return "not_found"
    return "unknown"


def _parse_stat(data: bytes, *, expected_lines: int) -> RemoteFileStat:
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


def _parse_listing_line(line: bytes) -> RemoteFileEntry | None:
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
