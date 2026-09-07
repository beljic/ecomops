from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Protocol, cast

from ecomops.config.schema import SSHConnectionConfig
from ecomops.core.exceptions import SSHTransportError

from .read_only import ReadOnlyPolicy

_LOGGER = logging.getLogger(__name__)
_RECV_CHUNK_SIZE = 64


@dataclass(frozen=True)
class RemoteReadResult:
    data: bytes
    byte_count: int
    truncated: bool


class _Channel(Protocol):
    def settimeout(self, timeout: float) -> None: ...

    def exec_command(self, command: str) -> None: ...

    def recv(self, size: int) -> bytes: ...

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
    ) -> None:
        self._connection = connection
        self._paramiko = paramiko_module or _load_paramiko()

    def read_tail(
        self,
        path: str,
        *,
        max_lines: int,
        max_bytes: int,
        timeout_seconds: int,
    ) -> RemoteReadResult:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be greater than zero")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        command = ReadOnlyPolicy.build_tail_command(path, max_lines + 1)
        client: _SSHClient | None = None
        channel: _Channel | None = None

        try:
            client = self._paramiko.SSHClient()
            client.load_system_host_keys()
            if self._connection.known_hosts_path is not None:
                client.load_host_keys(str(self._connection.known_hosts_path))
            client.set_missing_host_key_policy(self._paramiko.RejectPolicy())
            client.connect(**self._connection_arguments(timeout_seconds))

            transport = client.get_transport()
            if transport is None:
                raise SSHTransportError("SSH connection did not provide a transport")
            channel = transport.open_session(timeout=timeout_seconds)
            channel.settimeout(timeout_seconds)
            channel.exec_command(command)
            return _read_bounded_channel(
                channel, max_lines=max_lines, max_bytes=max_bytes
            )
        except SSHTransportError:
            raise
        except Exception as error:
            _LOGGER.debug("SSH remote log read failed")
            raise SSHTransportError("SSH connection or read failed") from error
        finally:
            if channel is not None:
                channel.close()
            if client is not None:
                client.close()

    def _connection_arguments(self, timeout_seconds: int) -> dict[str, object]:
        arguments: dict[str, object] = {
            "hostname": self._connection.host,
            "port": self._connection.port,
            "username": self._connection.user,
            "timeout": timeout_seconds,
            "banner_timeout": timeout_seconds,
            "auth_timeout": timeout_seconds,
            "channel_timeout": timeout_seconds,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if self._connection.key_path is not None:
            arguments["key_filename"] = str(self._connection.key_path)
        return arguments


def _load_paramiko() -> _ParamikoModule:
    return cast(_ParamikoModule, importlib.import_module("paramiko"))


def _read_bounded_channel(
    channel: _Channel, *, max_lines: int, max_bytes: int
) -> RemoteReadResult:
    chunks: list[bytes] = []
    byte_count = 0
    truncated = False
    completed = False

    while byte_count < max_bytes:
        try:
            chunk = channel.recv(min(_RECV_CHUNK_SIZE, max_bytes - byte_count))
        except TimeoutError:
            truncated = True
            break

        if not chunk:
            completed = True
            if channel.exit_status_ready() and channel.recv_exit_status() != 0:
                raise SSHTransportError("Remote tail command failed")
            break

        chunks.append(chunk)
        byte_count += len(chunk)
        if b"\n".join(chunks).count(b"\n") > max_lines:
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
