from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ecomops.config.schema import LogAliasConfig, SSHConnectionConfig
from ecomops.core.exceptions import SSHTransportError
from ecomops.logs.sources import ReadLimits
from ecomops.logs.time_ranges import TimeRange
from ecomops.ssh.client import ParamikoSSHClient, RemoteReadResult
from ecomops.ssh.fetcher import SSHLogSource

NOW = datetime(2026, 9, 3, 12, 30, tzinfo=UTC)


class RejectPolicySentinel:
    pass


class FakeChannel:
    def __init__(
        self,
        chunks: list[bytes | BaseException],
        *,
        exit_status: int = 0,
    ) -> None:
        self._chunks = list(chunks)
        self._exit_status = exit_status
        self.commands: list[str] = []
        self.recv_sizes: list[int] = []
        self.timeouts: list[float] = []
        self.closed = False
        self.tty_requested = False
        self.agent_forwarding_requested = False
        self.x11_forwarding_requested = False

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def exec_command(self, command: str) -> None:
        self.commands.append(command)

    def recv(self, size: int) -> bytes:
        self.recv_sizes.append(size)
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        if len(chunk) <= size:
            return chunk
        self._chunks.insert(0, chunk[size:])
        return chunk[:size]

    def exit_status_ready(self) -> bool:
        return not self._chunks

    def recv_exit_status(self) -> int:
        return self._exit_status

    def get_pty(self) -> None:
        self.tty_requested = True
        raise AssertionError("TTY must not be requested")

    def request_forward_agent(self, handler: object) -> None:
        self.agent_forwarding_requested = True
        raise AssertionError("Agent forwarding must not be requested")

    def request_x11(self) -> None:
        self.x11_forwarding_requested = True
        raise AssertionError("X11 forwarding must not be requested")

    def close(self) -> None:
        self.closed = True


class FakeTransport:
    def __init__(self, channel: FakeChannel) -> None:
        self.channel = channel
        self.open_session_timeouts: list[float] = []
        self.port_forwarding_requested = False

    def open_session(self, timeout: float | None = None) -> FakeChannel:
        assert timeout is not None
        self.open_session_timeouts.append(timeout)
        return self.channel

    def request_port_forward(self, address: str, port: int) -> None:
        self.port_forwarding_requested = True
        raise AssertionError("Port forwarding must not be requested")


class FakeSSHClient:
    def __init__(
        self,
        transport: FakeTransport,
        *,
        connect_error: BaseException | None = None,
    ) -> None:
        self.transport = transport
        self.connect_error = connect_error
        self.system_host_keys_loaded = False
        self.loaded_host_key_files: list[str] = []
        self.missing_host_key_policies: list[object] = []
        self.connect_calls: list[dict[str, object]] = []
        self.closed = False
        self.sftp_opened = False

    def load_system_host_keys(self) -> None:
        self.system_host_keys_loaded = True

    def load_host_keys(self, filename: str) -> None:
        self.loaded_host_key_files.append(filename)

    def set_missing_host_key_policy(self, policy: object) -> None:
        self.missing_host_key_policies.append(policy)

    def connect(self, **kwargs: object) -> None:
        self.connect_calls.append(kwargs)
        if self.connect_error is not None:
            raise self.connect_error

    def get_transport(self) -> FakeTransport:
        return self.transport

    def open_sftp(self) -> None:
        self.sftp_opened = True
        raise AssertionError("SFTP must not be opened")

    def close(self) -> None:
        self.closed = True


class FakeParamiko:
    def __init__(self, ssh_client: FakeSSHClient) -> None:
        self.ssh_client = ssh_client
        self.reject_policy = RejectPolicySentinel()

    def SSHClient(self) -> FakeSSHClient:
        return self.ssh_client

    def RejectPolicy(self) -> RejectPolicySentinel:
        return self.reject_policy


def connection(known_hosts_path: Path | None = None) -> SSHConnectionConfig:
    return SSHConnectionConfig(
        type="ssh",
        host="logs.example.test",
        user="readonly",
        port=2222,
        key_path=Path("/keys/read-only"),
        known_hosts_path=known_hosts_path,
    )


def paramiko_client(
    channel: FakeChannel,
    *,
    known_hosts_path: Path | None = None,
    connect_error: BaseException | None = None,
) -> tuple[ParamikoSSHClient, FakeSSHClient, FakeTransport, FakeParamiko]:
    transport = FakeTransport(channel)
    ssh_client = FakeSSHClient(transport, connect_error=connect_error)
    module = FakeParamiko(ssh_client)
    client = ParamikoSSHClient(connection(known_hosts_path), paramiko_module=module)
    return client, ssh_client, transport, module


def test_paramiko_transport_verifies_hosts_and_uses_bounded_session() -> None:
    channel = FakeChannel([b"one\ntwo\n", b""])
    client, ssh_client, transport, module = paramiko_client(
        channel, known_hosts_path=Path("/keys/known_hosts")
    )

    result = client.read_tail(
        "/var/log/app.log", max_lines=2, max_bytes=64, timeout_seconds=7
    )

    assert result == RemoteReadResult(data=b"one\ntwo\n", byte_count=8, truncated=False)
    assert ssh_client.system_host_keys_loaded is True
    assert ssh_client.loaded_host_key_files == ["/keys/known_hosts"]
    assert ssh_client.missing_host_key_policies == [module.reject_policy]
    assert ssh_client.connect_calls == [
        {
            "hostname": "logs.example.test",
            "port": 2222,
            "username": "readonly",
            "key_filename": "/keys/read-only",
            "timeout": 7,
            "banner_timeout": 7,
            "auth_timeout": 7,
            "channel_timeout": 7,
            "allow_agent": True,
            "look_for_keys": True,
        }
    ]
    assert transport.open_session_timeouts == [7]
    assert channel.timeouts == [7]
    assert channel.commands == ["tail --lines 3 -- /var/log/app.log"]
    assert channel.recv_sizes
    assert max(channel.recv_sizes) <= 64
    assert channel.closed is True
    assert ssh_client.closed is True
    assert channel.tty_requested is False
    assert channel.agent_forwarding_requested is False
    assert channel.x11_forwarding_requested is False
    assert transport.port_forwarding_requested is False
    assert ssh_client.sftp_opened is False


def test_paramiko_transport_closes_at_line_limit_and_keeps_latest_lines() -> None:
    channel = FakeChannel([b"one\ntwo\nthree\n"])
    client, ssh_client, _, _ = paramiko_client(channel)

    result = client.read_tail(
        "/var/log/app.log", max_lines=2, max_bytes=100, timeout_seconds=5
    )

    assert result == RemoteReadResult(
        data=b"two\nthree\n", byte_count=14, truncated=True
    )
    assert channel.closed is True
    assert ssh_client.closed is True


def test_paramiko_transport_closes_at_byte_limit_without_partial_line() -> None:
    channel = FakeChannel([b"one\ntwo\nthree\n"])
    client, ssh_client, _, _ = paramiko_client(channel)

    result = client.read_tail(
        "/var/log/app.log", max_lines=10, max_bytes=10, timeout_seconds=5
    )

    assert result == RemoteReadResult(data=b"one\ntwo\n", byte_count=10, truncated=True)
    assert channel.recv_sizes == [10]
    assert channel.closed is True
    assert ssh_client.closed is True


def test_paramiko_transport_closes_on_timeout_and_marks_partial_read() -> None:
    channel = FakeChannel([b"one\n", TimeoutError("timed out")])
    client, ssh_client, _, _ = paramiko_client(channel)

    result = client.read_tail(
        "/var/log/app.log", max_lines=10, max_bytes=100, timeout_seconds=5
    )

    assert result == RemoteReadResult(data=b"one\n", byte_count=4, truncated=True)
    assert channel.closed is True
    assert ssh_client.closed is True


def test_transport_failure_does_not_log_or_expose_credentials(
    caplog: pytest.LogCaptureFixture,
) -> None:
    credential = "not-a-real-secret"
    channel = FakeChannel([])
    client, ssh_client, _, _ = paramiko_client(
        channel, connect_error=RuntimeError(f"password={credential}")
    )

    with (
        caplog.at_level(logging.DEBUG),
        pytest.raises(
            SSHTransportError, match="SSH connection or read failed"
        ) as raised,
    ):
        client.read_tail(
            "/var/log/app.log", max_lines=10, max_bytes=100, timeout_seconds=5
        )

    assert credential not in str(raised.value)
    assert credential not in caplog.text
    assert ssh_client.closed is True


class FakeTailClient:
    def __init__(self, result: RemoteReadResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def read_tail(
        self,
        path: str,
        *,
        max_lines: int,
        max_bytes: int,
        timeout_seconds: int,
    ) -> RemoteReadResult:
        self.calls.append(
            {
                "path": path,
                "max_lines": max_lines,
                "max_bytes": max_bytes,
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.result


def test_ssh_log_source_consumes_task_two_interfaces_and_filters_range() -> None:
    remote = FakeTailClient(
        RemoteReadResult(
            data=(
                b"[2026-09-03 09:00:00] ERROR: old\n"
                b"[2026-09-03 12:00:00] ERROR: recent\n"
            ),
            byte_count=79,
            truncated=True,
        )
    )
    source = SSHLogSource(connection(), client=remote)
    alias = LogAliasConfig(path="/var/log/app.log", type="php")
    limits = ReadLimits(max_lines=50, max_bytes=1_000, timeout_seconds=9)

    result = source.read(alias, limits, TimeRange.parse("1h", NOW))

    assert remote.calls == [
        {
            "path": "/var/log/app.log",
            "max_lines": 50,
            "max_bytes": 1_000,
            "timeout_seconds": 9,
        }
    ]
    assert [entry.message for entry in result.entries] == ["recent"]
    assert [entry.line_number for entry in result.entries] == [None]
    assert result.line_count == 1
    assert result.byte_count == 79
    assert result.truncated is True
    assert result.actual_range == TimeRange(
        start=datetime(2026, 9, 3, 12, 0, tzinfo=UTC),
        end=datetime(2026, 9, 3, 12, 0, tzinfo=UTC),
    )


def test_ssh_log_source_marks_exact_historical_selection_incomplete() -> None:
    remote = FakeTailClient(
        RemoteReadResult(
            data=b"[2026-09-03 10:15:00] ERROR: matching\n",
            byte_count=43,
            truncated=False,
        )
    )
    source = SSHLogSource(connection(), client=remote)

    result = source.read(
        LogAliasConfig(path="/var/log/app.log", type="php"),
        ReadLimits(max_lines=50, max_bytes=1_000, timeout_seconds=9),
        TimeRange.parse("2026-09-03T10:00:00Z", NOW),
    )

    assert result.truncated is True
