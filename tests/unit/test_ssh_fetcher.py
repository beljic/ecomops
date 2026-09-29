from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ecomops.config.schema import LogAliasConfig, SSHConnectionConfig
from ecomops.core.exceptions import (
    ConfigurationError,
    SSHPermissionDeniedError,
    SSHTransportError,
)
from ecomops.core.models import SourceMetadata
from ecomops.logs.sources import ReadLimits
from ecomops.logs.time_ranges import TimeRange
from ecomops.ssh.client import (
    ParamikoSSHClient,
    RemoteCommandFailedError,
    RemoteFileEntry,
    RemoteFileMissing,
    RemoteFileStat,
    RemoteListing,
    RemoteReadResult,
)
from ecomops.ssh.fetcher import SSHLogSource
from ecomops.ssh.read_only import MAX_LIST_ENTRIES

NOW = datetime(2026, 9, 3, 12, 30, tzinfo=UTC)


class RejectPolicySentinel:
    pass


class FakeChannel:
    def __init__(
        self,
        chunks: list[bytes | BaseException],
        *,
        exit_status: int = 0,
        close_error: BaseException | None = None,
        execution_error: BaseException | None = None,
        stderr: bytes = b"",
    ) -> None:
        self._stderr = stderr
        self._chunks = list(chunks)
        self._exit_status = exit_status
        self._close_error = close_error
        self._execution_error = execution_error
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
        if self._execution_error is not None:
            raise self._execution_error

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

    def recv_stderr(self, size: int) -> bytes:
        chunk, self._stderr = self._stderr[:size], self._stderr[size:]
        return chunk

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
        if self._close_error is not None:
            raise self._close_error


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


def test_paramiko_transport_verifies_hosts_and_uses_bounded_session(
    tmp_path: Path,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("logs.example.test ssh-ed25519 key\n", encoding="utf-8")
    channel = FakeChannel([b"one\ntwo\n", b""])
    client, ssh_client, transport, module = paramiko_client(
        channel, known_hosts_path=known_hosts
    )

    result = client.read_tail(
        "/var/log/app.log", max_lines=2, max_bytes=64, timeout_seconds=7
    )

    assert result == RemoteReadResult(data=b"one\ntwo\n", byte_count=8, truncated=False)
    assert ssh_client.system_host_keys_loaded is True
    assert ssh_client.loaded_host_key_files == [str(known_hosts)]
    assert ssh_client.missing_host_key_policies == [module.reject_policy]
    assert len(ssh_client.connect_calls) == 1
    arguments = ssh_client.connect_calls[0]
    assert arguments | {
        "timeout": 0,
        "banner_timeout": 0,
        "auth_timeout": 0,
        "channel_timeout": 0,
    } == {
        "hostname": "logs.example.test",
        "port": 2222,
        "username": "readonly",
        "key_filename": "/keys/read-only",
        "timeout": 0,
        "banner_timeout": 0,
        "auth_timeout": 0,
        "channel_timeout": 0,
        "allow_agent": False,
        "look_for_keys": False,
    }
    assert all(
        0 < arguments[name] <= 7
        for name in (
            "timeout",
            "banner_timeout",
            "auth_timeout",
            "channel_timeout",
        )
    )
    assert len(transport.open_session_timeouts) == 1
    assert 0 < transport.open_session_timeouts[0] <= 7
    assert channel.timeouts
    assert all(0 < timeout <= 7 for timeout in channel.timeouts)
    assert channel.commands == ["tail -c 64 -- /var/log/app.log"]
    assert channel.recv_sizes
    assert max(channel.recv_sizes) <= 64
    assert channel.closed is True
    assert ssh_client.closed is True
    assert channel.tty_requested is False
    assert channel.agent_forwarding_requested is False
    assert channel.x11_forwarding_requested is False
    assert transport.port_forwarding_requested is False
    assert ssh_client.sftp_opened is False


def test_paramiko_transport_bounds_remote_read_by_requested_bytes() -> None:
    channel = FakeChannel([b""])
    client, _, _, _ = paramiko_client(channel)

    client.read_tail(
        "/var/log/app.log",
        max_lines=50_000,
        max_bytes=64,
        timeout_seconds=7,
    )

    assert channel.commands == ["tail -c 64 -- /var/log/app.log"]


def test_paramiko_transport_rejects_caller_requests_above_configured_limit() -> None:
    client, _, _, _ = paramiko_client(FakeChannel([b""]))

    with pytest.raises(ValueError, match="50000"):
        client.read_tail(
            "/var/log/app.log",
            max_lines=50_001,
            max_bytes=64,
            timeout_seconds=7,
        )


def test_paramiko_transport_counts_newlines_across_chunk_boundaries() -> None:
    # 20 real lines of 5 bytes each, delivered as 20 separate small recv()
    # chunks (as a real TCP stream would). A naive `b"\n".join(chunks)`
    # newline count inserts one spurious separator per chunk boundary and
    # truncates well before the real 15-line limit is reached.
    line = b"abcd\n"
    channel = FakeChannel([line for _ in range(20)])
    client, _, _, _ = paramiko_client(channel)

    result = client.read_tail(
        "/var/log/app.log", max_lines=15, max_bytes=1_000, timeout_seconds=5
    )

    assert result.data.count(b"\n") == 15
    assert result.byte_count == 80
    assert result.truncated is True


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


def test_paramiko_transport_keeps_newest_complete_lines_at_byte_limit() -> None:
    channel = FakeChannel([b"two\nthree\n"])
    client, ssh_client, _, _ = paramiko_client(channel)

    result = client.read_tail(
        "/var/log/app.log", max_lines=10, max_bytes=10, timeout_seconds=5
    )

    assert result == RemoteReadResult(
        data=b"two\nthree\n", byte_count=10, truncated=True
    )
    assert channel.commands == ["tail -c 10 -- /var/log/app.log"]
    assert channel.recv_sizes == [10]
    assert channel.closed is True
    assert ssh_client.closed is True


def test_paramiko_transport_sets_remaining_timeout_before_blocking_execution() -> None:
    clock_values = iter([0.0, 0.0, 0.0, 4.0])
    channel = FakeChannel([], execution_error=TimeoutError("timed out"))
    transport = FakeTransport(channel)
    ssh_client = FakeSSHClient(transport)
    client = ParamikoSSHClient(
        connection(),
        paramiko_module=FakeParamiko(ssh_client),
        monotonic=lambda: next(clock_values),
    )

    with pytest.raises(SSHTransportError, match="SSH connection or read failed"):
        client.read_tail(
            "/var/log/app.log", max_lines=10, max_bytes=100, timeout_seconds=5
        )

    assert channel.timeouts == [1.0]
    assert channel.commands == ["tail -c 100 -- /var/log/app.log"]
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


def test_paramiko_transport_uses_a_total_monotonic_deadline() -> None:
    clock_values = iter([0.0, 0.0, 0.0, 0.0, 4.0, 5.0])
    channel = FakeChannel([b"one\n", b"two\n"])
    transport = FakeTransport(channel)
    ssh_client = FakeSSHClient(transport)
    client = ParamikoSSHClient(
        connection(),
        paramiko_module=FakeParamiko(ssh_client),
        monotonic=lambda: next(clock_values),
    )

    result = client.read_tail(
        "/var/log/app.log", max_lines=10, max_bytes=100, timeout_seconds=5
    )

    assert result == RemoteReadResult(data=b"one\n", byte_count=4, truncated=True)
    assert channel.recv_sizes == [64]
    assert channel.timeouts == [5.0, 1.0]


def test_paramiko_transport_attempts_client_cleanup_when_channel_close_fails() -> None:
    channel = FakeChannel([b""], close_error=RuntimeError("close failed"))
    client, ssh_client, _, _ = paramiko_client(channel)

    result = client.read_tail(
        "/var/log/app.log", max_lines=10, max_bytes=100, timeout_seconds=5
    )

    assert result == RemoteReadResult(data=b"", byte_count=0, truncated=False)
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


def test_permission_failure_is_sanitized_without_exposing_secrets(
    caplog: pytest.LogCaptureFixture,
) -> None:
    credential = "not-a-real-secret"
    channel = FakeChannel([])
    client, ssh_client, _, _ = paramiko_client(
        channel, connect_error=PermissionError(f"permission denied: {credential}")
    )

    with (
        caplog.at_level(logging.DEBUG),
        pytest.raises(
            SSHPermissionDeniedError, match="SSH permission denied"
        ) as raised,
    ):
        client.read_tail(
            "/var/log/app.log", max_lines=10, max_bytes=100, timeout_seconds=5
        )

    assert credential not in str(raised.value)
    assert credential not in caplog.text
    assert ssh_client.closed is True


def test_paramiko_transport_rejects_writable_known_hosts_before_loading(
    tmp_path: Path,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("logs.example.test ssh-ed25519 key\n", encoding="utf-8")
    known_hosts.chmod(0o664)
    channel = FakeChannel([b""])
    client, ssh_client, _, _ = paramiko_client(channel, known_hosts_path=known_hosts)

    with pytest.raises(ConfigurationError, match="group- or world-writable"):
        client.read_tail(
            "/var/log/app.log", max_lines=10, max_bytes=100, timeout_seconds=5
        )

    assert ssh_client.loaded_host_key_files == []


def test_paramiko_transport_reports_missing_known_hosts_file_clearly(
    tmp_path: Path,
) -> None:
    missing_known_hosts = tmp_path / "does-not-exist"
    channel = FakeChannel([b""])
    client, ssh_client, _, _ = paramiko_client(
        channel, known_hosts_path=missing_known_hosts
    )

    with pytest.raises(ConfigurationError, match=str(missing_known_hosts)):
        client.read_tail(
            "/var/log/app.log", max_lines=10, max_bytes=100, timeout_seconds=5
        )

    assert ssh_client.loaded_host_key_files == []


def test_permission_error_class_name_from_a_real_paramiko_exception_is_recognized() -> (
    None
):
    # paramiko is lazy-imported (see _load_paramiko), so this branch is
    # matched by class name rather than isinstance against the real
    # paramiko.AuthenticationException. Use a same-named stand-in here so the
    # match itself is exercised without importing paramiko's exception type.
    AuthenticationException = type("AuthenticationException", (Exception,), {})
    channel = FakeChannel([])
    client, ssh_client, _, _ = paramiko_client(
        channel, connect_error=AuthenticationException("denied")
    )

    with pytest.raises(SSHPermissionDeniedError):
        client.read_tail(
            "/var/log/app.log", max_lines=10, max_bytes=100, timeout_seconds=5
        )

    assert ssh_client.closed is True


def test_explicit_private_key_disables_default_key_and_agent_discovery() -> None:
    client, _, _, _ = paramiko_client(FakeChannel([b""]))

    arguments = client._connection_arguments(7)

    assert arguments["key_filename"] == "/keys/read-only"
    assert arguments["allow_agent"] is False
    assert arguments["look_for_keys"] is False


def test_ephemeral_password_is_passed_to_paramiko_without_key_discovery() -> None:
    channel = FakeChannel([b""])
    client, ssh_client, _, _ = paramiko_client(channel)

    client.read_tail(
        "/var/log/app.log",
        max_lines=10,
        max_bytes=100,
        timeout_seconds=5,
        password="one-time-secret",
    )

    assert ssh_client.connect_calls[0]["password"] == "one-time-secret"
    assert ssh_client.connect_calls[0]["allow_agent"] is False
    assert ssh_client.connect_calls[0]["look_for_keys"] is False


class FakeTailClient:
    def __init__(self, result: RemoteReadResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def stat_file(self, path: str, *, timeout_seconds: int) -> RemoteFileStat | None:
        return RemoteFileStat(
            size_bytes=len(self.result.data),
            modified_at=datetime(2026, 9, 3, tzinfo=UTC),
            is_regular_file=True,
        )

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


def test_ssh_log_source_reports_tail_sampling_and_parse_stats() -> None:
    remote = FakeTailClient(
        RemoteReadResult(
            data=(
                b"[2026-09-03 09:00:00] ERROR: old\n"
                b"[2026-09-03 12:00:00] WARNING: recent\n"
                b"unstructured continuation\n"
            ),
            byte_count=97,
            truncated=True,
        )
    )
    source = SSHLogSource(connection(), client=remote)

    result = source.read(
        LogAliasConfig(path="/var/log/app.log", type="php"),
        ReadLimits(max_lines=50, max_bytes=1_000, timeout_seconds=9),
        TimeRange.parse("1h", NOW),
    )

    assert result.line_count == 1
    assert result.source_metadata is not None
    assert result.source_metadata.exists is True
    assert result.source_metadata.readable is True
    assert result.source_metadata.size_bytes == 97
    assert result.sampling is not None
    assert result.sampling.direction == "tail"
    assert result.sampling.sampled_bytes == 97
    assert result.sampling.complete_lines == 3
    assert result.sampling.max_bytes == 1_000
    assert result.sampling.max_lines == 50
    assert result.parse_stats is not None
    assert result.parse_stats.parsed_lines == 2
    assert result.parse_stats.unparsed_lines == 1
    assert result.parse_stats.level_counts == {"ERROR": 1, "WARNING": 1}
    assert result.parse_stats.filtered_out_lines == 2


def test_paramiko_stat_runs_only_the_fixed_file_check_command() -> None:
    channel = FakeChannel([b"f 4096 1788000000.0000000000\n", b""])
    client, ssh_client, _, _ = paramiko_client(channel)

    result = client.stat_file("/var/log/app.log", timeout_seconds=7)

    assert channel.commands == [
        "find /var/log/app.log -maxdepth 0 -printf '%y %s %T@\\n'"
    ]
    assert result == RemoteFileStat(
        size_bytes=4096,
        modified_at=datetime.fromtimestamp(1788000000, tz=UTC),
        is_regular_file=True,
    )
    assert channel.closed is True
    assert ssh_client.closed is True
    assert ssh_client.sftp_opened is False


@pytest.mark.parametrize(
    ("stderr", "reason"),
    [
        (b"find: '/var/log/missing.log': No such file or directory\n", "not_found"),
        (b"find: '/srv/shop/var/log': Permission denied\n", "permission_denied"),
        (b"", "unknown"),
    ],
)
def test_paramiko_stat_reports_why_a_file_is_unavailable(
    stderr: bytes, reason: str
) -> None:
    channel = FakeChannel([b""], exit_status=1, stderr=stderr)
    client, _, _, _ = paramiko_client(channel)

    result = client.stat_file("/var/log/missing.log", timeout_seconds=7)

    assert result == RemoteFileMissing(reason=reason)


def test_paramiko_tail_reports_a_permission_error_explicitly() -> None:
    channel = FakeChannel(
        [b""],
        exit_status=1,
        stderr=b"tail: cannot open '/var/log/app.log' for reading: Permission denied\n",
    )
    client, _, _, _ = paramiko_client(channel)

    with pytest.raises(RemoteCommandFailedError) as raised:
        client.read_tail(
            "/var/log/app.log", max_lines=10, max_bytes=64, timeout_seconds=7
        )

    assert raised.value.reason == "permission_denied"
    assert "cannot open" not in str(raised.value)


def test_paramiko_stat_treats_symlinks_and_directories_as_not_regular() -> None:
    channel = FakeChannel([b"l 12 1788000000.0\n", b""])
    client, _, _, _ = paramiko_client(channel)

    result = client.stat_file("/var/log", timeout_seconds=7)

    assert result is not None
    assert result.is_regular_file is False


def test_paramiko_list_runs_only_the_fixed_find_command_and_skips_bad_names() -> None:
    channel = FakeChannel(
        [
            b"1788000000.5 120 transfer-2026-09-01.log\n"
            b"1788086400.0 240 transfer-2026-09-02.log\n"
            b"not-a-listing-line\n",
            b"",
        ]
    )
    client, _, _, _ = paramiko_client(channel)

    result = client.list_files(
        "/srv/example-shop/var/log", "transfer-*.log", timeout_seconds=7
    )

    assert channel.commands == [
        "find /srv/example-shop/var/log -maxdepth 1 -type f "
        "-name 'transfer-*.log' -printf '%T@ %s %f\\n'"
    ]
    assert result == RemoteListing(
        entries=[
            RemoteFileEntry(
                name="transfer-2026-09-01.log",
                size_bytes=120,
                modified_at=datetime.fromtimestamp(1788000000.5, tz=UTC),
            ),
            RemoteFileEntry(
                name="transfer-2026-09-02.log",
                size_bytes=240,
                modified_at=datetime.fromtimestamp(1788086400.0, tz=UTC),
            ),
        ],
        truncated=False,
    )


def test_paramiko_list_is_bounded_by_the_maximum_entry_count() -> None:
    lines = b"".join(
        f"1788000000.0 1 transfer-{index}.log\n".encode()
        for index in range(MAX_LIST_ENTRIES + 5)
    )
    channel = FakeChannel([lines, b""])
    client, _, _, _ = paramiko_client(channel)

    result = client.list_files("/var/log", "transfer-*.log", timeout_seconds=7)

    assert len(result.entries) <= MAX_LIST_ENTRIES
    assert result.truncated is True


class FakeInspectClient(FakeTailClient):
    def __init__(
        self,
        result: RemoteReadResult,
        *,
        stat: RemoteFileStat | None = None,
        listing: RemoteListing | None = None,
        read_error: BaseException | None = None,
    ) -> None:
        super().__init__(result)
        self.stat = stat
        self.listing = listing or RemoteListing(entries=[], truncated=False)
        self.read_error = read_error
        self.stat_calls: list[str] = []
        self.list_calls: list[tuple[str, str]] = []

    def read_tail(
        self,
        path: str,
        *,
        max_lines: int,
        max_bytes: int,
        timeout_seconds: int,
    ) -> RemoteReadResult:
        if self.read_error is not None:
            raise self.read_error
        return super().read_tail(
            path,
            max_lines=max_lines,
            max_bytes=max_bytes,
            timeout_seconds=timeout_seconds,
        )

    def stat_file(self, path: str, *, timeout_seconds: int) -> RemoteFileStat | None:
        self.stat_calls.append(path)
        return self.stat

    def list_files(
        self, directory: str, pattern: str, *, timeout_seconds: int
    ) -> RemoteListing:
        self.list_calls.append((directory, pattern))
        return self.listing


INSPECT_LIMITS = ReadLimits(max_lines=100, max_bytes=4_096, timeout_seconds=9)
MTIME = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)


def test_ssh_source_lists_candidates_newest_first() -> None:
    remote = FakeInspectClient(
        RemoteReadResult(data=b"", byte_count=0, truncated=False),
        listing=RemoteListing(
            entries=[
                RemoteFileEntry(name="transfer-1.log", size_bytes=1, modified_at=NOW),
                RemoteFileEntry(name="transfer-2.log", size_bytes=2, modified_at=MTIME),
            ],
            truncated=False,
        ),
    )
    source = SSHLogSource(connection(), client=remote)

    listing = source.list_candidates(
        Path("/srv/example-shop/var/log"), "transfer-*.log", timeout_seconds=9
    )

    assert remote.list_calls == [("/srv/example-shop/var/log", "transfer-*.log")]
    assert [candidate.path for candidate in listing.files] == [
        "/srv/example-shop/var/log/transfer-1.log",
        "/srv/example-shop/var/log/transfer-2.log",
    ]
    assert listing.truncated is False


def test_ssh_source_inspect_combines_stat_and_a_bounded_sample() -> None:
    remote = FakeInspectClient(
        RemoteReadResult(
            data=b"[2026-09-03 12:00:00] ERROR: boom\n", byte_count=34, truncated=True
        ),
        stat=RemoteFileStat(size_bytes=9_000, modified_at=MTIME, is_regular_file=True),
    )
    source = SSHLogSource(connection(), client=remote)

    result = source.inspect(
        LogAliasConfig(path="/var/log/app.log", type="php"), INSPECT_LIMITS
    )

    assert remote.stat_calls == ["/var/log/app.log"]
    assert result.source_metadata == SourceMetadata(
        exists=True, readable=True, size_bytes=9_000, modified_at=MTIME
    )
    assert result.parse_stats is not None
    assert result.parse_stats.parsed_lines == 1
    assert result.sampling is not None
    assert result.sampling.max_bytes == 4_096


def test_ssh_source_inspect_reports_a_missing_file_without_reading() -> None:
    remote = FakeInspectClient(
        RemoteReadResult(data=b"", byte_count=0, truncated=False),
        stat=RemoteFileMissing(reason="not_found"),
    )
    source = SSHLogSource(connection(), client=remote)

    result = source.inspect(
        LogAliasConfig(path="/var/log/missing.log", type="php"), INSPECT_LIMITS
    )

    assert remote.calls == []
    assert result.source_metadata == SourceMetadata(
        exists=False, readable=False, error="file not found"
    )


def test_ssh_source_reports_an_inaccessible_folder_separately() -> None:
    remote = FakeInspectClient(
        RemoteReadResult(data=b"", byte_count=0, truncated=False),
        stat=RemoteFileMissing(reason="permission_denied"),
    )
    source = SSHLogSource(connection(), client=remote)

    result = source.inspect(
        LogAliasConfig(path="/var/log/app.log", type="php"), INSPECT_LIMITS
    )

    assert remote.calls == []
    assert result.source_metadata == SourceMetadata(
        exists=None,
        readable=False,
        error="permission denied: the file or a folder above it is not accessible",
    )


def test_ssh_read_keeps_size_and_mtime_from_the_file_check() -> None:
    remote = FakeInspectClient(
        RemoteReadResult(data=b"line\n", byte_count=5, truncated=False),
        stat=RemoteFileStat(size_bytes=9_000, modified_at=MTIME, is_regular_file=True),
    )
    source = SSHLogSource(connection(), client=remote)

    result = source.read(
        LogAliasConfig(path="/var/log/app.log", type="php"),
        INSPECT_LIMITS,
        TimeRange.parse("all", NOW),
    )

    assert result.source_metadata == SourceMetadata(
        exists=True, readable=True, size_bytes=9_000, modified_at=MTIME
    )


@pytest.mark.parametrize("method", ["read", "inspect"])
def test_ssh_tail_permission_error_is_reported_as_permission_denied(
    method: str,
) -> None:
    remote = FakeInspectClient(
        RemoteReadResult(data=b"", byte_count=0, truncated=False),
        stat=RemoteFileStat(size_bytes=10, modified_at=MTIME, is_regular_file=True),
        read_error=RemoteCommandFailedError(
            "Remote tail command failed", reason="permission_denied"
        ),
    )
    source = SSHLogSource(connection(), client=remote)
    alias = LogAliasConfig(path="/var/log/app.log", type="php")

    if method == "read":
        result = source.read(alias, INSPECT_LIMITS, TimeRange.parse("all", NOW))
    else:
        result = source.inspect(alias, INSPECT_LIMITS)

    assert result.entries == []
    assert result.source_metadata == SourceMetadata(
        exists=True,
        readable=False,
        size_bytes=10,
        modified_at=MTIME,
        error="permission denied reading the file",
    )


def test_ssh_source_inspect_reports_an_unreadable_file() -> None:
    remote = FakeInspectClient(
        RemoteReadResult(data=b"", byte_count=0, truncated=False),
        stat=RemoteFileStat(size_bytes=10, modified_at=MTIME, is_regular_file=True),
        read_error=SSHTransportError("Remote tail command failed"),
    )
    source = SSHLogSource(connection(), client=remote)

    result = source.inspect(
        LogAliasConfig(path="/var/log/secret.log", type="php"), INSPECT_LIMITS
    )

    assert result.source_metadata == SourceMetadata(
        exists=True,
        readable=False,
        size_bytes=10,
        modified_at=MTIME,
        error="read failed",
    )


def test_ssh_source_inspect_propagates_authentication_denial() -> None:
    remote = FakeInspectClient(
        RemoteReadResult(data=b"", byte_count=0, truncated=False),
        stat=RemoteFileStat(size_bytes=10, modified_at=MTIME, is_regular_file=True),
        read_error=SSHPermissionDeniedError("SSH permission denied"),
    )
    source = SSHLogSource(connection(), client=remote)

    with pytest.raises(SSHPermissionDeniedError):
        source.inspect(
            LogAliasConfig(path="/var/log/app.log", type="php"), INSPECT_LIMITS
        )


def test_ssh_log_source_applies_the_alias_client_ip_policy() -> None:
    remote = FakeTailClient(
        RemoteReadResult(
            data=(
                b'203.0.113.10 - - [03/Sep/2026:12:00:00 +0000] "GET / HTTP/1.1" '
                b'200 1 "-" "agent" "198.51.100.7"\n'
            ),
            byte_count=90,
            truncated=False,
        )
    )
    source = SSHLogSource(connection(), client=remote)

    result = source.read(
        LogAliasConfig(
            path="/var/log/nginx/transfer.log",
            type="nginx",
            client_ip_source="x_forwarded_for",
        ),
        ReadLimits(max_lines=50, max_bytes=1_000, timeout_seconds=9),
        TimeRange.parse("all", NOW),
    )

    assert result.entries[0].access is not None
    assert result.entries[0].access.client_ip == "198.51.100.7"


@pytest.mark.parametrize(
    ("stat", "error"),
    [
        (
            RemoteFileMissing(reason="unknown"),
            "file not found or folder not accessible",
        ),
        (
            RemoteFileStat(size_bytes=0, modified_at=MTIME, is_regular_file=False),
            "not a regular file, or a symlink in its path (symlinks are not followed)",
        ),
    ],
)
def test_ssh_read_checks_the_file_before_tailing_it(
    stat: RemoteFileStat | RemoteFileMissing, error: str
) -> None:
    remote = FakeInspectClient(
        RemoteReadResult(data=b"secret\n", byte_count=7, truncated=False), stat=stat
    )
    source = SSHLogSource(connection(), client=remote)

    result = source.read(
        LogAliasConfig(path="/var/log/app.log", type="php"),
        INSPECT_LIMITS,
        TimeRange.parse("all", NOW),
    )

    assert remote.calls == []
    assert result.entries == []
    assert result.source_metadata is not None
    assert result.source_metadata.error == error


def test_ssh_inspect_checks_the_file_once() -> None:
    remote = FakeInspectClient(
        RemoteReadResult(data=b"line\n", byte_count=5, truncated=False),
        stat=RemoteFileStat(size_bytes=5, modified_at=MTIME, is_regular_file=True),
    )
    source = SSHLogSource(connection(), client=remote)

    source.inspect(LogAliasConfig(path="/var/log/app.log", type="php"), INSPECT_LIMITS)

    assert remote.stat_calls == ["/var/log/app.log"]
    assert len(remote.calls) == 1


@pytest.mark.parametrize(
    "output",
    [
        b"d 0 1.0\nl 0 1.0\nf 10 1788000000.0\n",
        b"l 0 1.0\nd 0 1.0\nf 10 1788000000.0\n",
        b"d 0 1.0\nf 10 1788000000.0\n",
    ],
)
def test_paramiko_stat_refuses_a_symlinked_parent_folder(output: bytes) -> None:
    channel = FakeChannel([output, b""])
    client, _, _, _ = paramiko_client(channel)

    result = client.stat_file(
        "/srv/shop/var/log/app.log",
        timeout_seconds=7,
        parents=["/srv/shop/var", "/srv/shop/var/log"],
    )

    assert result is not None
    assert result.is_regular_file is False


def test_paramiko_stat_accepts_real_parent_folders() -> None:
    channel = FakeChannel([b"d 0 1.0\nd 0 1.0\nf 10 1788000000.0\n", b""])
    client, _, _, _ = paramiko_client(channel)

    result = client.stat_file(
        "/srv/shop/var/log/app.log",
        timeout_seconds=7,
        parents=["/srv/shop/var", "/srv/shop/var/log"],
    )

    assert result is not None
    assert result.is_regular_file is True
    assert result.size_bytes == 10


def test_ssh_source_checks_parent_folders_below_the_allowed_log_folder() -> None:
    remote = RecordingParentsClient()
    source = SSHLogSource(connection(), client=remote, allowed_dirs=[Path("/srv/shop")])

    source.read(
        LogAliasConfig(path="/srv/shop/var/log/nginx/app.log", type="nginx"),
        INSPECT_LIMITS,
        TimeRange.parse("all", NOW),
    )

    assert remote.parents == [
        ["/srv/shop/var", "/srv/shop/var/log", "/srv/shop/var/log/nginx"]
    ]


def test_ssh_glob_listing_refuses_a_symlinked_folder() -> None:
    remote = RecordingParentsClient(regular=False)
    source = SSHLogSource(connection(), client=remote, allowed_dirs=[Path("/srv/shop")])

    listing = source.list_candidates(
        Path("/srv/shop/var/log"), "transfer-*.log", timeout_seconds=9
    )

    assert listing.files == []
    assert remote.list_calls == []
    assert remote.parents == [["/srv/shop/var"]]


class RecordingParentsClient(FakeTailClient):
    def __init__(self, *, regular: bool = True) -> None:
        super().__init__(RemoteReadResult(data=b"x\n", byte_count=2, truncated=False))
        self.regular = regular
        self.parents: list[list[str]] = []
        self.list_calls: list[str] = []

    def stat_file(  # type: ignore[override]
        self, path: str, *, timeout_seconds: int, parents: list[str] | None = None
    ) -> RemoteFileStat | None:
        self.parents.append(list(parents or []))
        return RemoteFileStat(
            size_bytes=2, modified_at=MTIME, is_regular_file=self.regular
        )

    def list_files(
        self, directory: str, pattern: str, *, timeout_seconds: int
    ) -> RemoteListing:
        self.list_calls.append(directory)
        return RemoteListing(entries=[], truncated=False)
