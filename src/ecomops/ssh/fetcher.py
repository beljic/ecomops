from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from ecomops.config.schema import LogAliasConfig, SSHConnectionConfig
from ecomops.core.models import LogEntry, LogReadResult
from ecomops.logs.parsers import parse_lines
from ecomops.logs.sources import ReadLimits
from ecomops.logs.time_ranges import TimeRange

from .client import ParamikoSSHClient, RemoteReadResult


class _TailClient(Protocol):
    def read_tail(
        self,
        path: str,
        *,
        max_lines: int,
        max_bytes: int,
        timeout_seconds: int,
    ) -> RemoteReadResult: ...


class SSHLogSource:
    """Parse a bounded, read-only SSH tail into the common log result model."""

    def __init__(
        self, connection: SSHConnectionConfig, *, client: _TailClient | None = None
    ) -> None:
        self._client = client or ParamikoSSHClient(connection)

    def read(
        self,
        alias: LogAliasConfig,
        limits: ReadLimits,
        time_range: TimeRange,
    ) -> LogReadResult:
        remote = self._client.read_tail(
            alias.path,
            max_lines=limits.max_lines,
            max_bytes=limits.max_bytes,
            timeout_seconds=limits.timeout_seconds,
        )
        lines = [
            line.decode("utf-8", errors="replace")
            for line in remote.data.splitlines(keepends=True)
        ]
        entries = parse_lines(lines, source=alias.path)
        entries = [entry.model_copy(update={"line_number": None}) for entry in entries]
        entries = _filter_entries(entries, time_range)

        return LogReadResult(
            entries=entries,
            line_count=len(entries),
            byte_count=remote.byte_count,
            truncated=remote.truncated or time_range.exact_selection,
            actual_range=_actual_range(entries),
        )


def _filter_entries(entries: list[LogEntry], time_range: TimeRange) -> list[LogEntry]:
    if time_range.start is None:
        return entries
    assert time_range.end is not None

    filtered_entries: list[LogEntry] = []
    for entry in entries:
        if entry.timestamp is None:
            continue
        timestamp = _as_utc(entry.timestamp)
        if time_range.start <= timestamp <= time_range.end:
            filtered_entries.append(entry.model_copy(update={"timestamp": timestamp}))
    return filtered_entries


def _actual_range(entries: list[LogEntry]) -> TimeRange | None:
    timestamps = [entry.timestamp for entry in entries if entry.timestamp is not None]
    if not timestamps:
        return None
    return TimeRange(start=min(timestamps), end=max(timestamps))


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
