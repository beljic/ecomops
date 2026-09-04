from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ecomops.config.schema import LogAliasConfig
from ecomops.core.models import LogEntry, LogReadResult

from .parsers import parse_lines
from .readers import read_local_bytes
from .time_ranges import TimeRange


@dataclass(frozen=True)
class ReadLimits:
    max_lines: int
    max_bytes: int
    timeout_seconds: int

    def __post_init__(self) -> None:
        for field_name, value in (
            ("max_lines", self.max_lines),
            ("max_bytes", self.max_bytes),
            ("timeout_seconds", self.timeout_seconds),
        ):
            if value <= 0:
                raise ValueError(f"{field_name} must be greater than zero")


class LocalLogSource:
    def read(
        self,
        alias: LogAliasConfig,
        limits: ReadLimits,
        time_range: TimeRange,
    ) -> LogReadResult:
        path = Path(alias.path).expanduser()
        size = path.stat().st_size
        byte_count = min(size, limits.max_bytes)
        offset = 0 if time_range.start is None else size - byte_count
        data = read_local_bytes(path, offset=offset, max_bytes=byte_count)
        at_end = offset + len(data) >= size
        starts_mid_line = offset > 0 and read_local_bytes(
            path, offset=offset - 1, max_bytes=1
        ) not in (b"\n", b"\r")
        lines = _complete_lines(data, starts_mid_line=starts_mid_line, at_end=at_end)
        entries = parse_lines(lines, source=str(path))
        if offset > 0:
            entries = [
                entry.model_copy(update={"line_number": None}) for entry in entries
            ]
        entries = _filter_entries(entries, time_range=time_range)

        truncated = (
            len(data) < size
            or len(entries) > limits.max_lines
            or time_range.exact_selection
        )
        entries = entries[: limits.max_lines]
        actual_range = _actual_range(entries)

        return LogReadResult(
            entries=entries,
            line_count=len(entries),
            byte_count=len(data),
            truncated=truncated,
            actual_range=actual_range,
        )


def _complete_lines(data: bytes, *, starts_mid_line: bool, at_end: bool) -> list[str]:
    lines = data.splitlines(keepends=True)
    if starts_mid_line and lines:
        lines = lines[1:]
    if not at_end and lines and not lines[-1].endswith((b"\n", b"\r")):
        lines = lines[:-1]
    return [line.decode("utf-8", errors="replace") for line in lines]


def _filter_entries(
    entries: list[LogEntry], *, time_range: TimeRange
) -> list[LogEntry]:
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
