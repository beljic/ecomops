from __future__ import annotations

import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ecomops.config.schema import LogAliasConfig
from ecomops.core.models import (
    LogEntry,
    LogReadResult,
    SamplingMetadata,
    SourceMetadata,
)

from .inspection import LogFileListing, list_local_candidates
from .parsers import parse_lines_with_stats
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
    def list_candidates(
        self,
        directory: Path,
        pattern: str,
        *,
        timeout_seconds: int,
        allowed_dirs: list[Path] | None = None,
    ) -> LogFileListing:
        """List glob candidates; ``timeout_seconds`` is unused for local reads."""
        assert allowed_dirs is not None, "local listing needs the allowed log folders"
        return list_local_candidates(directory, pattern, allowed_dirs)

    def inspect(self, alias: LogAliasConfig, limits: ReadLimits) -> LogReadResult:
        """Describe the file and parse a bounded head sample; no analyzers run."""
        return self.read(alias, limits, TimeRange(start=None, end=None))

    def read(
        self,
        alias: LogAliasConfig,
        limits: ReadLimits,
        time_range: TimeRange,
    ) -> LogReadResult:
        path = Path(alias.path).expanduser()
        metadata = inspect_local_file(path)
        if not metadata.readable:
            return LogReadResult(
                entries=[],
                line_count=0,
                byte_count=0,
                truncated=False,
                source_metadata=metadata,
            )
        try:
            size = path.stat().st_size
            byte_count = min(size, limits.max_bytes)
            offset = 0 if time_range.start is None else size - byte_count
            data = read_local_bytes(path, offset=offset, max_bytes=byte_count)
            starts_mid_line = offset > 0 and read_local_bytes(
                path, offset=offset - 1, max_bytes=1
            ) not in (b"\n", b"\r")
        except OSError:
            # Rotated, deleted, or re-permissioned between the check and the read.
            return LogReadResult(
                entries=[],
                line_count=0,
                byte_count=0,
                truncated=False,
                source_metadata=metadata.model_copy(
                    update={
                        "readable": False,
                        "error": "file disappeared or became unreadable",
                    }
                ),
            )
        at_end = offset + len(data) >= size
        lines = _complete_lines(data, starts_mid_line=starts_mid_line, at_end=at_end)
        parsed = parse_lines_with_stats(
            lines, source=str(path), client_ip_source=alias.client_ip_source
        )
        entries = parsed.entries
        if offset > 0:
            entries = [
                entry.model_copy(update={"line_number": None}) for entry in entries
            ]
        sampled_range = sampled_time_range(entries)
        entries = _filter_entries(entries, time_range=time_range)
        parse_stats = parsed.stats.model_copy(
            update={"filtered_out_lines": len(parsed.entries) - len(entries)}
        )

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
            source_metadata=metadata,
            parse_stats=parse_stats,
            sampling=SamplingMetadata(
                direction="head" if time_range.start is None else "tail",
                max_bytes=limits.max_bytes,
                max_lines=limits.max_lines,
                sampled_bytes=len(data),
                complete_lines=len(lines),
                sampled_range=sampled_range,
            ),
        )


def inspect_local_file(path: Path) -> SourceMetadata:
    """Describe a local log with ``stat`` and a read-open check; never writes."""
    try:
        file_stat = path.stat()
    except FileNotFoundError:
        return SourceMetadata(exists=False, readable=False, error="file not found")
    except PermissionError:
        return SourceMetadata(exists=False, readable=False, error="permission denied")
    except OSError:
        return SourceMetadata(exists=False, readable=False, error="cannot access file")

    modified_at = datetime.fromtimestamp(file_stat.st_mtime, tz=UTC)
    if not stat.S_ISREG(file_stat.st_mode):
        return SourceMetadata(
            exists=True,
            readable=False,
            modified_at=modified_at,
            error="not a regular file",
        )
    error: str | None = None
    try:
        with path.open("rb"):
            pass
    except PermissionError:
        error = "permission denied"
    except OSError:
        error = "cannot open file"
    return SourceMetadata(
        exists=True,
        readable=error is None,
        size_bytes=file_stat.st_size,
        modified_at=modified_at,
        error=error,
    )


def sampled_time_range(entries: list[LogEntry]) -> TimeRange | None:
    """Time range covered by every timestamped line in the sample, in UTC."""
    timestamps = [
        _as_utc(entry.timestamp) for entry in entries if entry.timestamp is not None
    ]
    if not timestamps:
        return None
    return TimeRange(start=min(timestamps), end=max(timestamps))


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
