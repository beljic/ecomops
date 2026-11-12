from __future__ import annotations

import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ecomops.config.schema import LogAliasConfig
from ecomops.core.models import (
    LogReadResult,
    SamplingMetadata,
    SourceMetadata,
)

from .filtering import filter_by_time, time_range_of
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
    def __enter__(self) -> LocalLogSource:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

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
            return _unreadable(metadata)
        if path.name.endswith(".gz"):
            return _unreadable(
                metadata.model_copy(
                    update={
                        "readable": False,
                        "error": "compressed logs are read over SSH only",
                    }
                )
            )
        try:
            window = _read_window(path, limits, from_end=time_range.start is not None)
        except OSError:
            # Rotated, deleted, or re-permissioned between the check and the read.
            return _unreadable(
                metadata.model_copy(
                    update={
                        "readable": False,
                        "error": "file disappeared or became unreadable",
                    }
                )
            )
        parsed = parse_lines_with_stats(
            window.lines, source=str(path), client_ip_source=alias.client_ip_source
        )
        entries = parsed.entries
        if window.offset > 0:
            entries = [
                entry.model_copy(update={"line_number": None}) for entry in entries
            ]
        sampled_range = time_range_of(entries)
        entries = filter_by_time(entries, time_range)
        truncated = (
            window.partial or len(entries) > limits.max_lines
        ) or time_range.exact_selection
        entries = entries[: limits.max_lines]

        return LogReadResult(
            entries=entries,
            line_count=len(entries),
            byte_count=len(window.data),
            truncated=truncated,
            actual_range=time_range_of(entries),
            source_metadata=metadata,
            parse_stats=parsed.stats.model_copy(
                update={"filtered_out_lines": len(parsed.entries) - len(entries)}
            ),
            sampling=SamplingMetadata(
                direction="tail" if window.from_end else "head",
                max_bytes=limits.max_bytes,
                max_lines=limits.max_lines,
                sampled_bytes=len(window.data),
                complete_lines=len(window.lines),
                sampled_range=sampled_range,
            ),
        )


@dataclass(frozen=True)
class _Window:
    """One bounded byte window of a local file, cut to complete lines."""

    data: bytes
    lines: list[str]
    offset: int
    from_end: bool
    partial: bool


def _read_window(path: Path, limits: ReadLimits, *, from_end: bool) -> _Window:
    size = path.stat().st_size
    byte_count = min(size, limits.max_bytes)
    offset = size - byte_count if from_end else 0
    data = read_local_bytes(path, offset=offset, max_bytes=byte_count)
    starts_mid_line = offset > 0 and read_local_bytes(
        path, offset=offset - 1, max_bytes=1
    ) not in (b"\n", b"\r")
    at_end = offset + len(data) >= size
    return _Window(
        data=data,
        lines=_complete_lines(data, starts_mid_line=starts_mid_line, at_end=at_end),
        offset=offset,
        from_end=from_end,
        partial=len(data) < size,
    )


def _unreadable(metadata: SourceMetadata) -> LogReadResult:
    return LogReadResult(
        entries=[],
        line_count=0,
        byte_count=0,
        truncated=False,
        source_metadata=metadata,
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


def _complete_lines(data: bytes, *, starts_mid_line: bool, at_end: bool) -> list[str]:
    lines = data.splitlines(keepends=True)
    if starts_mid_line and lines:
        lines = lines[1:]
    if not at_end and lines and not lines[-1].endswith((b"\n", b"\r")):
        lines = lines[:-1]
    return [line.decode("utf-8", errors="replace") for line in lines]
