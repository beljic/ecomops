"""Read-only log inspection: file discovery and health, without analyzers."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path

from pydantic import BaseModel, computed_field

from ecomops.config.log_policy import LogPathPolicyViolation, check_log_path
from ecomops.core.models import (
    ParseStats,
    SamplingMetadata,
    SourceMetadata,
    read_warnings,
)
from ecomops.ssh.read_only import MAX_LIST_ENTRIES


class LogFileCandidate(BaseModel):
    path: str
    size_bytes: int | None = None
    modified_at: datetime | None = None


class LogFileListing(BaseModel):
    """Files matching one glob alias, newest first."""

    directory: str
    pattern: str
    files: list[LogFileCandidate]
    truncated: bool = False


class LogInspection(BaseModel):
    project: str
    alias: str
    log_type: str
    connection_type: str
    configured_path: str
    listing: LogFileListing | None = None
    selected_path: str | None = None
    source_metadata: SourceMetadata
    parse_stats: ParseStats | None = None
    sampling: SamplingMetadata | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def warnings(self) -> list[str]:
        stats = self.parse_stats
        return read_warnings(
            self.source_metadata,
            stats,
            analyzed_lines=0 if stats is None else stats.total_lines,
        )


class ProjectCheck(BaseModel):
    project: str
    connection_type: str
    aliases: list[LogInspection]


def newest_first(
    directory: str, pattern: str, files: list[LogFileCandidate], *, truncated: bool
) -> LogFileListing:
    ordered = sorted(
        files,
        key=lambda candidate: (
            candidate.modified_at or datetime.min.replace(tzinfo=UTC),
            candidate.path,
        ),
        reverse=True,
    )
    return LogFileListing(
        directory=directory, pattern=pattern, files=ordered, truncated=truncated
    )


def list_local_candidates(
    directory: Path, pattern: str, allowed_dirs: list[Path]
) -> LogFileListing:
    """List regular, non-symlink log files matching ``pattern``.

    Every candidate's real path must pass the log path policy for
    ``allowed_dirs``. Scans one directory only and stops after
    ``MAX_LIST_ENTRIES`` matches.
    """
    real_dirs = [directory.resolve() for directory in allowed_dirs]
    files: list[LogFileCandidate] = []
    truncated = False
    try:
        entries = os.scandir(directory)
    except OSError:
        return newest_first(str(directory), pattern, [], truncated=False)
    with entries:
        for entry in entries:
            if not fnmatchcase(entry.name, pattern):
                continue
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                continue
            path = Path(entry.path)
            try:
                check_log_path(path.resolve(), real_dirs)
            except LogPathPolicyViolation:
                continue
            if len(files) >= MAX_LIST_ENTRIES:
                truncated = True
                break
            file_stat = entry.stat(follow_symlinks=False)
            files.append(
                LogFileCandidate(
                    path=str(path),
                    size_bytes=file_stat.st_size,
                    modified_at=datetime.fromtimestamp(file_stat.st_mtime, tz=UTC),
                )
            )
    return newest_first(str(directory), pattern, files, truncated=truncated)
