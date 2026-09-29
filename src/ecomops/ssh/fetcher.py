from __future__ import annotations

import os
from collections.abc import Sequence
from contextlib import AbstractContextManager, nullcontext
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from ecomops.config.schema import LogAliasConfig, SSHConnectionConfig
from ecomops.core.exceptions import SSHPermissionDeniedError, SSHTransportError
from ecomops.core.models import (
    LogReadResult,
    SamplingMetadata,
    SourceMetadata,
)
from ecomops.logs.filtering import filter_by_time, time_range_of
from ecomops.logs.inspection import LogFileCandidate, LogFileListing, newest_first
from ecomops.logs.parsers import parse_lines_with_stats
from ecomops.logs.sources import ReadLimits
from ecomops.logs.time_ranges import TimeRange

from .client import (
    ParamikoSSHClient,
    RemoteCommandFailedError,
    RemoteFileMissing,
    RemoteFileStat,
    RemoteListing,
    RemoteReadResult,
)

_UNAVAILABLE = {
    "not_found": "file not found",
    "permission_denied": (
        "permission denied: the file or a folder above it is not accessible"
    ),
    "unknown": "file not found or folder not accessible",
}
_NOT_REGULAR_FILE = (
    "not a regular file, or a symlink in its path (symlinks are not followed)"
)


class _TailClient(Protocol):
    def read_tail(
        self,
        path: str,
        *,
        max_lines: int,
        max_bytes: int,
        timeout_seconds: int,
        password: str | None = None,
    ) -> RemoteReadResult: ...

    def stat_file(
        self,
        path: str,
        *,
        timeout_seconds: int,
        password: str | None = None,
        parents: Sequence[str] = (),
    ) -> RemoteFileStat | RemoteFileMissing: ...

    def list_files(
        self,
        directory: str,
        pattern: str,
        *,
        timeout_seconds: int,
        password: str | None = None,
    ) -> RemoteListing: ...


class SSHLogSource:
    """Parse a bounded, read-only SSH tail into the common log result model."""

    def __init__(
        self,
        connection: SSHConnectionConfig,
        *,
        client: _TailClient | None = None,
        password: str | None = None,
        allowed_dirs: Sequence[Path],
    ) -> None:
        self._client = client or ParamikoSSHClient(connection)
        self._password = password
        self._session: AbstractContextManager[None] = nullcontext()
        self._allowed_dirs = [PurePosixPath(os.path.normpath(d)) for d in allowed_dirs]

    def __enter__(self) -> SSHLogSource:
        """Use one SSH login for every operation until the block ends."""
        self._session = (
            self._client.session()
            if isinstance(self._client, ParamikoSSHClient)
            else nullcontext()
        )
        self._session.__enter__()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._session.__exit__(None, None, None)

    def _auth(self) -> dict[str, Any]:
        return {} if self._password is None else {"password": self._password}

    def _stat(
        self, path: str, timeout_seconds: int
    ) -> RemoteFileStat | RemoteFileMissing:
        """Check ``path`` and every folder between it and its allowed log folder."""
        parents = self._parents_below_allowed_dir(path)
        extra: dict[str, Any] = {"parents": parents} if parents else {}
        return self._client.stat_file(
            path, timeout_seconds=timeout_seconds, **self._auth(), **extra
        )

    def _allowed_base(self, folder: str) -> PurePosixPath | None:
        """The deepest allowed log folder containing ``folder``, if any."""
        target = PurePosixPath(os.path.normpath(folder))
        containing = [
            allowed
            for allowed in self._allowed_dirs
            if allowed == target or allowed in target.parents
        ]
        return max(containing, key=lambda allowed: len(allowed.parts), default=None)

    def _parents_below_allowed_dir(self, path: str) -> list[str]:
        target = PurePosixPath(os.path.normpath(path))
        base = self._allowed_base(str(target.parent))
        if base is None:
            return []
        parents = [parent for parent in target.parents if base in parent.parents]
        return [str(parent) for parent in reversed(parents)]

    def list_candidates(
        self,
        directory: Path,
        pattern: str,
        *,
        timeout_seconds: int,
        allowed_dirs: list[Path] | None = None,
    ) -> LogFileListing:
        """List glob candidates with the fixed ``find`` builder.

        The folder and pattern passed the log path policy during project
        validation (``allowed_dirs`` is not needed here); ``find -type f``
        skips symlinks and ``-maxdepth 1`` keeps the listing in one directory.
        """
        if self._allowed_base(str(directory)) is None:
            return newest_first(str(directory), pattern, [], truncated=False)
        folder = self._stat(str(directory), timeout_seconds)
        if isinstance(folder, RemoteFileMissing) or not folder.is_directory:
            # Missing folder, or a symlink in the folder path: list nothing.
            return newest_first(str(directory), pattern, [], truncated=False)
        listing = self._client.list_files(
            str(directory), pattern, timeout_seconds=timeout_seconds, **self._auth()
        )
        files = [
            LogFileCandidate(
                path=str(directory / entry.name),
                size_bytes=entry.size_bytes,
                modified_at=entry.modified_at,
            )
            for entry in listing.entries
        ]
        return newest_first(str(directory), pattern, files, truncated=listing.truncated)

    def inspect(self, alias: LogAliasConfig, limits: ReadLimits) -> LogReadResult:
        """Check the file, then parse one bounded tail sample; no analyzers run."""
        metadata = self._checked_metadata(alias.path, limits.timeout_seconds)
        if not metadata.readable:
            return _unreadable_result(metadata)
        return self._tail(
            alias,
            limits,
            TimeRange(start=None, end=None),
            metadata,
            report_transport_errors=True,
        )

    def read(
        self,
        alias: LogAliasConfig,
        limits: ReadLimits,
        time_range: TimeRange,
    ) -> LogReadResult:
        """Check that the path is a regular file (no symlink), then tail it."""
        metadata = self._checked_metadata(alias.path, limits.timeout_seconds)
        if not metadata.readable:
            return _unreadable_result(metadata)
        return self._tail(
            alias, limits, time_range, metadata, report_transport_errors=False
        )

    def _checked_metadata(self, path: str, timeout_seconds: int) -> SourceMetadata:
        """Check a file before reading; refuse it without SSH if not allowed."""
        folder = str(PurePosixPath(os.path.normpath(path)).parent)
        if self._allowed_base(folder) is None:
            return SourceMetadata(
                exists=None, readable=False, error="outside the allowed log folders"
            )
        file_stat = self._stat(path, timeout_seconds)
        if isinstance(file_stat, RemoteFileMissing):
            return SourceMetadata(
                exists=False if file_stat.reason == "not_found" else None,
                readable=False,
                error=_UNAVAILABLE[file_stat.reason],
            )
        metadata = SourceMetadata(
            exists=True,
            readable=True,
            size_bytes=file_stat.size_bytes,
            modified_at=file_stat.modified_at,
        )
        if not file_stat.is_regular_file:
            return metadata.model_copy(
                update={"readable": False, "error": _NOT_REGULAR_FILE}
            )
        return metadata

    def _tail(
        self,
        alias: LogAliasConfig,
        limits: ReadLimits,
        time_range: TimeRange,
        metadata: SourceMetadata,
        *,
        report_transport_errors: bool,
    ) -> LogReadResult:
        """Tail a checked file; keep the check's size and mtime in the result."""
        try:
            result = self._read_checked_file(alias, limits, time_range)
        except SSHPermissionDeniedError:
            raise
        except RemoteCommandFailedError as error:
            message = (
                "permission denied reading the file"
                if error.reason == "permission_denied"
                else "read failed"
            )
            return _unreadable_result(
                metadata.model_copy(update={"readable": False, "error": message})
            )
        except SSHTransportError:
            if not report_transport_errors:
                raise
            return _unreadable_result(
                metadata.model_copy(update={"readable": False, "error": "read failed"})
            )
        return result.model_copy(update={"source_metadata": metadata})

    def _read_checked_file(
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
            **self._auth(),
        )
        lines = [
            line.decode("utf-8", errors="replace")
            for line in remote.data.splitlines(keepends=True)
        ]
        parsed = parse_lines_with_stats(
            lines, source=alias.path, client_ip_source=alias.client_ip_source
        )
        entries = [
            entry.model_copy(update={"line_number": None}) for entry in parsed.entries
        ]
        sampled_range = time_range_of(entries)
        entries = filter_by_time(entries, time_range)

        return LogReadResult(
            entries=entries,
            line_count=len(entries),
            byte_count=remote.byte_count,
            truncated=remote.truncated or time_range.exact_selection,
            actual_range=time_range_of(entries),
            # Replaced by the file check's metadata in ``_tail``.
            source_metadata=SourceMetadata(exists=True, readable=True),
            parse_stats=parsed.stats.model_copy(
                update={"filtered_out_lines": len(parsed.entries) - len(entries)}
            ),
            sampling=SamplingMetadata(
                direction="tail",
                max_bytes=limits.max_bytes,
                max_lines=limits.max_lines,
                sampled_bytes=remote.byte_count,
                complete_lines=len(lines),
                sampled_range=sampled_range,
            ),
        )


def _unreadable_result(metadata: SourceMetadata) -> LogReadResult:
    return LogReadResult(
        entries=[],
        line_count=0,
        byte_count=0,
        truncated=False,
        source_metadata=metadata,
    )
