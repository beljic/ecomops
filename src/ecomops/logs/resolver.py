import os

from ecomops.config.schema import (
    LocalConnectionConfig,
    ProjectConfig,
    SSHConnectionConfig,
)
from ecomops.logs.inspection import LogFileListing
from ecomops.logs.sources import LocalLogSource
from ecomops.ssh.fetcher import SSHLogSource


def resolve_source(
    project: ProjectConfig, alias: str, *, ssh_password: str | None = None
) -> LocalLogSource | SSHLogSource:
    """Resolve a configured alias to its fixed read-only transport."""
    project.resolve_log_alias(alias)
    if isinstance(project.connection, LocalConnectionConfig):
        return LocalLogSource()
    assert isinstance(project.connection, SSHConnectionConfig)
    allowed_dirs = project.allowed_log_dirs()
    if ssh_password is None:
        return SSHLogSource(project.connection, allowed_dirs=allowed_dirs)
    return SSHLogSource(
        project.connection, password=ssh_password, allowed_dirs=allowed_dirs
    )


def list_log_files(
    project: ProjectConfig,
    alias: str,
    source: LocalLogSource | SSHLogSource,
    *,
    timeout_seconds: int,
) -> LogFileListing:
    """List the files a configured glob alias matches, newest first."""
    directory, pattern = project.resolve_log_glob(alias)
    return source.list_candidates(
        directory,
        pattern,
        allowed_dirs=project.allowed_log_dirs(),
        timeout_seconds=timeout_seconds,
    )


def select_log_file(
    project: ProjectConfig,
    alias: str,
    source: LocalLogSource | SSHLogSource,
    *,
    timeout_seconds: int,
) -> tuple[str | None, LogFileListing | None]:
    """Return the file to read: the exact path, or the newest glob match.

    For local projects the selected path is re-checked after resolving
    symlinks, so a log path cannot lead to a file outside the log folders.
    """
    if not project.resolve_log_alias(alias).is_glob:
        selected: str | None = str(project.resolve_log_path(alias))
        listing = None
    else:
        listing = list_log_files(
            project, alias, source, timeout_seconds=timeout_seconds
        )
        selected = listing.files[0].path if listing.files else None
    if selected is not None and isinstance(project.connection, LocalConnectionConfig):
        project.check_real_log_path(os.path.realpath(selected))
    return selected, listing
