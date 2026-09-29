from datetime import UTC, datetime

from ecomops.analyzers.pipeline import AnalyzerPipeline
from ecomops.analyzers.rules.cron import CronAnalyzer
from ecomops.analyzers.rules.magento import MagentoAnalyzer
from ecomops.analyzers.rules.mysql import MySQLAnalyzer
from ecomops.analyzers.rules.nginx import NginxAnalyzer
from ecomops.analyzers.rules.php import PhpAnalyzer
from ecomops.analyzers.security import scan_security
from ecomops.analyzers.traffic import DEFAULT_TOP_N, summarize_traffic
from ecomops.config.projects import ProjectRegistry
from ecomops.config.schema import ProjectConfig, SSHConnectionConfig
from ecomops.core.exceptions import (
    LogFileNotFoundError,
    LogPathPolicyError,
    SSHPermissionDeniedError,
    SSHTransportError,
)
from ecomops.core.models import (
    AnalysisContext,
    AnalysisReport,
    LogReadResult,
    ReadContext,
    SecurityReport,
    SourceMetadata,
    TrafficReport,
)
from ecomops.logs.inspection import LogFileListing, LogInspection, ProjectCheck
from ecomops.logs.resolver import (
    list_log_files,
    resolve_source,
    select_log_file,
)
from ecomops.logs.sources import LocalLogSource, ReadLimits
from ecomops.logs.time_ranges import TimeRange
from ecomops.ssh.fetcher import SSHLogSource
from ecomops.ssh.read_only import MAX_READ_LINES

DEFAULT_MAX_BYTES = 1_000_000
DEFAULT_TIMEOUT_SECONDS = 10
INSPECTION_MAX_BYTES = 64_000
INSPECTION_MAX_LINES = 1_000


def analyze_project_log(
    project: str,
    alias: str,
    since: str = "all",
    until: str | None = None,
    max_lines: int | None = None,
    max_bytes: int | None = None,
    ssh_password: str | None = None,
    ssh_username: str | None = None,
) -> AnalysisReport:
    """Read a configured project alias and run the deterministic analyzers."""
    project_config, selected_path, read_result = _read_project_log(
        project, alias, since, until, max_lines, max_bytes, ssh_password, ssh_username
    )
    context = AnalysisContext(
        source=project_config.resolve_log_source(alias).model_copy(
            update={"path": selected_path}
        ),
        project_name=project_config.name,
        platform=project_config.platform,
        since=since,
    )
    report = AnalyzerPipeline(
        [
            PhpAnalyzer(),
            MagentoAnalyzer(),
            NginxAnalyzer(),
            MySQLAnalyzer(),
            CronAnalyzer(),
        ]
    ).run(read_result.entries, context)
    return report.model_copy(
        update={
            "connection_type": project_config.connection.type,
            "remote_access": project_config.connection.type == "ssh",
            "line_count": read_result.line_count,
            "byte_count": read_result.byte_count,
            "truncated": read_result.truncated,
            "actual_range": read_result.actual_range,
            "source_metadata": read_result.source_metadata,
            "parse_stats": read_result.parse_stats,
            "sampling": read_result.sampling,
        }
    )


def summarize_project_traffic(
    project: str,
    alias: str,
    since: str = "all",
    until: str | None = None,
    max_lines: int | None = None,
    max_bytes: int | None = None,
    ssh_password: str | None = None,
    top_n: int = DEFAULT_TOP_N,
    ssh_username: str | None = None,
) -> TrafficReport:
    """Summarize web traffic in one bounded read; no raw lines are returned."""
    project_config, selected_path, read_result = _read_project_log(
        project, alias, since, until, max_lines, max_bytes, ssh_password, ssh_username
    )
    return TrafficReport(
        read=_read_context(project_config, alias, selected_path, read_result),
        summary=summarize_traffic(read_result.entries, top_n=top_n),
    )


def scan_project_security(
    project: str,
    alias: str,
    since: str = "all",
    until: str | None = None,
    max_lines: int | None = None,
    max_bytes: int | None = None,
    ssh_password: str | None = None,
    ssh_username: str | None = None,
) -> SecurityReport:
    """Report deterministic security indicators from one bounded read."""
    project_config, selected_path, read_result = _read_project_log(
        project, alias, since, until, max_lines, max_bytes, ssh_password, ssh_username
    )
    return SecurityReport(
        read=_read_context(project_config, alias, selected_path, read_result),
        scan=scan_security(
            read_result.entries,
            tor_cidrs=project_config.security.tor_cidrs,
            login_threshold=project_config.security.login_threshold,
        ),
    )


def _read_project_log(
    project: str,
    alias: str,
    since: str,
    until: str | None,
    max_lines: int | None,
    max_bytes: int | None,
    ssh_password: str | None,
    ssh_username: str | None = None,
) -> tuple[ProjectConfig, str, LogReadResult]:
    """Resolve the alias to one policy-checked log file and read it, bounded."""
    project_config = ProjectRegistry.load().get(project)
    alias_config = project_config.resolve_log_alias(alias)
    source = _source(project_config, alias, ssh_password, ssh_username)
    selected_path, _ = select_log_file(
        project_config, alias, source, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    if selected_path is None:
        _, pattern = project_config.resolve_log_glob(alias)
        raise LogFileNotFoundError(
            f"No files match {pattern} for log alias '{alias}' "
            f"in project '{project_config.name}'."
        )
    time_range = _resolve_time_range(since, until)
    limits = ReadLimits(
        max_lines=MAX_READ_LINES if max_lines is None else max_lines,
        max_bytes=DEFAULT_MAX_BYTES if max_bytes is None else max_bytes,
        timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
    )
    resolved_alias = alias_config.model_copy(update={"path": selected_path})
    return (
        project_config,
        selected_path,
        source.read(resolved_alias, limits, time_range),
    )


def _read_context(
    project_config: ProjectConfig,
    alias: str,
    selected_path: str,
    read_result: LogReadResult,
) -> ReadContext:
    return ReadContext(
        project=project_config.name,
        alias=alias,
        path=selected_path,
        connection_type=project_config.connection.type,
        line_count=read_result.line_count,
        byte_count=read_result.byte_count,
        truncated=read_result.truncated,
        actual_range=read_result.actual_range,
        source_metadata=read_result.source_metadata,
        parse_stats=read_result.parse_stats,
        sampling=read_result.sampling,
    )


def list_project_log_files(
    project: str,
    alias: str,
    ssh_password: str | None = None,
    ssh_username: str | None = None,
) -> LogFileListing:
    """List files matched by a configured glob alias; reads no log content."""
    project_config = ProjectRegistry.load().get(project)
    source = _source(project_config, alias, ssh_password, ssh_username)
    return list_log_files(
        project_config, alias, source, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )


def inspect_project_log(
    project: str,
    alias: str,
    ssh_password: str | None = None,
    ssh_username: str | None = None,
) -> LogInspection:
    """Report file health and parser recognition for one alias; no analyzers run."""
    project_config = ProjectRegistry.load().get(project)
    return _inspect_alias(project_config, alias, ssh_password, ssh_username)


def check_project(
    project: str,
    ssh_password: str | None = None,
    ssh_username: str | None = None,
) -> ProjectCheck:
    """Inspect every configured alias of a project; no analyzers run.

    Transport failures are reported per alias. Authentication denial stops the
    whole check so callers can ask for credentials once.
    """
    project_config = ProjectRegistry.load().get(project)
    inspections: list[LogInspection] = []
    for alias in project_config.log_aliases:
        try:
            inspections.append(
                _inspect_alias(project_config, alias, ssh_password, ssh_username)
            )
        except SSHPermissionDeniedError:
            raise
        except SSHTransportError:
            inspections.append(
                _base_inspection(project_config, alias).model_copy(
                    update={
                        "source_metadata": SourceMetadata(
                            exists=False,
                            readable=False,
                            error="SSH connection or read failed",
                        )
                    }
                )
            )
    return ProjectCheck(
        project=project_config.name,
        connection_type=project_config.connection.type,
        aliases=inspections,
    )


def _base_inspection(project_config: ProjectConfig, alias: str) -> LogInspection:
    return LogInspection(
        project=project_config.name,
        alias=alias,
        log_type=project_config.resolve_log_alias(alias).type,
        connection_type=project_config.connection.type,
        configured_path=str(project_config.resolve_log_path(alias)),
        source_metadata=SourceMetadata(exists=False, readable=False),
    )


def _inspect_alias(
    project_config: ProjectConfig,
    alias: str,
    ssh_password: str | None,
    ssh_username: str | None = None,
) -> LogInspection:
    alias_config = project_config.resolve_log_alias(alias)
    source = _source(project_config, alias, ssh_password, ssh_username)
    try:
        selected_path, listing = select_log_file(
            project_config, alias, source, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
        )
    except LogPathPolicyError as error:
        return _base_inspection(project_config, alias).model_copy(
            update={
                "source_metadata": SourceMetadata(
                    exists=True, readable=False, error=str(error)
                )
            }
        )
    inspection = _base_inspection(project_config, alias).model_copy(
        update={"listing": listing, "selected_path": selected_path}
    )
    if selected_path is None:
        _, pattern = project_config.resolve_log_glob(alias)
        return inspection.model_copy(
            update={
                "source_metadata": SourceMetadata(
                    exists=False, readable=False, error=f"no files match {pattern}"
                )
            }
        )
    result = source.inspect(
        alias_config.model_copy(update={"path": selected_path}),
        ReadLimits(
            max_lines=INSPECTION_MAX_LINES,
            max_bytes=INSPECTION_MAX_BYTES,
            timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
        ),
    )
    assert result.source_metadata is not None
    return inspection.model_copy(
        update={
            "source_metadata": result.source_metadata,
            "parse_stats": result.parse_stats,
            "sampling": result.sampling,
        }
    )


def _source(
    project: ProjectConfig,
    alias: str,
    ssh_password: str | None,
    ssh_username: str | None = None,
) -> LocalLogSource | SSHLogSource:
    """Build the read-only source; an ephemeral username applies to this call only."""
    if ssh_username is not None and isinstance(project.connection, SSHConnectionConfig):
        project = project.model_copy(
            update={
                "connection": project.connection.model_copy(
                    update={"user": ssh_username}
                )
            }
        )
    if ssh_password is None:
        return resolve_source(project, alias)
    return resolve_source(project, alias, ssh_password=ssh_password)


def _resolve_time_range(since: str, until: str | None) -> TimeRange:
    now = datetime.now(UTC)
    time_range = TimeRange.parse(since, now)
    if until is None:
        return time_range

    end = TimeRange.parse(until, now).start
    if end is None:
        raise ValueError("until must be a timestamp or relative time range")
    if time_range.start is None:
        return TimeRange(start=datetime.min.replace(tzinfo=UTC), end=end)
    if end < time_range.start:
        raise ValueError("until must not be earlier than since")
    return TimeRange(start=time_range.start, end=end)
