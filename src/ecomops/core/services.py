from datetime import UTC, datetime

from ecomops.analyzers.pipeline import AnalyzerPipeline
from ecomops.analyzers.rules.cron import CronAnalyzer
from ecomops.analyzers.rules.magento import MagentoAnalyzer
from ecomops.analyzers.rules.mysql import MySQLAnalyzer
from ecomops.analyzers.rules.nginx import NginxAnalyzer
from ecomops.analyzers.rules.php import PhpAnalyzer
from ecomops.config.projects import ProjectRegistry
from ecomops.core.models import AnalysisContext, AnalysisReport
from ecomops.logs.resolver import resolve_source
from ecomops.logs.sources import ReadLimits
from ecomops.logs.time_ranges import TimeRange
from ecomops.ssh.read_only import MAX_READ_LINES

DEFAULT_MAX_BYTES = 1_000_000
DEFAULT_TIMEOUT_SECONDS = 10


def analyze_project_log(
    project: str,
    alias: str,
    since: str = "all",
    until: str | None = None,
    max_lines: int | None = None,
    max_bytes: int | None = None,
    ssh_password: str | None = None,
) -> AnalysisReport:
    """Read a configured project alias and run the deterministic analyzers."""
    project_config = ProjectRegistry.load().get(project)
    alias_config = project_config.resolve_log_alias(alias)
    if ssh_password is None:
        source = resolve_source(project_config, alias)
    else:
        source = resolve_source(project_config, alias, ssh_password=ssh_password)
    time_range = _resolve_time_range(since, until)
    limits = ReadLimits(
        max_lines=MAX_READ_LINES if max_lines is None else max_lines,
        max_bytes=DEFAULT_MAX_BYTES if max_bytes is None else max_bytes,
        timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
    )
    resolved_alias = alias_config.model_copy(
        update={"path": str(project_config.resolve_log_path(alias))}
    )
    read_result = source.read(resolved_alias, limits, time_range)
    context = AnalysisContext(
        source=project_config.resolve_log_source(alias),
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
        }
    )


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
