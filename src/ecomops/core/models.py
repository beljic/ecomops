from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, computed_field

from ecomops.logs.time_ranges import TimeRange


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class LogSource(BaseModel):
    type: Literal["local", "ssh", "stdin"]
    path: str | None = None
    project: str | None = None
    alias: str | None = None
    log_type: str | None = None


ClientIpSource = Literal["socket", "x_forwarded_for"]


class AccessRequest(BaseModel):
    """Structured fields of one web-server access log line.

    ``client_ip`` follows the alias ``client_ip_source`` policy; the remote
    user field is intentionally not kept.
    """

    client_ip: str
    socket_ip: str
    forwarded_for: list[str] = Field(default_factory=list)
    method: str | None = None
    path: str | None = None
    protocol: str | None = None
    status: int
    bytes_sent: int | None = None
    referer: str | None = None
    user_agent: str | None = None


class LogEntry(BaseModel):
    timestamp: datetime | None = None
    level: str | None = None
    source: str
    message: str
    raw: str
    line_number: int | None = None
    access: AccessRequest | None = None


class SourceMetadata(BaseModel):
    """What is known about the log file itself, independent of its content.

    ``exists`` is ``None`` when it cannot be determined, for example when a
    folder above the file is not accessible.
    """

    exists: bool | None
    readable: bool
    size_bytes: int | None = None
    modified_at: datetime | None = None
    error: str | None = None


class ParseStats(BaseModel):
    """How the sampled lines were recognized and filtered.

    ``level_counts`` covers every recognized line in the sample, before the
    time filter, using the normalized uppercase level (``main.CRITICAL`` ->
    ``CRITICAL``).
    """

    total_lines: int = 0
    parsed_lines: int = 0
    unparsed_lines: int = 0
    level_counts: dict[str, int] = Field(default_factory=dict)
    format_counts: dict[str, int] = Field(default_factory=dict)
    filtered_out_lines: int = 0


class SamplingMetadata(BaseModel):
    """Which bounded window of the file was read."""

    direction: Literal["head", "tail"]
    max_bytes: int
    max_lines: int
    sampled_bytes: int
    complete_lines: int
    sampled_range: TimeRange | None = None


class LogReadResult(BaseModel):
    entries: list[LogEntry]
    line_count: int
    byte_count: int
    truncated: bool
    actual_range: TimeRange | None = None
    source_metadata: SourceMetadata | None = None
    parse_stats: ParseStats | None = None
    sampling: SamplingMetadata | None = None


class Evidence(BaseModel):
    message: str
    source: str
    sample: str
    line_number: int | None = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    root_cause_guess: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    recommended_steps: list[str] = Field(default_factory=list)


class AnalysisContext(BaseModel):
    source: LogSource
    project_name: str | None = None
    platform: str | None = None
    since: str | None = None
    analyzers: list[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    source: LogSource
    findings: list[Finding]
    generated_at: datetime
    summary: str | None = None
    ai_enriched: bool = False
    ai_provider: str | None = None
    connection_type: str = "local"
    remote_access: bool = False
    line_count: int = 0
    byte_count: int = 0
    truncated: bool = False
    actual_range: TimeRange | None = None
    source_metadata: SourceMetadata | None = None
    parse_stats: ParseStats | None = None
    sampling: SamplingMetadata | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def warnings(self) -> list[str]:
        """Why the analyzed sample may not support a "no findings" conclusion."""
        return read_warnings(
            self.source_metadata, self.parse_stats, analyzed_lines=self.line_count
        )


def read_warnings(
    source: SourceMetadata | None,
    stats: ParseStats | None,
    *,
    analyzed_lines: int,
) -> list[str]:
    if source is None:
        return []
    if source.error is not None:
        return [f"source unavailable: {source.error}"]
    if stats is None:
        return []
    if stats.total_lines == 0:
        if source.size_bytes == 0:
            return ["log file is empty"]
        return ["no complete lines in the sampled window"]
    if stats.parsed_lines == 0:
        return [
            f"parser recognized none of {stats.total_lines} sampled lines; "
            "the log format may be unsupported"
        ]
    if analyzed_lines == 0 and stats.filtered_out_lines > 0:
        return [
            f"all {stats.filtered_out_lines} sampled lines were outside the time range"
        ]
    return []


class CountItem(BaseModel):
    value: str
    count: int


class IpStatusCounts(BaseModel):
    client_ip: str
    total_requests: int
    error_requests: int
    status_counts: dict[str, int]


class TrafficSummary(BaseModel):
    """Bounded top-N counts over parsed access entries; never raw lines."""

    total_requests: int
    unique_client_ips: int
    top_client_ips: list[CountItem]
    status_counts: dict[str, int]
    top_paths: list[CountItem]
    top_user_agents: list[CountItem]
    peak_requests_per_minute: int
    busiest_minutes: list[CountItem]
    status_by_ip: list[IpStatusCounts] = Field(default_factory=list)


class ReadContext(BaseModel):
    """What was read for a structured tool, without the log content itself."""

    project: str
    alias: str
    path: str
    connection_type: str
    line_count: int
    byte_count: int
    truncated: bool
    actual_range: TimeRange | None = None
    source_metadata: SourceMetadata | None = None
    parse_stats: ParseStats | None = None
    sampling: SamplingMetadata | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def warnings(self) -> list[str]:
        return read_warnings(
            self.source_metadata, self.parse_stats, analyzed_lines=self.line_count
        )


class TrafficReport(BaseModel):
    read: ReadContext
    summary: TrafficSummary

    @computed_field  # type: ignore[prop-decorator]
    @property
    def warnings(self) -> list[str]:
        warnings = list(self.read.warnings)
        if self.summary.total_requests == 0 and self.read.line_count > 0:
            warnings.append("no web access log entries in the analyzed sample")
        return warnings


class SecurityIndicator(BaseModel):
    id: str
    title: str
    count: int
    top_client_ips: list[CountItem]
    samples: list[str]
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class TorClassification(BaseModel):
    """Tor matches against a locally configured CIDR list only."""

    status: Literal["unavailable", "checked"]
    matched_requests: int = 0
    top_client_ips: list[CountItem] = Field(default_factory=list)


class SecurityScan(BaseModel):
    requests_scanned: int
    indicators: list[SecurityIndicator]
    tor: TorClassification


class SecurityReport(BaseModel):
    read: ReadContext
    scan: SecurityScan

    @computed_field  # type: ignore[prop-decorator]
    @property
    def warnings(self) -> list[str]:
        warnings = list(self.read.warnings)
        if self.scan.requests_scanned == 0 and self.read.line_count > 0:
            warnings.append("no web access log entries in the analyzed sample")
        return warnings
