from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

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


class LogEntry(BaseModel):
    timestamp: datetime | None = None
    level: str | None = None
    source: str
    message: str
    raw: str
    line_number: int | None = None


class LogReadResult(BaseModel):
    entries: list[LogEntry]
    line_count: int
    byte_count: int
    truncated: bool
    actual_range: TimeRange | None = None


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
    connection_type: str = "local"
    remote_access: bool = False
    line_count: int = 0
    byte_count: int = 0
    truncated: bool = False
