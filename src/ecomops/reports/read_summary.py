from datetime import datetime

from ecomops.core.models import (
    AnalysisReport,
    ParseStats,
    SamplingMetadata,
    SourceMetadata,
)
from ecomops.logs.time_ranges import TimeRange


def read_summary_lines(report: AnalysisReport) -> list[str]:
    """Describe what was read, recognized, and filtered, shared by text renderers."""
    lines: list[str] = []
    source = report.source_metadata
    if source is not None:
        lines.append(describe_source(source))

    sampling = report.sampling
    if sampling is not None:
        lines.append(describe_sample(sampling))

    stats = report.parse_stats
    if stats is not None and source is not None and source.error is None:
        lines.append(describe_parse(stats))
        lines.append(f"Filtered out by time range: {stats.filtered_out_lines}")
        lines.append(f"Analyzed entries: {report.line_count}")
        levels = describe_levels(stats)
        if levels is not None:
            lines.append(levels)

    if sampling is not None and sampling.sampled_range is not None:
        lines.append(f"Sampled range: {_range(sampling.sampled_range)}")
    if source is not None and report.actual_range is not None:
        lines.append(f"Analyzed range: {_range(report.actual_range)}")
    lines.extend(f"Warning: {warning}" for warning in report.warnings)
    return lines


def describe_source(source: SourceMetadata) -> str:
    state = [
        {True: "exists", False: "missing", None: "existence unknown"}[source.exists],
        "readable" if source.readable else "unreadable",
    ]
    if source.size_bytes is not None:
        state.append(f"{source.size_bytes} bytes")
    if source.modified_at is not None:
        state.append(f"modified {_iso(source.modified_at)}")
    detail = f" ({source.error})" if source.error is not None else ""
    return f"Source: {', '.join(state)}{detail}"


def describe_sample(sampling: SamplingMetadata) -> str:
    window = "first" if sampling.direction == "head" else "last"
    return (
        f"Sample: {sampling.direction} ({window} <= {sampling.max_bytes} bytes, "
        f"<= {sampling.max_lines} lines): {sampling.sampled_bytes} bytes, "
        f"{sampling.complete_lines} complete lines"
    )


def describe_parse(stats: ParseStats) -> str:
    return (
        f"Parsed: {stats.parsed_lines} recognized, {stats.unparsed_lines} unrecognized"
    )


def describe_levels(stats: ParseStats) -> str | None:
    if not stats.level_counts:
        return None
    levels = ", ".join(
        f"{level}={count}" for level, count in sorted(stats.level_counts.items())
    )
    return f"Levels in sample: {levels}"


def _range(value: TimeRange) -> str:
    start = "-" if value.start is None else _iso(value.start)
    end = "-" if value.end is None else _iso(value.end)
    return f"{start} .. {end}"


def _iso(value: datetime) -> str:
    return value.isoformat()
