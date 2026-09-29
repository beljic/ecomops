import json
from datetime import UTC, datetime

import pytest

from ecomops.core.models import (
    AnalysisReport,
    Finding,
    LogSource,
    ParseStats,
    SamplingMetadata,
    Severity,
    SourceMetadata,
)
from ecomops.logs.time_ranges import TimeRange
from ecomops.reports.json import render_json
from ecomops.reports.markdown import render_markdown
from ecomops.reports.terminal import render_terminal


def report_with_finding() -> AnalysisReport:
    return AnalysisReport(
        source=LogSource(type="local", project="example-shop", alias="php"),
        findings=[
            Finding(
                id="php-memory",
                title="PHP memory exhausted",
                severity=Severity.high,
                category="php",
                count=2,
                recommended_steps=["Check memory_limit."],
            )
        ],
        generated_at=datetime(2026, 9, 7, tzinfo=UTC),
        connection_type="local",
        line_count=4,
        byte_count=128,
        truncated=True,
    )


def test_json_renderer_produces_complete_serializable_report() -> None:
    rendered = json.loads(render_json(report_with_finding()))

    assert rendered["source"]["project"] == "example-shop"
    assert rendered["findings"][0]["severity"] == "high"
    assert rendered["truncated"] is True


def test_markdown_renderer_includes_metadata_and_findings() -> None:
    rendered = render_markdown(report_with_finding())

    assert "# EcomOps Analysis" in rendered
    assert "Connection: `local`" in rendered
    assert "Sampling: `bounded`" in rendered
    assert "### [high] PHP memory exhausted" in rendered
    assert "Check memory_limit." in rendered


def report_with_read_metadata(
    *,
    source: SourceMetadata | None = None,
    stats: ParseStats | None = None,
    line_count: int = 1,
    findings: list[Finding] | None = None,
) -> AnalysisReport:
    return AnalysisReport(
        source=LogSource(type="local", project="example-shop", alias="php"),
        findings=findings or [],
        generated_at=datetime(2026, 9, 7, tzinfo=UTC),
        line_count=line_count,
        byte_count=96,
        truncated=True,
        source_metadata=source
        or SourceMetadata(
            exists=True,
            readable=True,
            size_bytes=4_096,
            modified_at=datetime(2026, 9, 7, 11, 0, tzinfo=UTC),
        ),
        parse_stats=stats
        or ParseStats(
            total_lines=3,
            parsed_lines=2,
            unparsed_lines=1,
            level_counts={"ERROR": 1, "CRITICAL": 1},
            filtered_out_lines=1,
        ),
        sampling=SamplingMetadata(
            direction="tail",
            max_bytes=1_000,
            max_lines=50,
            sampled_bytes=96,
            complete_lines=3,
            sampled_range=TimeRange(
                start=datetime(2026, 9, 7, 9, 0, tzinfo=UTC),
                end=datetime(2026, 9, 7, 10, 30, tzinfo=UTC),
            ),
        ),
        actual_range=TimeRange(
            start=datetime(2026, 9, 7, 10, 30, tzinfo=UTC),
            end=datetime(2026, 9, 7, 10, 30, tzinfo=UTC),
        ),
    )


RENDERERS = [render_terminal, render_markdown]


@pytest.mark.parametrize("render", RENDERERS)
def test_text_renderers_show_source_sample_parse_and_ranges(render: object) -> None:
    assert callable(render)
    rendered = render(report_with_read_metadata())

    assert "Source: exists, readable, 4096 bytes" in rendered
    assert "modified 2026-09-07T11:00:00+00:00" in rendered
    assert "Sample: tail (last <= 1000 bytes, <= 50 lines)" in rendered
    assert "96 bytes, 3 complete lines" in rendered
    assert "Parsed: 2 recognized, 1 unrecognized" in rendered
    assert "Filtered out by time range: 1" in rendered
    assert "Analyzed entries: 1" in rendered
    assert "Levels in sample: CRITICAL=1, ERROR=1" in rendered
    assert (
        "Sampled range: 2026-09-07T09:00:00+00:00 .. 2026-09-07T10:30:00+00:00"
        in rendered
    )
    assert (
        "Analyzed range: 2026-09-07T10:30:00+00:00 .. 2026-09-07T10:30:00+00:00"
        in rendered
    )
    assert "No findings." in rendered


@pytest.mark.parametrize("render", RENDERERS)
def test_text_renderers_warn_instead_of_no_findings_when_parser_recognized_nothing(
    render: object,
) -> None:
    assert callable(render)
    report = report_with_read_metadata(
        stats=ParseStats(total_lines=4, parsed_lines=0, unparsed_lines=4),
        line_count=4,
    )

    rendered = render(report)

    assert "No findings." not in rendered
    assert (
        "Warning: parser recognized none of 4 sampled lines; "
        "the log format may be unsupported" in rendered
    )


@pytest.mark.parametrize("render", RENDERERS)
def test_text_renderers_explain_a_missing_source(render: object) -> None:
    assert callable(render)
    report = report_with_read_metadata(
        source=SourceMetadata(exists=False, readable=False, error="file not found"),
        stats=ParseStats(),
        line_count=0,
    ).model_copy(update={"sampling": None, "actual_range": None})

    rendered = render(report)

    assert "No findings." not in rendered
    assert "Source: missing, unreadable (file not found)" in rendered
    assert "Warning: source unavailable: file not found" in rendered


@pytest.mark.parametrize("render", RENDERERS)
def test_text_renderers_explain_an_empty_file(render: object) -> None:
    assert callable(render)
    report = report_with_read_metadata(
        source=SourceMetadata(exists=True, readable=True, size_bytes=0),
        stats=ParseStats(),
        line_count=0,
    )

    rendered = render(report)

    assert "No findings." not in rendered
    assert "Warning: log file is empty" in rendered


@pytest.mark.parametrize("render", RENDERERS)
def test_text_renderers_explain_entries_removed_by_the_time_filter(
    render: object,
) -> None:
    assert callable(render)
    report = report_with_read_metadata(
        stats=ParseStats(
            total_lines=3, parsed_lines=3, unparsed_lines=0, filtered_out_lines=3
        ),
        line_count=0,
    )

    rendered = render(report)

    assert "No findings." not in rendered
    assert "Warning: all 3 sampled lines were outside the time range" in rendered


def test_json_renderer_exposes_structured_read_metadata_and_warnings() -> None:
    report = report_with_read_metadata(
        stats=ParseStats(total_lines=4, parsed_lines=0, unparsed_lines=4),
        line_count=4,
    )

    rendered = json.loads(render_json(report))

    assert rendered["source_metadata"]["size_bytes"] == 4_096
    assert rendered["parse_stats"]["unparsed_lines"] == 4
    assert rendered["sampling"]["direction"] == "tail"
    assert rendered["sampling"]["sampled_range"]["start"] == "2026-09-07T09:00:00Z"
    assert rendered["warnings"] == [
        "parser recognized none of 4 sampled lines; the log format may be unsupported"
    ]


def test_reports_without_read_metadata_keep_the_previous_output() -> None:
    report = report_with_finding().model_copy(update={"findings": []})

    assert render_terminal(report).endswith("Sampling: bounded\nNo findings.")
    assert json.loads(render_json(report))["warnings"] == []
