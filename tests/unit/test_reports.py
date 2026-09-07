import json
from datetime import UTC, datetime

from ecomops.core.models import AnalysisReport, Finding, LogSource, Severity
from ecomops.reports.json import render_json
from ecomops.reports.markdown import render_markdown


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
