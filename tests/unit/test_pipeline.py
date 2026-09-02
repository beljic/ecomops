from ecomops.analyzers.pipeline import AnalyzerPipeline
from ecomops.analyzers.rules.mysql import MySQLAnalyzer
from ecomops.core.models import AnalysisContext, LogEntry, LogSource


def test_pipeline_aggregates_findings_by_id() -> None:
    entries = [
        LogEntry(
            source="db.log",
            message="Deadlock found",
            raw="Deadlock found",
            line_number=1,
        ),
        LogEntry(
            source="db.log",
            message="Deadlock found",
            raw="Deadlock found",
            line_number=2,
        ),
    ]
    source = LogSource(type="local", path="db.log")

    report = AnalyzerPipeline([MySQLAnalyzer()]).run(
        entries, AnalysisContext(source=source)
    )

    assert len(report.findings) == 1
    assert report.findings[0].count == 2
    assert len(report.findings[0].evidence) == 2
