from datetime import UTC, datetime

import pytest

from ecomops.ai.enrichment import enrich_report
from ecomops.core.models import (
    AnalysisContext,
    AnalysisReport,
    Finding,
    LogSource,
    Severity,
)


def test_enrichment_uses_noop_by_default_and_marks_report() -> None:
    report = AnalysisReport(
        source=LogSource(type="local"),
        findings=[
            Finding(
                id="php-memory",
                title="PHP memory exhausted",
                severity=Severity.high,
                category="php",
            )
        ],
        generated_at=datetime(2026, 9, 7, tzinfo=UTC),
    )

    enriched = enrich_report(
        report,
        AnalysisContext(source=report.source),
        "noop",
    )

    assert enriched.findings == report.findings
    assert enriched.ai_enriched is True
    assert enriched.ai_provider == "noop"


def test_unknown_provider_is_rejected() -> None:
    report = AnalysisReport(
        source=LogSource(type="local"),
        findings=[],
        generated_at=datetime(2026, 9, 7, tzinfo=UTC),
    )

    with pytest.raises(ValueError, match="Unknown AI provider"):
        enrich_report(report, AnalysisContext(source=report.source), "remote")
