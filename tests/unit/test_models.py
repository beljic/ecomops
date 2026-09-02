from ecomops.core.models import Finding, LogEntry, Severity


def test_log_entry_and_finding_store_analysis_data() -> None:
    entry = LogEntry(
        source="local.log",
        message="memory exhausted",
        raw="memory exhausted",
        line_number=7,
    )
    finding = Finding(
        id="php.memory_exhausted",
        title="PHP memory exhausted",
        severity=Severity.high,
        category="php",
        evidence=[],
    )

    assert entry.line_number == 7
    assert finding.severity is Severity.high
