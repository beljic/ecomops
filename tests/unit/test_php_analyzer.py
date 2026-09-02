from ecomops.analyzers.rules.php import PhpAnalyzer
from ecomops.core.models import AnalysisContext, LogEntry, LogSource, Severity


def test_php_analyzer_detects_memory_exhaustion() -> None:
    entry = LogEntry(
        source="php_memory.log",
        message="PHP Fatal error: Allowed memory size exhausted",
        raw="PHP Fatal error: Allowed memory size exhausted",
        line_number=1,
    )

    findings = PhpAnalyzer().analyze(
        [entry], AnalysisContext(source=LogSource(type="local", path="php_memory.log"))
    )

    assert len(findings) == 1
    assert findings[0].severity is Severity.high
    assert findings[0].count == 1
    assert findings[0].evidence[0].line_number == 1
