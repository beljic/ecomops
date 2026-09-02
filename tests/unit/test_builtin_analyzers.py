import pytest

from ecomops.analyzers.rules.cron import CronAnalyzer
from ecomops.analyzers.rules.magento import MagentoAnalyzer
from ecomops.analyzers.rules.mysql import MySQLAnalyzer
from ecomops.analyzers.rules.nginx import NginxAnalyzer
from ecomops.core.models import AnalysisContext, LogEntry, LogSource, Severity


def entry(message: str, line: int = 1) -> LogEntry:
    return LogEntry(source="test.log", message=message, raw=message, line_number=line)


def context() -> AnalysisContext:
    return AnalysisContext(source=LogSource(type="local", path="test.log"))


@pytest.mark.parametrize(
    ("analyzer", "message", "finding_id"),
    [
        (MagentoAnalyzer(), "report.CRITICAL: No such entity", "magento.critical"),
        (
            NginxAnalyzer(),
            "upstream timed out while reading response",
            "nginx.upstream_timeout",
        ),
        (MySQLAnalyzer(), "Deadlock found when trying to get lock", "mysql.deadlock"),
        (CronAnalyzer(), "Cron job failed: import_products", "cron.failed"),
    ],
)
def test_builtin_analyzers_detect_required_signals(
    analyzer: object, message: str, finding_id: str
) -> None:
    findings = analyzer.analyze([entry(message)], context())  # type: ignore[attr-defined]

    assert findings[0].id == finding_id
    assert findings[0].evidence[0].sample == message
    assert findings[0].severity in {Severity.critical, Severity.high, Severity.medium}
