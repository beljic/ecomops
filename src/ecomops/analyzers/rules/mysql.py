from collections.abc import Sequence

from ecomops.analyzers.rules._matching import finding_for_matches
from ecomops.core.models import AnalysisContext, Finding, LogEntry, Severity


class MySQLAnalyzer:
    id = "mysql"

    def analyze(
        self, entries: Sequence[LogEntry], context: AnalysisContext
    ) -> list[Finding]:
        rules = [
            (r"deadlock found", "mysql.deadlock", "MySQL deadlock", Severity.high),
            (
                r"lock wait timeout exceeded",
                "mysql.lock_wait_timeout",
                "MySQL lock wait timeout",
                Severity.high,
            ),
        ]
        findings: list[Finding] = []
        for pattern, finding_id, title, severity in rules:
            finding = finding_for_matches(
                entries, pattern, finding_id, title, severity, "mysql"
            )
            if finding:
                findings.append(finding)
        return findings
