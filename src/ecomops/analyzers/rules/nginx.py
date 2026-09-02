from collections.abc import Sequence

from ecomops.analyzers.rules._matching import finding_for_matches
from ecomops.core.models import AnalysisContext, Finding, LogEntry, Severity


class NginxAnalyzer:
    id = "nginx"

    def analyze(
        self, entries: Sequence[LogEntry], context: AnalysisContext
    ) -> list[Finding]:
        finding = finding_for_matches(
            entries,
            r"upstream timed out",
            "nginx.upstream_timeout",
            "Nginx upstream timeout",
            Severity.high,
            "nginx",
        )
        return [finding] if finding else []
