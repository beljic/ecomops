from collections.abc import Sequence

from ecomops.analyzers.rules._matching import finding_for_matches
from ecomops.core.models import AnalysisContext, Finding, LogEntry, Severity


class CronAnalyzer:
    id = "cron"

    def analyze(
        self, entries: Sequence[LogEntry], context: AnalysisContext
    ) -> list[Finding]:
        finding = finding_for_matches(
            entries,
            r"cron.*failed|failed.*cron",
            "cron.failed",
            "Cron job failed",
            Severity.high,
            "cron",
        )
        return [finding] if finding else []
