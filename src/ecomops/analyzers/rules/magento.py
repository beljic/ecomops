from collections.abc import Sequence

from ecomops.analyzers.rules._matching import finding_for_matches
from ecomops.core.models import AnalysisContext, Finding, LogEntry, Severity


class MagentoAnalyzer:
    id = "magento"

    def analyze(
        self, entries: Sequence[LogEntry], context: AnalysisContext
    ) -> list[Finding]:
        finding = finding_for_matches(
            entries,
            r"(?:report|main)\.CRITICAL",
            "magento.critical",
            "Magento critical error",
            Severity.high,
            "magento",
        )
        return [finding] if finding else []
