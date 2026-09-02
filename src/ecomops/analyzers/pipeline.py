from collections.abc import Sequence
from datetime import UTC, datetime

from ecomops.analyzers.base import Analyzer
from ecomops.core.models import AnalysisContext, AnalysisReport, Finding, LogEntry


class AnalyzerPipeline:
    def __init__(self, analyzers: Sequence[Analyzer]) -> None:
        self.analyzers = analyzers

    def run(self, entries: list[LogEntry], context: AnalysisContext) -> AnalysisReport:
        grouped: dict[str, Finding] = {}
        for analyzer in self.analyzers:
            try:
                findings = analyzer.analyze(entries, context)
            except Exception:
                continue
            for finding in findings:
                if finding.id not in grouped:
                    grouped[finding.id] = finding
                    continue
                current = grouped[finding.id]
                current.count += finding.count
                current.evidence.extend(finding.evidence)
                current.evidence = current.evidence[:3]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings = sorted(
            grouped.values(),
            key=lambda finding: (order[finding.severity.value], -finding.count),
        )
        return AnalysisReport(
            source=context.source,
            findings=findings,
            generated_at=datetime.now(UTC),
        )
