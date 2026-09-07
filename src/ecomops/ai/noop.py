from ecomops.core.models import AnalysisContext, Finding


class NoopProvider:
    """Default provider that leaves deterministic findings unchanged."""

    id = "noop"

    def is_available(self) -> bool:
        return True

    def enrich_findings(
        self, findings: list[Finding], context: AnalysisContext
    ) -> list[Finding]:
        del context
        return list(findings)
