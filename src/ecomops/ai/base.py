from typing import Protocol

from ecomops.core.models import AnalysisContext, Finding


class AIProvider(Protocol):
    """Contract for optional, non-authoritative finding enrichment."""

    id: str

    def is_available(self) -> bool:
        """Return whether the provider can be used in the current environment."""

    def enrich_findings(
        self, findings: list[Finding], context: AnalysisContext
    ) -> list[Finding]:
        """Return enriched findings without inventing evidence."""
