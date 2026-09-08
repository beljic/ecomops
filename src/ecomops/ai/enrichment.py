from ecomops.core.models import AnalysisContext, AnalysisReport

from .providers import get_provider
from .redaction import redact_report


def enrich_report(
    report: AnalysisReport,
    context: AnalysisContext,
    provider_name: str,
) -> AnalysisReport:
    """Enrich only redacted structured findings with an optional provider."""
    safe_report = redact_report(report)
    provider = get_provider(provider_name)
    if not provider.is_available():
        raise ValueError(f"AI provider '{provider_name}' is not available.")
    findings = provider.enrich_findings(safe_report.findings, context)
    return safe_report.model_copy(
        update={
            "findings": findings,
            "ai_enriched": True,
            "ai_provider": provider.id,
        }
    )
