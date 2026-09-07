from typing import Any

from ecomops.core.models import AnalysisReport


def structured_report(report: AnalysisReport) -> dict[str, Any]:
    """Convert an analysis report to the stable MCP response shape."""
    return {
        "metadata": {
            "connection_type": report.connection_type,
            "remote_access": report.remote_access,
            "line_count": report.line_count,
            "byte_count": report.byte_count,
            "truncated": report.truncated,
        },
        "findings": [finding.model_dump(mode="json") for finding in report.findings],
    }
