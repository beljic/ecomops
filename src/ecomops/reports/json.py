import json

from ecomops.core.models import AnalysisReport


def render_json(report: AnalysisReport) -> str:
    """Render a report as stable, JSON-serializable output."""
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True)
