from typing import Literal

from ecomops.core.models import AnalysisReport

from .json import render_json
from .markdown import render_markdown
from .terminal import render_terminal

ReportFormat = Literal["terminal", "json", "markdown"]


def render_report(report: AnalysisReport, output_format: ReportFormat) -> str:
    """Render a report without writing files or changing the source system."""
    if output_format == "json":
        return render_json(report)
    if output_format == "markdown":
        return render_markdown(report)
    return render_terminal(report)
