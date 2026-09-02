from ecomops.core.models import AnalysisReport


def render_terminal(report: AnalysisReport) -> str:
    if not report.findings:
        return "No findings."
    lines = [f"Findings: {len(report.findings)}"]
    for finding in report.findings:
        lines.append(
            f"[{finding.severity.value}] {finding.title} (count: {finding.count})"
        )
        for evidence in finding.evidence:
            location = (
                f"line {evidence.line_number}"
                if evidence.line_number
                else "unknown line"
            )
            lines.append(f"  Evidence ({location}): {evidence.sample}")
    return "\n".join(lines)
