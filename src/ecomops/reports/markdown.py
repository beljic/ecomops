from ecomops.ai.redaction import redact_report
from ecomops.core.models import AnalysisReport

from .read_summary import read_summary_lines


def render_markdown(report: AnalysisReport) -> str:
    """Render a report as a compact Markdown document."""
    report = redact_report(report)
    lines = ["# EcomOps Analysis", ""]
    if report.source.project is not None:
        lines.extend(
            [
                f"- Connection: `{report.connection_type}`",
                f"- Remote access: `{'yes' if report.remote_access else 'no'}`",
                f"- Read: `{report.line_count}` lines, `{report.byte_count}` bytes",
                f"- Sampling: `{'bounded' if report.truncated else 'complete'}`",
                "",
            ]
        )
    summary = read_summary_lines(report)
    if summary:
        lines.extend([*(f"- {line}" for line in summary), ""])
    if report.ai_enriched:
        lines.extend([f"- AI enrichment: `{report.ai_provider}`", ""])
    if not report.findings:
        if not report.warnings:
            lines.append("No findings.")
        return "\n".join(lines).rstrip()

    lines.append("## Findings")
    lines.append("")
    for finding in report.findings:
        lines.append(f"### [{finding.severity.value}] {finding.title}")
        lines.append("")
        lines.append(f"- Category: `{finding.category}`")
        lines.append(f"- Count: `{finding.count}`")
        if finding.root_cause_guess:
            lines.append(f"- Root cause: {finding.root_cause_guess}")
        for evidence in finding.evidence:
            location = (
                f"line {evidence.line_number}"
                if evidence.line_number
                else "unknown line"
            )
            lines.append(f"- Evidence ({location}): `{evidence.sample}`")
        if finding.recommended_steps:
            lines.append("- Recommended steps:")
            lines.extend(f"  - {step}" for step in finding.recommended_steps)
        lines.append("")
    return "\n".join(lines).rstrip()
