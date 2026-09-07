from ecomops.core.models import AnalysisReport


def render_terminal(report: AnalysisReport) -> str:
    lines = [
        f"Connection: {report.connection_type.upper()}",
        f"Remote access: {'yes' if report.remote_access else 'no'}",
        f"Read: {report.line_count} lines, {report.byte_count} bytes",
        f"Sampling: {'bounded' if report.truncated else 'complete'}",
    ]
    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines)
    lines.append(f"Findings: {len(report.findings)}")
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
