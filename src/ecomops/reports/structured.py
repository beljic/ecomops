"""Text rendering for the traffic and security reports."""

from collections.abc import Iterable

from ecomops.core.models import CountItem, SecurityReport, TrafficReport

from .read_summary import describe_parse, describe_sample, describe_source


def traffic_lines(report: TrafficReport) -> list[str]:
    summary = report.summary
    lines = _read_lines(report.read.path, report)
    lines.append(
        f"Requests: {summary.total_requests} from "
        f"{summary.unique_client_ips} client IPs"
    )
    lines.append(f"Status counts: {_pairs(summary.status_counts.items())}")
    lines.append(f"Top client IPs: {_items(summary.top_client_ips)}")
    lines.append(f"Top paths: {_items(summary.top_paths)}")
    lines.append(f"Top user agents: {_items(summary.top_user_agents)}")
    lines.append(
        f"Peak requests per minute: {summary.peak_requests_per_minute} "
        f"(busiest: {_items(summary.busiest_minutes)})"
    )
    if summary.status_by_ip:
        lines.append("Errors by client IP:")
        lines.extend(
            f"  {row.client_ip}: {_pairs(row.status_counts.items())}"
            for row in summary.status_by_ip
        )
    lines.extend(f"Warning: {warning}" for warning in report.warnings)
    return lines


def security_lines(report: SecurityReport) -> list[str]:
    scan = report.scan
    lines = _read_lines(report.read.path, report)
    lines.append(f"Requests scanned: {scan.requests_scanned}")
    if not scan.indicators and not report.warnings:
        lines.append("No security indicators.")
    for indicator in scan.indicators:
        lines.append(
            f"[{indicator.id}] {indicator.title} (count: {indicator.count}; "
            f"client IPs: {_items(indicator.top_client_ips)})"
        )
        lines.extend(f"  Sample: {sample}" for sample in indicator.samples)
    tor = scan.tor
    tor_detail = (
        f", {tor.matched_requests} matching requests" if tor.status == "checked" else ""
    )
    lines.append(f"Tor classification: {tor.status}{tor_detail}")
    lines.extend(f"Warning: {warning}" for warning in report.warnings)
    return lines


def render_text(lines: list[str], output_format: str) -> str:
    if output_format == "markdown":
        return "\n".join(
            f"- {line.strip()}" if not line.startswith("  ") else f"  - {line.strip()}"
            for line in lines
        )
    return "\n".join(lines)


def _read_lines(path: str, report: TrafficReport | SecurityReport) -> list[str]:
    read = report.read
    lines = [f"Log: {path}"]
    if read.source_metadata is not None:
        lines.append(describe_source(read.source_metadata))
    if read.sampling is not None:
        lines.append(describe_sample(read.sampling))
    if read.parse_stats is not None:
        lines.append(describe_parse(read.parse_stats))
    return lines


def _items(items: list[CountItem]) -> str:
    return ", ".join(f"{item.value}={item.count}" for item in items) or "-"


def _pairs(pairs: Iterable[tuple[str, int]]) -> str:
    return ", ".join(f"{key}={value}" for key, value in pairs) or "-"
