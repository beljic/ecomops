from typing import Any

from ecomops.ai.redaction import redact_report
from ecomops.core.models import AnalysisReport
from ecomops.logs.inspection import LogFileListing, ProjectCheck

MCP_MAX_LISTED_FILES = 50


def structured_report(report: AnalysisReport) -> dict[str, Any]:
    """Convert an analysis report to the stable MCP response shape."""
    report = redact_report(report)
    metadata: dict[str, Any] = {
        "connection_type": report.connection_type,
        "remote_access": report.remote_access,
        "line_count": report.line_count,
        "byte_count": report.byte_count,
        "truncated": report.truncated,
    }
    if report.source_metadata is not None:
        # Reports built without a source read keep the original response shape.
        dumped = report.model_dump(
            mode="json",
            include={"actual_range", "parse_stats", "sampling", "warnings"},
        )
        metadata["source"] = report.source_metadata.model_dump(mode="json")
        metadata.update(dumped)
    return {
        "metadata": metadata,
        "findings": [finding.model_dump(mode="json") for finding in report.findings],
    }


def structured_listing(listing: LogFileListing) -> dict[str, Any]:
    """Bounded, newest-first file listing for one configured glob alias."""
    files = listing.files[:MCP_MAX_LISTED_FILES]
    return {
        "directory": listing.directory,
        "pattern": listing.pattern,
        "files": [candidate.model_dump(mode="json") for candidate in files],
        "total_matches": len(listing.files),
        "truncated": listing.truncated or len(listing.files) > len(files),
    }


def structured_check(check: ProjectCheck) -> dict[str, Any]:
    """Per-alias source health; glob listings are bounded like ``list_log_files``."""
    aliases: list[dict[str, Any]] = []
    for inspection in check.aliases:
        item = inspection.model_dump(mode="json", exclude={"listing"})
        item["listing"] = (
            None
            if inspection.listing is None
            else structured_listing(inspection.listing)
        )
        aliases.append(item)
    return {
        "project": check.project,
        "connection_type": check.connection_type,
        "aliases": aliases,
    }
