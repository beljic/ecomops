from ecomops.logs.inspection import LogInspection, ProjectCheck

from .read_summary import (
    describe_levels,
    describe_parse,
    describe_sample,
    describe_source,
)

MAX_RENDERED_CANDIDATES = 5


def check_lines(check: ProjectCheck) -> list[str]:
    """Describe per-alias file health for a project check; no findings."""
    lines = [f"Project: {check.project} ({check.connection_type.upper()})"]
    if not check.aliases:
        lines.append("No log aliases configured.")
    for inspection in check.aliases:
        lines.extend(_alias_lines(inspection))
    return lines


def render_check_terminal(check: ProjectCheck) -> str:
    return "\n".join(check_lines(check))


def render_check_markdown(check: ProjectCheck) -> str:
    lines = check_lines(check)
    return "\n".join(
        ["# EcomOps Project Check", ""]
        + [line if line.startswith("[") else f"- {line.strip()}" for line in lines]
    )


def render_check_json(check: ProjectCheck) -> str:
    return check.model_dump_json(indent=2)


def _alias_lines(inspection: LogInspection) -> list[str]:
    lines = [
        f"[{inspection.alias}] {inspection.log_type}: {inspection.configured_path}"
    ]
    listing = inspection.listing
    if listing is not None:
        suffix = ", truncated" if listing.truncated else ""
        lines.append(f"  Candidates: {len(listing.files)} (newest first{suffix})")
        lines.extend(
            f"    {candidate.path}"
            for candidate in listing.files[:MAX_RENDERED_CANDIDATES]
        )
        if inspection.selected_path is not None:
            lines.append(f"  Selected: {inspection.selected_path}")
    lines.append(f"  {describe_source(inspection.source_metadata)}")
    if inspection.sampling is not None:
        lines.append(f"  {describe_sample(inspection.sampling)}")
    if inspection.parse_stats is not None:
        lines.append(f"  {describe_parse(inspection.parse_stats)}")
        levels = describe_levels(inspection.parse_stats)
        if levels is not None:
            lines.append(f"  {levels}")
    lines.extend(f"  Warning: {warning}" for warning in inspection.warnings)
    return lines
