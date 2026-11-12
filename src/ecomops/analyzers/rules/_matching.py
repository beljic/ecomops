import re
from collections.abc import Sequence

from ecomops.core.models import Evidence, Finding, LogEntry, Severity


def finding_for_matches(
    entries: Sequence[LogEntry],
    pattern: str,
    finding_id: str,
    title: str,
    severity: Severity,
    category: str,
) -> Finding | None:
    indexes = {
        index
        for index, entry in enumerate(entries)
        if re.search(pattern, entry.message, re.I)
    }
    matches = [entry for index, entry in enumerate(entries) if index in indexes]
    if not matches:
        return None
    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        category=category,
        evidence=[
            Evidence(
                message=entry.message,
                source=entry.source,
                sample=entry.raw,
                line_number=entry.line_number,
            )
            for entry in matches[:3]
        ],
        count=len(matches),
        matched_entry_indexes=indexes,
    )
