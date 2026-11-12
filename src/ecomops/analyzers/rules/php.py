import re
from collections.abc import Sequence

from ecomops.core.models import AnalysisContext, Evidence, Finding, LogEntry, Severity


class PhpAnalyzer:
    """Detect high-signal PHP runtime failures."""

    id = "php"

    def analyze(
        self, entries: Sequence[LogEntry], context: AnalysisContext
    ) -> list[Finding]:
        indexes = {
            index
            for index, entry in enumerate(entries)
            if re.search(r"allowed memory size.*exhausted", entry.message, re.I)
        }
        memory_entries = [
            entry for index, entry in enumerate(entries) if index in indexes
        ]
        if not memory_entries:
            return []
        first = memory_entries[0]
        evidence = [
            Evidence(
                message=entry.message,
                source=entry.source,
                sample=entry.raw,
                line_number=entry.line_number,
            )
            for entry in memory_entries[:3]
        ]
        return [
            Finding(
                id="php.memory_exhausted",
                title="PHP memory exhausted",
                severity=Severity.high,
                category="php",
                root_cause_guess="A PHP process exceeded its configured memory limit.",
                evidence=evidence,
                count=len(memory_entries),
                matched_entry_indexes=indexes,
                first_seen=first.timestamp,
                last_seen=memory_entries[-1].timestamp,
                recommended_steps=[
                    (
                        "Inspect the request, import, or cron job at the reported "
                        "file and line."
                    ),
                    (
                        "Check whether the PHP memory limit is appropriate for that "
                        "workload."
                    ),
                ],
            )
        ]
