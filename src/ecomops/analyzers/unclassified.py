import hashlib
import re
from collections import Counter
from collections.abc import Sequence

from ecomops.ai.redaction import redact_sensitive_text
from ecomops.core.models import Evidence, Finding, LogEntry, Severity
from ecomops.logs.time_ranges import as_utc

DEFAULT_TOP_N = 10
MAX_TOP_N = 50
_LEVELS = {"ERROR": 0, "CRITICAL": 1, "ALERT": 2, "EMERGENCY": 3}
_ALIASES = {"CRIT": "CRITICAL", "EMERG": "EMERGENCY"}
_SOURCE = re.compile(r"\bin (/[^\s\"'{}]+?):(\d+)\b")
_FRAME_SOURCE = re.compile(r"^\s*#\d+\s+(/[^\s(]+)\((\d+)\)")
_QUOTED = re.compile(r""""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' """, re.X)
_IDENTIFIER = re.compile(
    r"\b(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|0x[0-9a-f]+|[0-9a-f]{8,}|\d+)\b",
    re.I,
)
_NAMED_ID = re.compile(r"\b((?:\w+[_-])?id)\s*([:=])\s*[^\s,;]+", re.I)


def _level(entry: LogEntry) -> str:
    level = (entry.level or "").rsplit(".", 1)[-1].upper()
    return _ALIASES.get(level, level)


def _bounded(value: str) -> str:
    return value if len(value) <= 500 else value[:497] + "..."


def _message(entry: LogEntry) -> str:
    message = re.split(r"\s+in /", entry.message, maxsplit=1)[0]
    message = re.split(r"\s+\{", message, maxsplit=1)[0]
    message = re.sub(r"\s+\[\]\s*$", "", message)
    message = _QUOTED.sub("<value>", message)
    message = _NAMED_ID.sub(r"\1\2<id>", message)
    message = _IDENTIFIER.sub("<id>", message)
    message = re.sub(r"\d+", "<id>", message)
    return " ".join(redact_sensitive_text(message).split())


def unclassified_findings(
    entries: Sequence[LogEntry], claimed: set[int], *, top_n: int = DEFAULT_TOP_N
) -> list[Finding]:
    if isinstance(top_n, bool) or not 1 <= top_n <= MAX_TOP_N:
        raise ValueError(f"top_n must be between 1 and {MAX_TOP_N}")
    claimed_records = {
        (entries[index].source, entries[index].record_id)
        for index in claimed
        if entries[index].record_id is not None
    }
    groups: dict[str, list[LogEntry]] = {}
    sources: dict[str, Counter[str]] = {}
    headers: dict[tuple[str, int], str] = {}
    for index, entry in enumerate(entries):
        record = (entry.source, entry.record_id)
        if entry.is_continuation:
            if entry.record_id is not None:
                message = headers.get((entry.source, entry.record_id))
                if message is not None and (frame := _FRAME_SOURCE.match(entry.raw)):
                    sources[message][f"{frame[1]}:{frame[2]}"] += 1
                    del headers[(entry.source, entry.record_id)]
            continue
        if (
            index in claimed
            or record in claimed_records
            or _level(entry) not in _LEVELS
        ):
            continue
        message = _message(entry)
        groups.setdefault(message, []).append(entry)
        locations = sources.setdefault(message, Counter())
        if source_match := _SOURCE.search(entry.message):
            locations[f"{source_match[1]}:{source_match[2]}"] += 1
        elif entry.record_id is not None:
            headers[(entry.source, entry.record_id)] = message

    findings: list[Finding] = []
    for message, matches in sorted(
        groups.items(), key=lambda item: (-len(item[1]), item[0])
    )[:top_n]:
        level = max((_level(entry) for entry in matches), key=_LEVELS.__getitem__)
        timestamps = [
            as_utc(entry.timestamp) for entry in matches if entry.timestamp is not None
        ]
        first = matches[0]
        sample = _bounded(redact_sensitive_text(first.raw))
        locations = sources[message]
        source = (
            min(locations, key=lambda location: (-locations[location], location))
            if locations
            else None
        )
        findings.append(
            Finding(
                id="unclassified." + hashlib.sha256(message.encode()).hexdigest()[:16],
                title="Unclassified errors",
                severity=Severity.high if level == "ERROR" else Severity.critical,
                category="unclassified",
                count=len(matches),
                first_seen=min(timestamps) if timestamps else None,
                last_seen=max(timestamps) if timestamps else None,
                message=_bounded(message),
                level=level,
                sample=sample,
                source=_bounded(redact_sensitive_text(source)) if source else None,
                evidence=[
                    Evidence(
                        message=_bounded(message),
                        source=first.source,
                        sample=sample,
                        line_number=first.line_number,
                    )
                ],
            )
        )
    return findings
