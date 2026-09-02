import re
from collections.abc import Iterable
from datetime import datetime

from ecomops.core.models import LogEntry

_PREFIX = re.compile(
    r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*"
    r"(?:(?P<level>[A-Za-z]+):\s*)?(?P<message>.*)$"
)


def parse_lines(lines: Iterable[str], source: str) -> list[LogEntry]:
    entries: list[LogEntry] = []
    for line_number, line in enumerate(lines, start=1):
        raw = line.rstrip("\r\n")
        match = _PREFIX.match(raw)
        if match:
            timestamp = datetime.fromisoformat(match["timestamp"])
            level = match["level"]
            message = match["message"]
        else:
            timestamp = None
            level = None
            message = raw
        entries.append(
            LogEntry(
                timestamp=timestamp,
                level=level,
                source=source,
                message=message,
                raw=raw,
                line_number=line_number,
            )
        )
    return entries
