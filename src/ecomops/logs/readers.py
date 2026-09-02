from collections.abc import Iterator
from pathlib import Path

from ecomops.core.models import LogEntry

from .parsers import parse_lines


def read_local_file(path: Path) -> Iterator[LogEntry]:
    """Read a UTF-8 local log while preserving its line numbers."""
    with path.open(encoding="utf-8", errors="replace") as log_file:
        yield from parse_lines(log_file, source=str(path))
