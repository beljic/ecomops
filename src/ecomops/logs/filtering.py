"""Time filtering shared by the local and SSH sources."""

from ecomops.core.models import LogEntry

from .time_ranges import TimeRange, as_utc


def filter_by_time(entries: list[LogEntry], time_range: TimeRange) -> list[LogEntry]:
    """Keep entries inside ``time_range``, with their continuation lines.

    A line without a timestamp (a stack-trace frame, a wrapped message)
    belongs to the nearest timestamped line above it and is kept or dropped
    with it. Lines before the first timestamp in the sample have no known
    time and are dropped. Kept timestamps are normalized to UTC.
    """
    if time_range.start is None:
        return entries
    assert time_range.end is not None

    kept: list[LogEntry] = []
    keep_continuation = False
    for entry in entries:
        if entry.timestamp is None:
            if keep_continuation:
                kept.append(entry)
            continue
        timestamp = as_utc(entry.timestamp)
        keep_continuation = time_range.start <= timestamp <= time_range.end
        if keep_continuation:
            kept.append(entry.model_copy(update={"timestamp": timestamp}))
    return kept


def time_range_of(entries: list[LogEntry]) -> TimeRange | None:
    """UTC range covered by the timestamped entries, or ``None``."""
    timestamps = [
        as_utc(entry.timestamp) for entry in entries if entry.timestamp is not None
    ]
    if not timestamps:
        return None
    return TimeRange(start=min(timestamps), end=max(timestamps))
