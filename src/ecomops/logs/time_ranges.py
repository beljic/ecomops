from __future__ import annotations

from calendar import monthrange
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True)
class TimeRange:
    start: datetime | None
    end: datetime | None
    exact_selection: bool = field(default=False, compare=False)

    @classmethod
    def parse(cls, value: str, now: datetime) -> TimeRange:
        normalized_now = _as_utc(now)
        normalized_value = value.strip().lower()

        if normalized_value == "all":
            return cls(start=None, end=None)

        relative_ranges = {"1h": timedelta(hours=1), "1d": timedelta(days=1)}
        if normalized_value == "7d":
            return cls(start=normalized_now - timedelta(days=7), end=normalized_now)
        if normalized_value == "1mo":
            return cls(start=_one_month_before(normalized_now), end=normalized_now)
        if normalized_value in relative_ranges:
            return cls(
                start=normalized_now - relative_ranges[normalized_value],
                end=normalized_now,
            )

        try:
            start = _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError as error:
            raise ValueError(f"Invalid time range: {value}") from error

        return cls(start=start, end=normalized_now, exact_selection=True)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _one_month_before(value: datetime) -> datetime:
    month = value.month - 1 or 12
    year = value.year - 1 if value.month == 1 else value.year
    day = min(value.day, monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)
