from __future__ import annotations

import re
from calendar import monthrange
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

_RELATIVE = re.compile(r"^(?P<amount>\d+)(?P<unit>mo|m|h|d|w)$")
_UNIT_DELTAS = {
    "m": timedelta(minutes=1),
    "h": timedelta(hours=1),
    "d": timedelta(days=1),
    "w": timedelta(weeks=1),
}


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

        relative = _RELATIVE.fullmatch(normalized_value)
        if relative is not None:
            amount = int(relative["amount"])
            if amount <= 0:
                raise ValueError(
                    f"Invalid time range: {value} (value must be positive)"
                )
            try:
                if relative["unit"] == "mo":
                    start = _months_before(normalized_now, amount)
                else:
                    start = normalized_now - amount * _UNIT_DELTAS[relative["unit"]]
            except (OverflowError, ValueError) as error:
                raise ValueError(
                    f"Invalid time range: {value} (too far in the past)"
                ) from error
            return cls(start=start, end=normalized_now)

        try:
            start = _as_utc(
                datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            )
        except ValueError as error:
            raise ValueError(f"Invalid time range: {value}") from error

        return cls(start=start, end=normalized_now, exact_selection=True)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _months_before(value: datetime, months: int) -> datetime:
    """Step back whole calendar months, clamping to the target month's last day."""
    month_index = value.year * 12 + (value.month - 1) - months
    year, month = divmod(month_index, 12)
    month += 1
    day = min(value.day, monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)
