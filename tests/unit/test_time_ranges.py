from datetime import UTC, datetime

import pytest

from ecomops.logs.time_ranges import TimeRange

NOW = datetime(2026, 9, 3, 12, 30, tzinfo=UTC)


def test_all_range_has_no_boundaries() -> None:
    result = TimeRange.parse("all", now=NOW)

    assert result.start is None
    assert result.end is None


@pytest.mark.parametrize(
    ("value", "expected_start"),
    [
        ("1h", datetime(2026, 9, 3, 11, 30, tzinfo=UTC)),
        ("1d", datetime(2026, 9, 2, 12, 30, tzinfo=UTC)),
        ("7d", datetime(2026, 8, 27, 12, 30, tzinfo=UTC)),
        ("1mo", datetime(2026, 8, 3, 12, 30, tzinfo=UTC)),
    ],
)
def test_relative_ranges_are_utc_aware(value: str, expected_start: datetime) -> None:
    result = TimeRange.parse(value, now=NOW)

    assert result.start == expected_start
    assert result.end == NOW


def test_iso_timestamp_is_a_utc_since_range() -> None:
    result = TimeRange.parse("2026-09-03T10:15:00+02:00", now=NOW)

    assert result.start == datetime(2026, 9, 3, 8, 15, tzinfo=UTC)
    assert result.end == NOW


def test_hour_range_crosses_midnight() -> None:
    result = TimeRange.parse("1h", now=datetime(2026, 9, 3, 0, 15, tzinfo=UTC))

    assert result.start == datetime(2026, 9, 2, 23, 15, tzinfo=UTC)


@pytest.mark.parametrize("value", ["", "0h", "-1h", "2h", "tomorrow"])
def test_invalid_ranges_are_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="time range"):
        TimeRange.parse(value, now=NOW)
