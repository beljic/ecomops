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


@pytest.mark.parametrize(
    "value",
    ["", "0h", "-1h", "tomorrow", "1.5h", "h", "10x", "1 h", "01mo0", "2026-13-01"],
)
def test_invalid_ranges_are_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="time range"):
        TimeRange.parse(value, now=NOW)


@pytest.mark.parametrize(
    ("value", "expected_start"),
    [
        ("30m", datetime(2026, 9, 3, 12, 0, tzinfo=UTC)),
        ("90m", datetime(2026, 9, 3, 11, 0, tzinfo=UTC)),
        ("2h", datetime(2026, 9, 3, 10, 30, tzinfo=UTC)),
        ("24h", datetime(2026, 9, 2, 12, 30, tzinfo=UTC)),
        ("30d", datetime(2026, 8, 4, 12, 30, tzinfo=UTC)),
        ("2w", datetime(2026, 8, 20, 12, 30, tzinfo=UTC)),
        ("3mo", datetime(2026, 6, 3, 12, 30, tzinfo=UTC)),
        ("12mo", datetime(2025, 9, 3, 12, 30, tzinfo=UTC)),
        ("14mo", datetime(2025, 7, 3, 12, 30, tzinfo=UTC)),
        ("2H", datetime(2026, 9, 3, 10, 30, tzinfo=UTC)),
    ],
)
def test_arbitrary_positive_relative_ranges(
    value: str, expected_start: datetime
) -> None:
    result = TimeRange.parse(value, now=NOW)

    assert result.start == expected_start
    assert result.end == NOW
    assert result.exact_selection is False


def test_month_range_clamps_to_the_last_day_of_a_shorter_month() -> None:
    result = TimeRange.parse("1mo", now=datetime(2026, 3, 31, 8, 0, tzinfo=UTC))

    assert result.start == datetime(2026, 2, 28, 8, 0, tzinfo=UTC)


def test_iso_date_is_midnight_utc() -> None:
    result = TimeRange.parse("2026-09-01", now=NOW)

    assert result.start == datetime(2026, 9, 1, 0, 0, tzinfo=UTC)
    assert result.exact_selection is True


def test_iso_timestamp_with_z_suffix() -> None:
    result = TimeRange.parse("2026-09-01T00:00:00Z", now=NOW)

    assert result.start == datetime(2026, 9, 1, 0, 0, tzinfo=UTC)


@pytest.mark.parametrize("value", ["0m", "0mo"])
def test_zero_relative_ranges_say_the_value_must_be_positive(value: str) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        TimeRange.parse(value, now=NOW)


@pytest.mark.parametrize("value", ["99999999999d", "999999999mo"])
def test_relative_ranges_beyond_the_calendar_are_rejected_cleanly(value: str) -> None:
    with pytest.raises(ValueError, match="time range"):
        TimeRange.parse(value, now=NOW)
