from datetime import UTC, datetime
from pathlib import Path

import pytest

from ecomops.config.schema import LogAliasConfig
from ecomops.logs.sources import LocalLogSource, ReadLimits
from ecomops.logs.time_ranges import TimeRange

NOW = datetime(2026, 9, 3, 12, 30, tzinfo=UTC)


def alias(path: Path) -> LogAliasConfig:
    return LogAliasConfig(path=str(path), type="php")


def limits(max_lines: int = 100, max_bytes: int = 1_000) -> ReadLimits:
    return ReadLimits(max_lines=max_lines, max_bytes=max_bytes, timeout_seconds=5)


@pytest.mark.parametrize(
    ("field", "value"),
    [("max_lines", 0), ("max_bytes", -1), ("timeout_seconds", 0)],
)
def test_read_limits_reject_non_positive_values(field: str, value: int) -> None:
    values = {"max_lines": 10, "max_bytes": 100, "timeout_seconds": 5}
    values[field] = value

    with pytest.raises(ValueError, match=field):
        ReadLimits(**values)


def test_local_source_stops_at_the_line_limit(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    path.write_text("one\ntwo\nthree\n", encoding="utf-8")

    result = LocalLogSource().read(
        alias(path), limits(max_lines=2), TimeRange.parse("all", NOW)
    )

    assert [entry.message for entry in result.entries] == ["one", "two"]
    assert result.line_count == 2
    assert result.truncated is True


def test_local_source_stops_at_the_byte_limit_without_partial_lines(
    tmp_path: Path,
) -> None:
    path = tmp_path / "app.log"
    path.write_bytes(b"one\ntwo\nthree\n")

    result = LocalLogSource().read(
        alias(path), limits(max_bytes=8), TimeRange.parse("all", NOW)
    )

    assert [entry.message for entry in result.entries] == ["one", "two"]
    assert result.byte_count == 8
    assert result.truncated is True


def test_local_source_replaces_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    path.write_bytes(b"good\nbad\xff\n")

    result = LocalLogSource().read(alias(path), limits(), TimeRange.parse("all", NOW))

    assert [entry.message for entry in result.entries] == ["good", "bad\ufffd"]
    assert result.truncated is False


def test_recent_range_reads_the_tail_and_reports_actual_range(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    path.write_text(
        "[2026-09-03 09:00:00] ERROR: old\n[2026-09-03 12:00:00] ERROR: recent\n",
        encoding="utf-8",
    )

    result = LocalLogSource().read(
        alias(path), limits(max_bytes=50), TimeRange.parse("1h", NOW)
    )

    assert [entry.message for entry in result.entries] == ["recent"]
    assert result.truncated is True
    assert result.actual_range == TimeRange(
        start=datetime(2026, 9, 3, 12, 0, tzinfo=UTC),
        end=datetime(2026, 9, 3, 12, 0, tzinfo=UTC),
    )


def test_tail_at_a_line_boundary_keeps_its_first_complete_line(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    older_line = "[2026-09-03 09:00:00] ERROR: older\n"
    tail_lines = (
        "[2026-09-03 12:00:00] ERROR: first recent\n"
        "[2026-09-03 12:15:00] ERROR: second recent\n"
    )
    path.write_text(older_line + tail_lines, encoding="utf-8")

    result = LocalLogSource().read(
        alias(path), limits(max_bytes=len(tail_lines)), TimeRange.parse("1h", NOW)
    )

    assert [entry.message for entry in result.entries] == [
        "first recent",
        "second recent",
    ]


def test_bounded_tail_entries_have_unknown_source_line_numbers(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    older_line = "[2026-09-03 09:00:00] ERROR: older\n"
    tail_lines = (
        "[2026-09-03 12:00:00] ERROR: first recent\n"
        "[2026-09-03 12:15:00] ERROR: second recent\n"
    )
    path.write_text(older_line + tail_lines, encoding="utf-8")

    result = LocalLogSource().read(
        alias(path), limits(max_bytes=len(tail_lines)), TimeRange.parse("1h", NOW)
    )

    assert [entry.line_number for entry in result.entries] == [None, None]


def test_iso_range_is_explicitly_marked_incomplete(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    path.write_text("[2026-09-03 10:15:00] ERROR: matching\n", encoding="utf-8")

    result = LocalLogSource().read(
        alias(path), limits(), TimeRange.parse("2026-09-03T10:00:00Z", NOW)
    )

    assert [entry.message for entry in result.entries] == ["matching"]
    assert result.truncated is True
