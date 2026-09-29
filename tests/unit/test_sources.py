import os
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


def test_recent_range_matches_magento_style_timestamps(tmp_path: Path) -> None:
    path = tmp_path / "exception.log"
    path.write_text(
        "[2026-09-03T09:00:00.000000+00:00] main.CRITICAL: old\n"
        "[2026-09-03T12:00:00.000000+00:00] main.CRITICAL: recent\n",
        encoding="utf-8",
    )

    result = LocalLogSource().read(
        alias(path), limits(max_bytes=200), TimeRange.parse("1h", NOW)
    )

    assert [entry.message for entry in result.entries] == ["recent"]


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


def test_local_source_reports_file_metadata_and_head_sampling(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    path.write_text(
        "[2026-09-03 09:00:00] ERROR: first\nnot a structured line\n",
        encoding="utf-8",
    )

    result = LocalLogSource().read(alias(path), limits(), TimeRange.parse("all", NOW))

    assert result.source_metadata is not None
    assert result.source_metadata.exists is True
    assert result.source_metadata.readable is True
    assert result.source_metadata.size_bytes == path.stat().st_size
    assert result.source_metadata.modified_at is not None
    assert result.source_metadata.error is None
    assert result.sampling is not None
    assert result.sampling.direction == "head"
    assert result.sampling.max_bytes == 1_000
    assert result.sampling.max_lines == 100
    assert result.sampling.sampled_bytes == path.stat().st_size
    assert result.sampling.complete_lines == 2
    assert result.parse_stats is not None
    assert result.parse_stats.parsed_lines == 1
    assert result.parse_stats.unparsed_lines == 1
    assert result.parse_stats.level_counts == {"ERROR": 1}
    assert result.line_count == 2


def test_local_source_counts_entries_removed_by_the_time_filter(
    tmp_path: Path,
) -> None:
    path = tmp_path / "app.log"
    path.write_text(
        "[2026-09-03 09:00:00] ERROR: old\n"
        "[2026-09-03 10:00:00] ERROR: also old\n"
        "[2026-09-03 12:00:00] ERROR: recent\n",
        encoding="utf-8",
    )

    result = LocalLogSource().read(alias(path), limits(), TimeRange.parse("1h", NOW))

    assert result.line_count == 1
    assert result.parse_stats is not None
    assert result.parse_stats.parsed_lines == 3
    assert result.parse_stats.filtered_out_lines == 2
    assert result.sampling is not None
    assert result.sampling.direction == "tail"
    assert result.sampling.sampled_range == TimeRange(
        start=datetime(2026, 9, 3, 9, 0, tzinfo=UTC),
        end=datetime(2026, 9, 3, 12, 0, tzinfo=UTC),
    )


def test_local_source_reports_an_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.log"
    path.write_bytes(b"")

    result = LocalLogSource().read(alias(path), limits(), TimeRange.parse("all", NOW))

    assert result.entries == []
    assert result.line_count == 0
    assert result.source_metadata is not None
    assert result.source_metadata.exists is True
    assert result.source_metadata.size_bytes == 0
    assert result.parse_stats is not None
    assert result.parse_stats.total_lines == 0
    assert result.parse_stats.parsed_lines == 0
    assert result.sampling is not None
    assert result.sampling.sampled_bytes == 0


def test_local_source_reports_a_missing_file_without_raising(tmp_path: Path) -> None:
    path = tmp_path / "missing.log"

    result = LocalLogSource().read(alias(path), limits(), TimeRange.parse("all", NOW))

    assert result.entries == []
    assert result.line_count == 0
    assert result.source_metadata is not None
    assert result.source_metadata.exists is False
    assert result.source_metadata.readable is False
    assert result.source_metadata.error == "file not found"


def test_local_source_reports_an_unreadable_file_without_raising(
    tmp_path: Path,
) -> None:
    path = tmp_path / "secret.log"
    path.write_text("line\n", encoding="utf-8")
    path.chmod(0o000)
    try:
        if os.access(path, os.R_OK):
            pytest.skip("running with privileges that bypass file permissions")
        result = LocalLogSource().read(
            alias(path), limits(), TimeRange.parse("all", NOW)
        )
    finally:
        path.chmod(0o600)

    assert result.entries == []
    assert result.source_metadata is not None
    assert result.source_metadata.exists is True
    assert result.source_metadata.readable is False
    assert result.source_metadata.error == "permission denied"


def test_local_source_reports_a_directory_as_not_a_regular_file(
    tmp_path: Path,
) -> None:
    result = LocalLogSource().read(
        alias(tmp_path), limits(), TimeRange.parse("all", NOW)
    )

    assert result.entries == []
    assert result.source_metadata is not None
    assert result.source_metadata.readable is False
    assert result.source_metadata.error == "not a regular file"


def test_local_source_applies_the_alias_client_ip_policy(tmp_path: Path) -> None:
    path = tmp_path / "transfer.log"
    path.write_text(
        '203.0.113.10 - - [03/Sep/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1 '
        '"-" "agent" "198.51.100.7"\n',
        encoding="utf-8",
    )
    forwarded = LogAliasConfig(
        path=str(path), type="nginx", client_ip_source="x_forwarded_for"
    )
    socket = LogAliasConfig(path=str(path), type="nginx")

    forwarded_result = LocalLogSource().read(
        forwarded, limits(), TimeRange.parse("all", NOW)
    )
    socket_result = LocalLogSource().read(socket, limits(), TimeRange.parse("all", NOW))

    assert forwarded_result.entries[0].access is not None
    assert forwarded_result.entries[0].access.client_ip == "198.51.100.7"
    assert socket_result.entries[0].access is not None
    assert socket_result.entries[0].access.client_ip == "203.0.113.10"


def test_access_entries_are_kept_by_a_recent_time_filter(tmp_path: Path) -> None:
    path = tmp_path / "transfer.log"
    path.write_text(
        '203.0.113.10 - - [03/Sep/2026:09:00:00 +0000] "GET /old HTTP/1.1" 200 1 '
        '"-" "agent"\n'
        '203.0.113.10 - - [03/Sep/2026:12:10:00 +0000] "GET /new HTTP/1.1" 200 1 '
        '"-" "agent"\n',
        encoding="utf-8",
    )

    result = LocalLogSource().read(
        LogAliasConfig(path=str(path), type="nginx"),
        limits(),
        TimeRange.parse("1h", NOW),
    )

    assert [entry.access.path for entry in result.entries if entry.access] == ["/new"]
    assert result.parse_stats is not None
    assert result.parse_stats.filtered_out_lines == 1


def test_local_source_reports_a_file_that_disappears_during_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.logs import sources

    path = tmp_path / "app.log"
    path.write_text("line\n", encoding="utf-8")

    def vanished(*args: object, **kwargs: object) -> bytes:
        raise FileNotFoundError(str(path))

    monkeypatch.setattr(sources, "read_local_bytes", vanished)

    result = LocalLogSource().read(alias(path), limits(), TimeRange.parse("all", NOW))

    assert result.entries == []
    assert result.source_metadata is not None
    assert result.source_metadata.readable is False
    assert result.source_metadata.error == "file disappeared or became unreadable"
