from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from ecomops.logs.parsers import parse_lines, parse_lines_with_stats
from ecomops.logs.readers import read_local_file


def test_local_reader_preserves_line_numbers(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    path.write_text("first\nsecond\n", encoding="utf-8")

    entries = list(read_local_file(path))

    assert [entry.line_number for entry in entries] == [1, 2]
    assert entries[1].raw == "second"


def test_parser_extracts_timestamp_and_message() -> None:
    entries = parse_lines(
        ["[2026-09-02 10:15:00] ERROR: database unavailable"],
        source="app.log",
    )

    assert entries[0].timestamp is not None
    assert entries[0].level == "ERROR"
    assert entries[0].message == "database unavailable"


def test_parser_with_stats_counts_parsed_unparsed_and_normalized_levels() -> None:
    result = parse_lines_with_stats(
        [
            "[2026-09-02 10:15:00] ERROR: database unavailable\n",
            "[2026-09-02 10:16:00] main.CRITICAL: payment failed\n",
            "[2026-09-02 10:17:00] warning: slow query\n",
            "[2026-09-02 10:18:00] no level here\n",
            "stack trace continuation\n",
        ],
        source="app.log",
    )

    assert len(result.entries) == 5
    assert result.stats.total_lines == 5
    assert result.stats.parsed_lines == 4
    assert result.stats.unparsed_lines == 1
    assert result.stats.level_counts == {"ERROR": 1, "CRITICAL": 1, "WARNING": 1}
    assert result.stats.filtered_out_lines == 0
    assert result.entries[1].level == "main.CRITICAL"


def test_parser_with_stats_returns_same_entries_as_parse_lines() -> None:
    lines = ["[2026-09-02 10:15:00] ERROR: boom\n", "plain\n"]

    assert parse_lines_with_stats(lines, source="app.log").entries == parse_lines(
        lines, source="app.log"
    )


FIXTURE = Path(__file__).parents[1] / "fixtures/logs/nginx_access_transfer.log"


def access_lines() -> list[str]:
    return FIXTURE.read_text(encoding="utf-8").splitlines(keepends=True)


def test_nginx_access_lines_are_recognized_with_structured_fields() -> None:
    result = parse_lines_with_stats(access_lines(), source="transfer.log")

    first = result.entries[0]
    assert first.timestamp == datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
    assert first.access is not None
    assert first.access.socket_ip == "203.0.113.10"
    assert first.access.client_ip == "203.0.113.10"
    assert first.access.forwarded_for == ["198.51.100.7", "203.0.113.10"]
    assert first.access.method == "GET"
    assert first.access.path == "/checkout/cart/"
    assert first.access.protocol == "HTTP/1.1"
    assert first.access.status == 200
    assert first.access.bytes_sent == 5120
    assert first.access.referer == "https://shop.example.test/"
    assert first.access.user_agent == "Mozilla/5.0 (X11; Linux x86_64)"
    assert first.message == first.raw


def test_nginx_access_optional_fields_and_offsets() -> None:
    entries = parse_lines_with_stats(access_lines(), source="transfer.log").entries

    scanner = entries[2].access
    assert scanner is not None
    assert scanner.forwarded_for == []
    assert scanner.referer is None
    assert scanner.status == 404

    throttled = entries[3]
    assert throttled.access is not None
    assert throttled.access.bytes_sent is None
    assert throttled.access.forwarded_for == []
    assert throttled.access.status == 429
    assert throttled.timestamp == datetime(
        2026, 9, 3, 12, 1, 10, tzinfo=timezone(timedelta(hours=2))
    )


def test_nginx_access_stats_count_formats_and_unsupported_lines() -> None:
    result = parse_lines_with_stats(access_lines(), source="transfer.log")

    assert result.stats.total_lines == 5
    assert result.stats.parsed_lines == 4
    assert result.stats.unparsed_lines == 1
    assert result.stats.format_counts == {"nginx_access": 4}
    assert result.stats.level_counts == {}
    assert result.entries[4].access is None
    assert result.entries[4].timestamp is None


def test_forwarded_for_policy_uses_the_first_valid_forwarded_ip() -> None:
    entries = parse_lines_with_stats(
        access_lines(), source="transfer.log", client_ip_source="x_forwarded_for"
    ).entries

    assert [entry.access.client_ip for entry in entries[:4] if entry.access] == [
        "198.51.100.7",
        "198.51.100.8",
        "192.0.2.44",
        "192.0.2.45",
    ]


def test_forwarded_for_policy_skips_invalid_forwarded_values() -> None:
    line = (
        '203.0.113.10 - - [03/Sep/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1 '
        '"-" "agent" "unknown, not-an-ip, 2001:db8::1"\n'
    )

    entry = parse_lines_with_stats(
        [line], source="transfer.log", client_ip_source="x_forwarded_for"
    ).entries[0]

    assert entry.access is not None
    assert entry.access.forwarded_for == ["2001:db8::1"]
    assert entry.access.client_ip == "2001:db8::1"


def test_bracketed_lines_still_win_and_are_counted_separately() -> None:
    result = parse_lines_with_stats(
        ["[2026-09-02 10:15:00] ERROR: boom\n", access_lines()[0]],
        source="mixed.log",
    )

    assert result.entries[0].level == "ERROR"
    assert result.entries[0].access is None
    assert result.stats.format_counts == {"bracketed": 1, "nginx_access": 1}


def test_malformed_access_timestamp_is_unrecognized() -> None:
    line = (
        '203.0.113.10 - - [31/Foo/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1 '
        '"-" "agent"\n'
    )

    result = parse_lines_with_stats([line], source="transfer.log")

    assert result.stats.unparsed_lines == 1
    assert result.entries[0].access is None


def test_nginx_error_lines_are_recognized_with_level_and_time() -> None:
    line = (
        "2026/09/03 12:00:00 [error] 1234#1234: *5 upstream timed out "
        "(110: Connection timed out) while reading response header, "
        "client: 203.0.113.10, server: shop.example.test\n"
    )

    result = parse_lines_with_stats([line, "not a log line\n"], source="error.log")

    entry = result.entries[0]
    assert entry.timestamp == datetime(2026, 9, 3, 12, 0)
    assert entry.level == "error"
    assert entry.message.startswith("*5 upstream timed out")
    assert result.stats.format_counts == {"nginx_error": 1}
    assert result.stats.level_counts == {"ERROR": 1}
    assert result.stats.unparsed_lines == 1


def test_nginx_error_line_with_an_invalid_date_is_unrecognized() -> None:
    result = parse_lines_with_stats(
        ["2026/13/45 12:00:00 [error] 1#1: boom\n"], source="error.log"
    )

    assert result.stats.unparsed_lines == 1
