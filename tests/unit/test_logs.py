from pathlib import Path

from ecomops.logs.parsers import parse_lines
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
