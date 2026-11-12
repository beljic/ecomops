import json
from datetime import UTC, datetime

import pytest

from ecomops.analyzers.pipeline import AnalyzerPipeline
from ecomops.analyzers.rules.magento import MagentoAnalyzer
from ecomops.analyzers.rules.mysql import MySQLAnalyzer
from ecomops.analyzers.rules.php import PhpAnalyzer
from ecomops.core.models import AnalysisContext, LogSource
from ecomops.logs.filtering import filter_by_time
from ecomops.logs.parsers import parse_lines_with_stats
from ecomops.logs.time_ranges import TimeRange
from ecomops.reports.json import render_json
from ecomops.reports.markdown import render_markdown
from ecomops.reports.terminal import render_terminal


@pytest.fixture
def monolog_lines() -> list[str]:
    messages = [
        "GraphQL\\Error\\SyntaxError: Syntax Error: Unexpected <EOF> "
        "in /var/www/html/vendor/webonyx/graphql-php/src/Language/Parser.php:454",
    ] * 3 + [
        "Magento\\Framework\\Exception\\LocalizedException: Multiple queries can't "
        "be executed. Run a single query and try again. "
        "in /var/www/html/vendor/magento/framework/DB/Adapter/Pdo/Mysql.php:699",
    ] * 6
    lines: list[str] = []
    for second, message in enumerate(messages):
        lines.append(
            f"[2026-11-06T05:19:{second:02d}.295401+00:00] "
            f"main.CRITICAL: {message} {{}} []\n"
        )
        lines.append("Stack trace:\n")
        lines.extend(
            f"#{frame} /var/www/html/app/Example.php(123): Example->run()\n"
            for frame in range(48)
        )
        lines.append('{"password":"synthetic-secret"}\n')
    return lines


def context() -> AnalysisContext:
    return AnalysisContext(
        source=LogSource(type="ssh", path="/var/www/html/var/log/exception.log")
    )


def test_monolog_errors_produce_two_groups_and_count_continuations(
    monolog_lines: list[str],
) -> None:
    parsed = parse_lines_with_stats(monolog_lines, source="exception.log")
    entries = [
        entry.model_copy(update={"line_number": None}) for entry in parsed.entries
    ]

    report = AnalyzerPipeline([PhpAnalyzer(), MagentoAnalyzer()]).run(
        entries, context()
    )

    assert [finding.count for finding in report.findings] == [6, 3]
    assert all(finding.category == "unclassified" for finding in report.findings)
    assert all(finding.level == "CRITICAL" for finding in report.findings)
    assert report.findings[0].first_seen == datetime(2026, 11, 6, 5, 19, 3, 295401, UTC)
    assert report.findings[0].last_seen == datetime(2026, 11, 6, 5, 19, 8, 295401, UTC)
    assert report.findings[0].source == (
        "/var/www/html/vendor/magento/framework/DB/Adapter/Pdo/Mysql.php:699"
    )
    assert parsed.stats.total_lines == 459
    assert parsed.stats.parsed_lines == 9
    assert parsed.stats.continuation_lines == 450
    assert parsed.stats.unparsed_lines == 0
    assert parsed.stats.level_counts == {"CRITICAL": 9}


def test_normalization_groups_dynamic_values_and_keeps_the_highest_level() -> None:
    lines = [
        f"[2026-11-06T05:19:0{i}+00:00] main.{level}: "
        f'Failed order {number}, id={identifier}, value="{value}" '
        f'in /var/www/html/app/Example.php:{line} {{"request":{number}}} []'
        for i, (level, number, identifier, value, line) in enumerate(
            [
                ("ERROR", 123, "aabbccddeeff0011", "first", 42),
                ("ALERT", 987, "112233aabbccddee", "second", 42),
                ("CRITICAL", 456, "abcdef0011223344", "third", 99),
            ]
        )
    ]
    entries = parse_lines_with_stats(lines, source="system.log").entries

    report = AnalyzerPipeline([]).run(entries, context())

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.count == 3
    assert finding.level == "ALERT"
    assert finding.source == "/var/www/html/app/Example.php:42"
    assert finding.message is not None
    assert all(
        value not in finding.message
        for value in ("123", "987", "aabbcc", "first", "third")
    )


@pytest.mark.parametrize(
    "level", ["ERROR", "CRITICAL", "ALERT", "EMERGENCY", "crit", "emerg"]
)
def test_every_error_level_is_reported(level: str) -> None:
    entries = parse_lines_with_stats(
        [f"[2026-11-06T05:19:00+00:00] main.{level}: Unknown failure {{}} []"],
        source="system.log",
    ).entries

    report = AnalyzerPipeline([]).run(entries, context())

    assert len(report.findings) == 1
    assert report.findings[0].count == 1


def test_fallback_excludes_low_levels_and_specific_matches_beyond_evidence_limit() -> (
    None
):
    lines = [
        f"[2026-11-06T05:19:0{i}+00:00] main.ERROR: "
        f"Allowed memory size of {i + 100} bytes exhausted"
        for i in range(7)
    ] + [
        "[2026-11-06T05:20:00+00:00] main.INFO: harmless",
        "[2026-11-06T05:20:01+00:00] main.WARNING: warning",
        "[2026-11-06T05:20:02+00:00] main.ERROR: Unknown failure",
    ]
    entries = [
        entry.model_copy(update={"line_number": None})
        for entry in parse_lines_with_stats(lines, source="system.log").entries
    ]

    report = AnalyzerPipeline([PhpAnalyzer()]).run(entries, context())

    assert [(finding.category, finding.count) for finding in report.findings] == [
        ("php", 7),
        ("unclassified", 1),
    ]


def test_groups_are_count_sorted_and_limited_without_truncating_specific_findings() -> (
    None
):
    lines = [
        "[2026-11-06T05:19:00+00:00] ERROR: " + message
        for message in [
            "third",
            "second",
            "second",
            "first",
            "first",
            "first",
            "Allowed memory size exhausted",
        ]
    ]
    entries = parse_lines_with_stats(lines, source="system.log").entries

    report = AnalyzerPipeline([PhpAnalyzer()]).run(entries, context(), top_n=2)

    assert [
        finding.message
        for finding in report.findings
        if finding.category == "unclassified"
    ] == ["first", "second"]
    assert any(finding.category == "php" for finding in report.findings)


def test_fallback_respects_time_filter_and_uses_stack_source() -> None:
    parsed = parse_lines_with_stats(
        [
            "[2026-11-05T05:19:00+00:00] ERROR: old failure",
            "#0 /var/www/html/app/Old.php(10): Example->run()",
            "[2026-11-06T05:19:00+00:00] ERROR: new failure",
            "#0 /var/www/html/app/New.php(20): Example->run()",
        ],
        source="system.log",
    )
    entries = filter_by_time(
        parsed.entries, TimeRange.parse("1d", datetime(2026, 11, 6, 6, tzinfo=UTC))
    )
    entries = [entry.model_copy(update={"line_number": None}) for entry in entries]

    report = AnalyzerPipeline([]).run(entries, context())

    assert len(report.findings) == 1
    assert report.findings[0].message == "new failure"
    assert report.findings[0].source == "/var/www/html/app/New.php:20"


def test_reports_carry_bounded_redacted_groups_in_every_format() -> None:
    entries = parse_lines_with_stats(
        [
            "[2026-11-06T05:19:00+00:00] ERROR: Failure "
            '{"password":"synthetic-secret", "token": "synthetic-token", '
            '"secret": "synthetic value"} []' + "x" * 1000
        ],
        source="system.log",
    ).entries
    report = AnalyzerPipeline([]).run(entries, context())

    for rendered in (
        render_terminal(report),
        render_markdown(report),
        render_json(report),
    ):
        assert "Unclassified errors" in rendered
        assert "No findings." not in rendered
        assert "synthetic-secret" not in rendered
        assert "synthetic-token" not in rendered
        assert "synthetic value" not in rendered
    group = json.loads(render_json(report))["findings"][0]
    assert (
        set(
            ("message", "count", "level", "first_seen", "last_seen", "sample", "source")
        )
        <= group.keys()
    )
    assert len(group["sample"]) <= 500
    assert "matched_entry_indexes" not in group


def test_orphan_stack_frames_stay_unrecognized() -> None:
    parsed = parse_lines_with_stats(
        ["#0 /var/www/html/app/Example.php(123): Example->run()", "Stack trace:"],
        source="system.log",
    )

    assert parsed.stats.continuation_lines == 0
    assert parsed.stats.unparsed_lines == 2


def test_named_ids_and_embedded_numbers_normalize_together() -> None:
    entries = parse_lines_with_stats(
        [
            "[2026-11-06T05:19:00+00:00] ERROR: Failed id=cart-Alpha9 order_123",
            "[2026-11-06T05:20:00+00:00] ERROR: Failed id=cart-Beta8 order_987",
        ],
        source="system.log",
    ).entries

    report = AnalyzerPipeline([]).run(entries, context())

    assert len(report.findings) == 1
    assert report.findings[0].count == 2


def test_matching_helper_claims_all_repeated_entries() -> None:
    entries = parse_lines_with_stats(
        ["[2026-11-06T05:19:00+00:00] ERROR: Deadlock found"] * 7,
        source="system.log",
    ).entries

    report = AnalyzerPipeline([MySQLAnalyzer()]).run(entries, context())

    assert len(report.findings) == 1
    assert report.findings[0].category == "mysql"
    assert report.findings[0].count == 7


def test_timestamps_use_actual_extremes_and_source_can_be_unknown() -> None:
    entries = parse_lines_with_stats(
        [
            "[2026-11-06T06:20:00+01:00] ERROR: Unknown failure",
            "[2026-11-06T05:19:00+00:00] ERROR: Unknown failure",
        ],
        source="system.log",
    ).entries

    finding = AnalyzerPipeline([]).run(entries, context()).findings[0]

    assert finding.first_seen == datetime(2026, 11, 6, 5, 19, tzinfo=UTC)
    assert finding.last_seen == datetime(2026, 11, 6, 5, 20, tzinfo=UTC)
    assert finding.source is None


@pytest.mark.parametrize(
    "secret",
    [
        '{"password":"synthetic secret with spaces"}',
        '{"token":"synthetic\\"quoted\\"secret"}',
        "{'api_key': 'synthetic secret'}",
        '{"password":"' + "synthetic-secret" * 100 + '"}',
    ],
)
def test_secret_values_are_redacted_before_sample_truncation(secret: str) -> None:
    entries = parse_lines_with_stats(
        ["[2026-11-06T05:19:00+00:00] ERROR: Failure " + secret],
        source="system.log",
    ).entries

    rendered = render_json(AnalyzerPipeline([]).run(entries, context()))

    assert "synthetic" not in rendered
    assert "[REDACTED]" in rendered
