import json
from pathlib import Path

import pytest

from ecomops.analyzers.traffic import MAX_TOP_N, summarize_traffic
from ecomops.config.schema import ProjectConfig
from ecomops.core.models import CountItem
from ecomops.logs.parsers import parse_lines_with_stats

FIXTURE = Path(__file__).parents[1] / "fixtures/logs/nginx_access_transfer.log"


def access_line(
    ip: str = "203.0.113.10",
    minute: int = 0,
    path: str = "/",
    status: int = 200,
    agent: str = "Mozilla/5.0",
) -> str:
    return (
        f'{ip} - - [03/Sep/2026:12:{minute:02d}:00 +0000] "GET {path} HTTP/1.1" '
        f'{status} 10 "-" "{agent}"\n'
    )


def entries(lines: list[str]):  # type: ignore[no-untyped-def]
    return parse_lines_with_stats(lines, source="access.log").entries


def test_summary_counts_ips_statuses_paths_agents_and_minutes() -> None:
    summary = summarize_traffic(
        entries(
            [
                access_line("203.0.113.10", 0, "/a", 200),
                access_line("203.0.113.10", 0, "/a", 403),
                access_line("203.0.113.10", 1, "/b", 404),
                access_line("192.0.2.1", 1, "/a", 429, agent="curl/8.5.0"),
                "not an access line\n",
            ]
        )
    )

    assert summary.total_requests == 4
    assert summary.unique_client_ips == 2
    assert summary.top_client_ips == [
        CountItem(value="203.0.113.10", count=3),
        CountItem(value="192.0.2.1", count=1),
    ]
    assert summary.status_counts == {"200": 1, "403": 1, "404": 1, "429": 1}
    assert summary.top_paths == [
        CountItem(value="/a", count=3),
        CountItem(value="/b", count=1),
    ]
    assert summary.top_user_agents == [
        CountItem(value="Mozilla/5.0", count=3),
        CountItem(value="curl/8.5.0", count=1),
    ]
    assert summary.peak_requests_per_minute == 2
    assert summary.busiest_minutes == [
        CountItem(value="2026-09-03T12:00:00+00:00", count=2),
        CountItem(value="2026-09-03T12:01:00+00:00", count=2),
    ]


def test_ties_are_ordered_deterministically_by_value() -> None:
    summary = summarize_traffic(
        entries([access_line("192.0.2.9"), access_line("192.0.2.1")])
    )

    assert [item.value for item in summary.top_client_ips] == [
        "192.0.2.1",
        "192.0.2.9",
    ]


def test_paths_drop_query_strings_so_tokens_are_not_aggregated() -> None:
    summary = summarize_traffic(
        entries(
            [
                access_line(path="/checkout?token=abc123"),
                access_line(path="/checkout?token=def456"),
            ]
        )
    )

    assert summary.top_paths == [CountItem(value="/checkout", count=2)]
    assert "abc123" not in summary.model_dump_json()


def test_user_agents_are_redacted_and_truncated() -> None:
    summary = summarize_traffic(
        entries([access_line(agent="bot password=hunter2 " + "x" * 500)])
    )

    agent = summary.top_user_agents[0].value
    assert "hunter2" not in agent
    assert len(agent) <= 200


def test_large_samples_stay_bounded_and_never_include_raw_lines() -> None:
    lines = [
        access_line(f"10.0.{index // 250}.{index % 250}", index % 60, f"/p{index}")
        for index in range(5_000)
    ]

    summary = summarize_traffic(entries(lines), top_n=5)

    assert summary.total_requests == 5_000
    assert summary.unique_client_ips == 5_000
    assert len(summary.top_client_ips) == 5
    assert len(summary.top_paths) == 5
    assert len(summary.busiest_minutes) == 5
    payload = summary.model_dump_json()
    assert '"GET' not in payload
    assert len(payload) < 5_000


@pytest.mark.parametrize("top_n", [0, MAX_TOP_N + 1])
def test_top_n_is_bounded(top_n: int) -> None:
    with pytest.raises(ValueError, match="top_n"):
        summarize_traffic([], top_n=top_n)


def test_fixture_summary_uses_the_alias_client_ip_policy() -> None:
    lines = FIXTURE.read_text(encoding="utf-8").splitlines(keepends=True)
    parsed = parse_lines_with_stats(
        lines, source="transfer.log", client_ip_source="x_forwarded_for"
    ).entries

    summary = summarize_traffic(parsed)

    assert summary.total_requests == 4
    assert summary.top_client_ips[0] == CountItem(value="192.0.2.44", count=1)
    assert {item.value for item in summary.top_client_ips} == {
        "198.51.100.7",
        "198.51.100.8",
        "192.0.2.44",
        "192.0.2.45",
    }


def test_service_returns_summary_with_read_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.core import services

    log = tmp_path / "access.log"
    log.write_text(access_line() + access_line(status=404), encoding="utf-8")
    project = ProjectConfig.model_validate(
        {
            "name": "example-shop",
            "connection": {"type": "local", "root": str(tmp_path)},
            "log_aliases": {"access": {"path": "access.log", "type": "nginx"}},
        }
    )
    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(lambda cls: ProjectRegistry({project.name: project})),
    )

    report = services.summarize_project_traffic("example-shop", "access")

    assert report.read.path == str(log)
    assert report.read.parse_stats is not None
    assert report.read.parse_stats.format_counts == {"nginx_access": 2}
    assert report.summary.status_counts == {"200": 1, "404": 1}
    assert report.warnings == []
    assert json.loads(report.model_dump_json())["summary"]["total_requests"] == 2


def test_service_warns_when_the_sample_has_no_access_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.core import services

    (tmp_path / "php.log").write_text(
        "[2026-09-03 10:00:00] ERROR: boom\n", encoding="utf-8"
    )
    project = ProjectConfig.model_validate(
        {
            "name": "example-shop",
            "connection": {"type": "local", "root": str(tmp_path)},
            "log_aliases": {"php": {"path": "php.log", "type": "php"}},
        }
    )
    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(lambda cls: ProjectRegistry({project.name: project})),
    )

    report = services.summarize_project_traffic("example-shop", "php")

    assert report.summary.total_requests == 0
    assert report.warnings == ["no web access log entries in the analyzed sample"]


def test_status_by_ip_ranks_client_ips_by_error_responses() -> None:
    summary = summarize_traffic(
        entries(
            [
                access_line("192.0.2.1", 0, "/a", 200),
                access_line("192.0.2.1", 0, "/b", 200),
                access_line("192.0.2.2", 0, "/wp-admin", 404),
                access_line("192.0.2.2", 0, "/login", 403),
                access_line("192.0.2.2", 1, "/login", 429),
                access_line("192.0.2.3", 1, "/x", 500),
                access_line("192.0.2.3", 1, "/x", 200),
            ]
        )
    )

    assert [item.model_dump() for item in summary.status_by_ip] == [
        {
            "client_ip": "192.0.2.2",
            "total_requests": 3,
            "error_requests": 3,
            "status_counts": {"403": 1, "404": 1, "429": 1},
        },
        {
            "client_ip": "192.0.2.3",
            "total_requests": 2,
            "error_requests": 1,
            "status_counts": {"200": 1, "500": 1},
        },
    ]


def test_status_by_ip_is_bounded_by_top_n() -> None:
    lines = [access_line(f"10.0.0.{index}", 0, "/x", 404) for index in range(30)]

    summary = summarize_traffic(entries(lines), top_n=4)

    assert len(summary.status_by_ip) == 4
