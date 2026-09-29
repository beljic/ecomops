import ipaddress
from pathlib import Path

import pytest
from pydantic import ValidationError

from ecomops.analyzers.security import scan_security
from ecomops.config.schema import ProjectConfig
from ecomops.logs.parsers import parse_lines_with_stats


def line(
    ip: str = "203.0.113.10",
    request: str = "GET / HTTP/1.1",
    status: int = 200,
    second: int = 0,
) -> str:
    return (
        f'{ip} - - [03/Sep/2026:12:00:{second:02d} +0000] "{request}" '
        f'{status} 10 "-" "agent"\n'
    )


def entries(lines: list[str]):  # type: ignore[no-untyped-def]
    return parse_lines_with_stats(lines, source="access.log").entries


def indicator(scan, indicator_id: str):  # type: ignore[no-untyped-def]
    return next(item for item in scan.indicators if item.id == indicator_id)


@pytest.mark.parametrize(
    ("request_line", "indicator_id"),
    [
        ("GET /wp-admin/setup-config.php HTTP/1.1", "scanner.wordpress"),
        ("GET /cgi-bin/luci HTTP/1.1", "scanner.cgi_bin"),
        ("GET /index.php?file=..%5C..%5Cwindows%5Cwin.ini HTTP/1.1", "scanner.win_ini"),
        ("GET /view?page=../../../../etc/passwd HTTP/1.1", "scanner.etc_passwd"),
        ("GET /.env HTTP/1.1", "scanner.dotenv"),
    ],
)
def test_scanner_paths_are_detected(request_line: str, indicator_id: str) -> None:
    scan = scan_security(entries([line(request=request_line, status=404)]))

    found = indicator(scan, indicator_id)
    assert found.count == 1
    assert found.top_client_ips[0].value == "203.0.113.10"
    assert found.first_seen is not None
    assert found.samples


def test_clean_traffic_has_no_indicators() -> None:
    scan = scan_security(entries([line(request="GET /checkout/cart/ HTTP/1.1")]))

    assert scan.indicators == []
    assert scan.requests_scanned == 1


def test_login_guessing_needs_repeated_posts_from_one_ip() -> None:
    login = "POST /customer/account/loginPost/ HTTP/1.1"
    lines = [line("192.0.2.7", login, 302, second) for second in range(6)]
    lines += [line("192.0.2.8", login, 302, 0)]

    scan = scan_security(entries(lines), login_threshold=5)

    found = indicator(scan, "login.guessing")
    assert found.count == 6
    assert [item.value for item in found.top_client_ips] == ["192.0.2.7"]


def test_login_posts_below_the_threshold_are_not_reported() -> None:
    login = "POST /wp-login.php HTTP/1.1"
    scan = scan_security(
        entries([line("192.0.2.7", login, 200, s) for s in range(3)]),
        login_threshold=5,
    )

    assert all(item.id != "login.guessing" for item in scan.indicators)


def test_malformed_request_lines_are_reported() -> None:
    scan = scan_security(entries([line(request="\\x16\\x03\\x01", status=400)]))

    assert indicator(scan, "request.malformed").count == 1


def test_tor_classification_is_unavailable_without_a_local_list() -> None:
    scan = scan_security(entries([line()]))

    assert scan.tor.status == "unavailable"
    assert scan.tor.matched_requests == 0


def test_tor_classification_uses_only_configured_cidrs() -> None:
    scan = scan_security(
        entries([line("198.51.100.20"), line("198.51.100.20"), line("192.0.2.1")]),
        tor_cidrs=[ipaddress.ip_network("198.51.100.0/24")],
    )

    assert scan.tor.status == "checked"
    assert scan.tor.matched_requests == 2
    assert scan.tor.top_client_ips[0].value == "198.51.100.20"


def test_samples_are_bounded_and_redacted() -> None:
    lines = [
        line(request=f"GET /site{index}/.env?token=secret{index} HTTP/1.1", status=404)
        for index in range(50)
    ]

    scan = scan_security(entries(lines), max_samples=3)

    found = indicator(scan, "scanner.dotenv")
    assert found.count == 50
    assert len(found.samples) == 3
    assert all("secret" not in sample for sample in found.samples)


def test_security_config_validates_tor_cidrs() -> None:
    project = ProjectConfig.model_validate(
        {
            "name": "example-shop",
            "connection": {"type": "local", "root": "/srv/example-shop"},
            "security": {"tor_cidrs": ["198.51.100.0/24"], "login_threshold": 3},
        }
    )

    assert project.security.tor_cidrs == [ipaddress.ip_network("198.51.100.0/24")]
    with pytest.raises(ValidationError, match="tor_cidrs"):
        ProjectConfig.model_validate(
            {
                "name": "example-shop",
                "connection": {"type": "local", "root": "/srv/example-shop"},
                "security": {"tor_cidrs": ["not-a-network"]},
            }
        )


def test_service_scan_uses_project_security_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.core import services

    (tmp_path / "access.log").write_text(
        line("198.51.100.20", "GET /.env HTTP/1.1", 404), encoding="utf-8"
    )
    project = ProjectConfig.model_validate(
        {
            "name": "example-shop",
            "connection": {"type": "local", "root": str(tmp_path)},
            "security": {"tor_cidrs": ["198.51.100.0/24"]},
            "log_aliases": {"access": {"path": "access.log", "type": "nginx"}},
        }
    )
    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(lambda cls: ProjectRegistry({project.name: project})),
    )

    report = services.scan_project_security("example-shop", "access")

    assert report.read.path == str(tmp_path / "access.log")
    assert report.scan.tor.matched_requests == 1
    assert [item.id for item in report.scan.indicators] == ["scanner.dotenv"]
