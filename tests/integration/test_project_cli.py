import importlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ecomops.cli.app import app
from ecomops.core.models import AnalysisReport, LogSource


def write_project_config(projects_dir: Path, log_path: Path) -> None:
    (projects_dir / "local-store.yaml").write_text(
        f"""
name: local-store
platform: magento
connection:
  type: local
  root: {log_path.parent}
log_aliases:
  php:
    path: {log_path.name}
    type: php
""",
        encoding="utf-8",
    )


@pytest.mark.parametrize("output_format", ["terminal", "markdown", "json"])
def test_project_analyze_shows_unknown_errors_with_top_and_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output_format: str
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    path = tmp_path / "system.log"
    path.write_text(
        "[2026-11-05T05:19:00+00:00] main.CRITICAL: Old failure {} []\n"
        + "[2026-11-06T05:19:00+00:00] main.ERROR: Unable to proceed: "
        "the maintenance mode is enabled. {} []\n"
        * 3
        + "[2026-11-06T05:20:00+00:00] main.CRITICAL: Other failure {} []\n"
        + "#0 /var/www/html/app/Example.php(42): Example->run()\n",
        encoding="utf-8",
    )
    write_project_config(projects_dir, path)
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))

    result = CliRunner().invoke(
        app,
        [
            "project",
            "local-store",
            "analyze",
            "php",
            "--top",
            "1",
            "--since",
            "2026-11-06T00:00:00Z",
            "--until",
            "2026-11-07T00:00:00Z",
            "--format",
            output_format,
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Unclassified errors" in result.output
    assert "maintenance mode is enabled" in result.output
    assert "Old failure" not in result.output
    assert "Other failure" not in result.output
    assert "No findings." not in result.output
    if output_format == "json":
        report = json.loads(result.output)
        assert report["findings"][0]["count"] == 3
        assert report["findings"][0]["level"] == "ERROR"
        assert len(report["findings"]) == 1
        assert report["parse_stats"]["continuation_lines"] == 1
        assert report["parse_stats"]["filtered_out_lines"] == 1


def test_project_commands_list_show_and_analyze_bounded_local_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    log_path = tmp_path / "system.log"
    log_path.write_text(
        "PHP Fatal error: Allowed memory size of 1 bytes exhausted\n"
        "PHP Fatal error: Allowed memory size of 2 bytes exhausted\n",
        encoding="utf-8",
    )
    write_project_config(projects_dir, log_path)
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))

    runner = CliRunner()
    listed = runner.invoke(app, ["project", "list"])
    shown = runner.invoke(app, ["project", "show", "local-store"])
    analyzed = runner.invoke(
        app,
        [
            "project",
            "local-store",
            "analyze",
            "php",
            "--max-lines",
            "1",
            "--max-bytes",
            "1024",
        ],
    )

    assert listed.exit_code == 0
    assert "local-store" in listed.stdout
    assert "LOCAL" in listed.stdout
    assert shown.exit_code == 0
    assert "magento" in shown.stdout
    assert "php" in shown.stdout
    assert analyzed.exit_code == 0
    assert "PHP memory exhausted" in analyzed.stdout
    assert "Connection: LOCAL" in analyzed.stdout
    assert "Remote access: no" in analyzed.stdout
    assert "Sampling: bounded" in analyzed.stdout


def test_project_show_missing_name_returns_readable_error_without_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))

    result = CliRunner().invoke(app, ["project", "show", "missing-store"])

    assert result.exit_code == 1
    assert "Error: Project 'missing-store' is not configured." in result.output
    assert "Traceback" not in result.output


def test_direct_local_analysis_does_not_render_project_read_metadata(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "system.log"
    log_path.write_text(
        "PHP Fatal error: Allowed memory size exhausted\n", encoding="utf-8"
    )

    result = CliRunner().invoke(app, ["analyze", str(log_path)])

    assert result.exit_code == 0
    assert "PHP memory exhausted" in result.stdout
    assert "Read:" not in result.stdout
    assert "Sampling:" not in result.stdout


def test_project_analyze_supports_json_and_markdown_formats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    log_path = tmp_path / "system.log"
    log_path.write_text(
        "PHP Fatal error: Allowed memory size exhausted\n", encoding="utf-8"
    )
    write_project_config(projects_dir, log_path)
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))

    runner = CliRunner()
    json_result = runner.invoke(
        app,
        ["project", "local-store", "analyze", "php", "--format", "json"],
    )
    markdown_result = runner.invoke(
        app,
        ["project", "local-store", "analyze", "php", "--format", "markdown"],
    )

    assert json_result.exit_code == 0
    assert '"connection_type": "local"' in json_result.stdout
    assert markdown_result.exit_code == 0
    assert "# EcomOps Analysis" in markdown_result.stdout


def test_project_analyze_can_prompt_for_ephemeral_ssh_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    (projects_dir / "remote.yaml").write_text(
        """
name: remote
platform: magento
connection:
  type: ssh
  host: logs.example.test
  user: readonly
log_aliases:
  access:
    path: /var/log/access.log
    type: nginx
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))

    cli_module = importlib.import_module("ecomops.cli.app")
    received: dict[str, object] = {}

    def fake_analyze_project_log(
        project: str,
        alias: str,
        since: str,
        until: str | None,
        max_lines: int | None,
        max_bytes: int | None,
        ssh_password: str | None,
        *,
        top_n: int,
    ) -> AnalysisReport:
        received["password"] = ssh_password
        return AnalysisReport(
            source=LogSource(type="ssh", project=project, alias=alias),
            findings=[],
            generated_at=datetime(2026, 9, 9, tzinfo=UTC),
            connection_type="ssh",
            remote_access=True,
        )

    monkeypatch.setattr(cli_module, "getpass", lambda prompt: "one-time-secret")
    monkeypatch.setattr(cli_module, "analyze_project_log", fake_analyze_project_log)

    result = CliRunner().invoke(
        app,
        ["project", "remote", "analyze", "access", "--prompt-password"],
    )

    assert result.exit_code == 0
    assert received == {"password": "one-time-secret"}
    assert "one-time-secret" not in result.output


@pytest.mark.parametrize(
    ("arguments", "expected_error"),
    [
        (
            ["project", "local-store", "analyze", "missing"],
            "Error: Log alias 'missing' is not configured for project 'local-store'.",
        ),
        (
            [
                "project",
                "local-store",
                "analyze",
                "php",
                "--since",
                "not-a-time",
            ],
            "Error: Invalid time range: not-a-time",
        ),
        (
            [
                "project",
                "local-store",
                "analyze",
                "php",
                "--since",
                "2026-01-02T00:00:00+00:00",
                "--until",
                "2026-01-01T00:00:00+00:00",
            ],
            "Error: until must not be earlier than since",
        ),
    ],
)
def test_project_cli_renders_expected_errors_without_tracebacks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    expected_error: str,
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    log_path = tmp_path / "system.log"
    log_path.write_text("", encoding="utf-8")
    write_project_config(projects_dir, log_path)
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))

    result = CliRunner().invoke(app, arguments)

    assert result.exit_code == 1
    assert expected_error in result.output
    assert "Traceback" not in result.output


def write_remote_project(projects_dir: Path) -> None:
    (projects_dir / "remote.yaml").write_text(
        """
name: remote
connection:
  type: ssh
  host: logs.example.test
  user: readonly
log_aliases:
  access:
    path: /var/log/access.log
    type: nginx
""",
        encoding="utf-8",
    )


def capture_password(
    monkeypatch: pytest.MonkeyPatch, received: dict[str, object]
) -> None:
    cli_module = importlib.import_module("ecomops.cli.app")

    def fake_analyze_project_log(
        project: str, alias: str, **kwargs: object
    ) -> AnalysisReport:
        received["password"] = kwargs["ssh_password"]
        return AnalysisReport(
            source=LogSource(type="ssh", project=project, alias=alias),
            findings=[],
            generated_at=datetime(2026, 9, 9, tzinfo=UTC),
            connection_type="ssh",
            remote_access=True,
        )

    def must_not_prompt(prompt: str) -> str:
        raise AssertionError("--password-stdin must not prompt")

    monkeypatch.setattr(cli_module, "analyze_project_log", fake_analyze_project_log)
    monkeypatch.setattr(cli_module, "getpass", must_not_prompt)


@pytest.mark.parametrize(
    ("stdin", "expected"),
    [
        ("s3cret-value\n", "s3cret-value"),
        ("s3cret-value\r\n", "s3cret-value"),
        ("s3cret-value", "s3cret-value"),
        ("  spaced secret \n\n", "  spaced secret \n"),
    ],
)
def test_password_stdin_strips_only_one_trailing_newline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdin: str, expected: str
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    write_remote_project(projects_dir)
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))
    received: dict[str, object] = {}
    capture_password(monkeypatch, received)

    result = CliRunner().invoke(
        app,
        ["project", "remote", "analyze", "access", "--password-stdin"],
        input=stdin,
    )

    assert result.exit_code == 0, result.output
    assert received == {"password": expected}
    assert "s3cret" not in result.output


def test_password_stdin_and_prompt_password_are_mutually_exclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    write_remote_project(projects_dir)
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))
    received: dict[str, object] = {}
    capture_password(monkeypatch, received)

    result = CliRunner().invoke(
        app,
        [
            "project",
            "remote",
            "analyze",
            "access",
            "--password-stdin",
            "--prompt-password",
        ],
        input="s3cret-value\n",
    )

    assert result.exit_code != 0
    assert "Use either --password-stdin or --prompt-password" in result.output
    assert "s3cret" not in result.output
    assert received == {}


def test_empty_password_stdin_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    write_remote_project(projects_dir)
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))
    received: dict[str, object] = {}
    capture_password(monkeypatch, received)

    result = CliRunner().invoke(
        app,
        ["project", "remote", "analyze", "access", "--password-stdin"],
        input="\n",
    )

    assert result.exit_code != 0
    assert "empty" in result.output
    assert received == {}


def test_password_stdin_is_rejected_for_local_projects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    log_path = tmp_path / "system.log"
    log_path.write_text("", encoding="utf-8")
    write_project_config(projects_dir, log_path)
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))

    result = CliRunner().invoke(
        app,
        ["project", "local-store", "analyze", "php", "--password-stdin"],
        input="s3cret-value\n",
    )

    assert result.exit_code != 0
    assert "only valid for SSH projects" in result.output
    assert "s3cret" not in result.output


def test_stdin_password_never_appears_in_authentication_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.core.exceptions import SSHPermissionDeniedError

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    write_remote_project(projects_dir)
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))
    cli_module = importlib.import_module("ecomops.cli.app")

    def deny(*args: object, **kwargs: object) -> AnalysisReport:
        raise SSHPermissionDeniedError("SSH permission denied")

    monkeypatch.setattr(cli_module, "analyze_project_log", deny)

    result = CliRunner().invoke(
        app,
        ["project", "remote", "analyze", "access", "--password-stdin"],
        input="s3cret-value\n",
    )

    assert result.exit_code == 1
    assert "SSH permission denied" in result.output
    assert "s3cret" not in result.output
    assert result.exception is None or "s3cret" not in repr(result.exception)


def test_password_options_are_visible_in_help() -> None:
    result = CliRunner().invoke(app, ["project", "--help"])

    assert "--prompt-password" in result.output
    assert "--password-stdin" in result.output


ACCESS_LOG = (
    '192.0.2.44 - - [03/Sep/2026:12:01:05 +0000] "GET /wp-admin/setup.php HTTP/1.1" '
    '404 153 "-" "ExampleScanner/1.0"\n'
    '203.0.113.10 - - [03/Sep/2026:12:01:06 +0000] "POST /customer/account/loginPost/ '
    'HTTP/1.1" 403 0 "-" "curl/8.5.0"\n'
    '203.0.113.10 - - [03/Sep/2026:12:01:07 +0000] "GET /checkout HTTP/1.1" '
    '200 10 "-" "Mozilla/5.0"\n'
)


def write_access_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    (tmp_path / "access.log").write_text(ACCESS_LOG, encoding="utf-8")
    (projects_dir / "example-shop.yaml").write_text(
        f"""
name: example-shop
connection:
  type: local
  root: {tmp_path}
log_aliases:
  access:
    path: access.log
    type: nginx
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))


def test_project_traffic_command_prints_a_bounded_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_access_project(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        app, ["project", "example-shop", "traffic", "access", "--top", "2"]
    )

    assert result.exit_code == 0, result.output
    assert "Requests: 3 from 2 client IPs" in result.output
    assert "Status counts: 200=1, 403=1, 404=1" in result.output
    assert "Top client IPs: 203.0.113.10=2, 192.0.2.44=1" in result.output
    assert "Errors by client IP:" in result.output
    assert "192.0.2.44: 404=1" in result.output
    assert "GET /wp-admin" not in result.output


def test_project_traffic_command_supports_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_access_project(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        app, ["project", "example-shop", "traffic", "access", "--format", "json"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["total_requests"] == 3
    assert payload["read"]["alias"] == "access"


def test_project_security_command_prints_indicators(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_access_project(tmp_path, monkeypatch)

    result = CliRunner().invoke(app, ["project", "example-shop", "security", "access"])

    assert result.exit_code == 0, result.output
    assert "Requests scanned: 3" in result.output
    assert "[scanner.wordpress] WordPress probe" in result.output
    assert "count: 1" in result.output
    assert "Tor classification: unavailable" in result.output


def test_project_traffic_rejects_an_out_of_range_top(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_access_project(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        app, ["project", "example-shop", "traffic", "access", "--top", "0"]
    )

    assert result.exit_code != 0
    assert "not in the range" in result.output
