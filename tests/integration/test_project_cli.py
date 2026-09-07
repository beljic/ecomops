from pathlib import Path

import pytest
from typer.testing import CliRunner

from ecomops.cli.app import app


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
