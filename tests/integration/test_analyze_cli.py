from pathlib import Path

from typer.testing import CliRunner

from ecomops.cli.app import app


def test_analyze_command_reports_php_memory_finding() -> None:
    log_path = Path("tests/fixtures/logs/php_memory.log")

    result = CliRunner().invoke(app, ["analyze", str(log_path)])

    assert result.exit_code == 0
    assert "PHP memory exhausted" in result.stdout
    assert "high" in result.stdout
    assert "line 1" in result.stdout


def test_analyze_command_can_enable_noop_ai_enrichment() -> None:
    log_path = Path("tests/fixtures/logs/php_memory.log")

    result = CliRunner().invoke(app, ["analyze", str(log_path), "--ai"])

    assert result.exit_code == 0
    assert "AI enrichment: enabled, provider=noop" in result.stdout


def test_direct_analysis_refuses_non_log_files(tmp_path: Path) -> None:
    secret = tmp_path / ".env"
    secret.write_text("DB_PASSWORD=hunter2\n", encoding="utf-8")
    config = tmp_path / "env.php"
    config.write_text("<?php return [];\n", encoding="utf-8")

    for path in (secret, config):
        result = CliRunner().invoke(app, ["analyze", str(path)])

        assert result.exit_code != 0
        assert "log path policy" in result.output.lower()
        assert "hunter2" not in result.output


def test_direct_analysis_refuses_a_symlink_to_a_non_log_file(tmp_path: Path) -> None:
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE KEY\n", encoding="utf-8")
    link = tmp_path / "innocent.log"
    link.symlink_to(secret)

    result = CliRunner().invoke(app, ["analyze", str(link)])

    assert result.exit_code != 0
    assert "PRIVATE KEY" not in result.output
