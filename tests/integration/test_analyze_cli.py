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
