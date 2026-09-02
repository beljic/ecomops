from typer.testing import CliRunner

from ecomops.cli.app import app


def test_help_lists_ecomops_usage() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "EcomOps Log Analyzer" in result.stdout


def test_version_prints_current_version() -> None:
    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert "ecomops 0.1.0" in result.stdout
