from typer.testing import CliRunner

from schnee.controllers.cli.main import app


def test_root_help_displays_cli_usage() -> None:
    """The root command exposes CLI help."""
    result = CliRunner().invoke(app, ["--help"], prog_name="schnee")

    assert result.exit_code == 0, "root help should exit successfully"
    assert "Usage:" in result.output, "root help should include Typer usage"
    assert "schnee" in result.output, "root help should identify the CLI name"
