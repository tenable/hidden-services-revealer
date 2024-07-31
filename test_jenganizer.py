from unittest import TestCase
from click.testing import CliRunner
import jenganizer


class Test(TestCase):
    # Note - if you run this test, you will need to have AWS credentials set up
    def test_cli(self):
        runner = CliRunner()
        result = runner.invoke(
            jenganizer.cli,
            [
                "--username",
                "testuser",
                "--profile-name",
                "default",
                "--region-name",
                "us-west-2",
                "--time-span",
                "15",
            ],
        )
        assert result.exit_code == 0

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(jenganizer.cli, ["--help"])
        assert result.exit_code == 0
        assert "Usage: cli [OPTIONS]" in result.output
        assert "Options:" in result.output
        assert "--username TEXT" in result.output
        assert "--profile-name TEXT" in result.output
        assert "--region-name TEXT" in result.output
        assert "--time-start TEXT" in result.output
        assert "--time-end TEXT" in result.output
        assert "--time-span TEXT" in result.output
        assert "--depth INTEGER" in result.output
        assert "--output TEXT" in result.output
        assert "--verbosity" in result.output

