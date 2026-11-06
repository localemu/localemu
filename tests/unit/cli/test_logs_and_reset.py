"""``localemu start -d`` used to redirect stdout/stderr to DEVNULL - a
detached run had no logs anywhere, and there was no ``logs``/``reset``
command either. These pin the new ``logs``/``reset`` commands and the
``start -d`` log-file wiring."""
from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

from localemu.cli.main import _log_file_path, cli


@pytest.fixture(autouse=True)
def isolated_config_dir(tmp_path, monkeypatch):
    """Point CONFIG_DIR (and therefore the log file) at a scratch dir, so
    these tests never touch the real ``~/.localemu``."""
    from localemu import config

    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "DATA_DIR", "")
    return tmp_path


class TestLogFilePath:
    def test_lives_under_config_dir(self, isolated_config_dir):
        assert _log_file_path() == os.path.join(str(isolated_config_dir), "localemu.log")


class TestLogsCommand:
    def test_no_log_file_reports_clearly_and_exits_nonzero(self):
        result = CliRunner().invoke(cli, ["logs"])
        assert result.exit_code == 1
        assert "No log file found" in result.output

    def test_prints_existing_log_contents(self, isolated_config_dir, capfd):
        # The command shells out to `tail`, which writes to the real fd,
        # not through Click's captured `result.output` - capfd catches it.
        log_path = _log_file_path()
        with open(log_path, "w") as f:
            f.write("line one\nline two\n")

        result = CliRunner().invoke(cli, ["logs"])
        assert result.exit_code == 0
        out = capfd.readouterr().out
        assert "line one" in out
        assert "line two" in out


class TestResetCommand:
    def test_nothing_to_reset_is_a_clean_noop(self):
        result = CliRunner().invoke(cli, ["reset", "--yes"])
        assert result.exit_code == 0
        assert "Nothing to reset" in result.output

    def test_yes_flag_skips_confirmation_and_deletes_log(self, isolated_config_dir):
        log_path = _log_file_path()
        with open(log_path, "w") as f:
            f.write("some logs\n")

        result = CliRunner().invoke(cli, ["reset", "--yes"])
        assert result.exit_code == 0
        assert "LocalEmu state reset." in result.output
        assert not os.path.exists(log_path)

    def test_without_yes_aborts_on_decline(self, isolated_config_dir):
        log_path = _log_file_path()
        with open(log_path, "w") as f:
            f.write("some logs\n")

        result = CliRunner().invoke(cli, ["reset"], input="n\n")
        assert "Aborted" in result.output
        assert os.path.exists(log_path)  # declined - must survive

    def test_wipes_data_dir_when_configured(self, isolated_config_dir, monkeypatch):
        from localemu import config

        data_dir = isolated_config_dir / "data"
        data_dir.mkdir()
        (data_dir / "some_state.json").write_text("{}")
        monkeypatch.setattr(config, "DATA_DIR", str(data_dir))

        result = CliRunner().invoke(cli, ["reset", "--yes"])
        assert result.exit_code == 0
        assert not data_dir.exists()
