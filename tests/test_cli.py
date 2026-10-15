"""The CLI surface: commands, aliases, exit codes, no accidental writes."""

from __future__ import annotations

import json

import pytest

from jamfdisabler import cli
from jamfdisabler.hosts import BEGIN_MARKER

ORIGINAL = b"127.0.0.1 localhost\n"


@pytest.fixture()
def paths(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(ORIGINAL)
    return {
        "hosts": hosts,
        "state_dir": tmp_path / "state",
        "args": [
            "--hosts-file",
            str(hosts),
            "--state-dir",
            str(tmp_path / "state"),
            "--yes",
            "--no-color",
            "--no-flush-dns",
            "--no-elevate",
        ],
    }


def test_version(capsys):
    assert cli.main(["--version"]) == 0
    assert "JamfDisabler" in capsys.readouterr().out


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    assert "jamfdisabler" in capsys.readouterr().out.lower()


def test_help_command(capsys):
    assert cli.main(["help"]) == 0
    out = capsys.readouterr().out
    assert "reversible" in out and "examples:" in out


def test_unknown_command_is_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["frobnicate"])
    assert exc.value.code != 0


def test_list_runs_without_privileges(capsys):
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "telemetry.jamfcloud.com" in out


def test_scan_is_read_only(capsys):
    assert cli.main(["scan", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "Nothing was changed" in out


def test_on_off_cycle_through_the_cli(paths, capsys):
    assert cli.main(["on"] + paths["args"]) == 0
    assert BEGIN_MARKER in paths["hosts"].read_text()
    capsys.readouterr()

    assert cli.main(["status"] + paths["args"] + ["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["enabled"] is True

    assert cli.main(["off"] + paths["args"]) == 0
    assert paths["hosts"].read_bytes() == ORIGINAL


def test_aliases_work(paths, capsys):
    assert cli.main(["enable"] + paths["args"]) == 0
    capsys.readouterr()
    assert cli.main(["undo"] + paths["args"]) == 0
    assert paths["hosts"].read_bytes() == ORIGINAL


def test_dry_run_never_writes(paths, capsys):
    assert cli.main(["on", "--dry-run"] + paths["args"]) == 0
    assert paths["hosts"].read_bytes() == ORIGINAL
    assert not paths["state_dir"].exists()
    assert "Dry run" in capsys.readouterr().out


def test_no_color_env(monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    assert cli.main(["list"]) == 0
    assert "\033[" not in capsys.readouterr().out


def test_list_blocked_shows_active_block(paths, capsys):
    assert cli.main(["list", "--blocked"] + paths["args"]) == 0
    assert "None - the block is off" in capsys.readouterr().out
    cli.main(["on"] + paths["args"])
    capsys.readouterr()
    assert cli.main(["list", "--blocked"] + paths["args"]) == 0
    out = capsys.readouterr().out
    assert "telemetry.jamfcloud.com" in out


def test_state_dir_json_status(paths, capsys):
    cli.main(["on"] + paths["args"])
    capsys.readouterr()
    cli.main(["status"] + paths["args"] + ["--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["state_dir"].endswith("state")
    assert payload["hosts"]["path"] == str(paths["hosts"])
    assert payload["hosts"]["sha256_before"] and payload["hosts"]["sha256_after"]
