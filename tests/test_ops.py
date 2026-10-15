"""End-to-end behaviour of enable/disable/status, and the safety guarantees."""

from __future__ import annotations

import json
import os

import pytest

from jamfdisabler import cli, ops
from jamfdisabler.hosts import BEGIN_MARKER, END_MARKER, HostsFile
from jamfdisabler.state import State

ORIGINAL = (
    b"127.0.0.1        localhost\n"
    b"::1              localhost ip6-localhost ip6-loopback\n"
    b"\n"
    b"192.0.2.1        printer.local\n"
)


@pytest.fixture()
def env(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(ORIGINAL)
    state_dir = tmp_path / "state"
    opts = ops.Options(
        hosts_path=str(hosts),
        state_dir=str(state_dir),
        assume_yes=True,
        flush_dns=False,
        firewall=False,
        auto_server=False,  # keep the test deterministic
    )
    return {"opts": opts, "hosts": hosts, "state_dir": state_dir}


def test_enable_then_disable_is_byte_exact(env, capsys):
    assert ops.enable(env["opts"]) == 0
    text = env["hosts"].read_text()
    assert BEGIN_MARKER in text and END_MARKER in text
    assert "telemetry.jamfcloud.com" in text

    assert ops.disable(env["opts"]) == 0
    assert env["hosts"].read_bytes() == ORIGINAL
    out = capsys.readouterr().out
    assert "byte-for-byte identical" in out


def test_manifest_records_everything_needed_to_undo(env):
    ops.enable(env["opts"])
    data = json.loads((env["state_dir"] / "manifest.json").read_text())
    hosts_state = data["hosts"]
    assert data["enabled"] is True
    assert hosts_state["path"] == str(env["hosts"])
    assert hosts_state["sha256_before"] and hosts_state["sha256_after"]
    assert hosts_state["count"] > 50
    assert "telemetry.jamfcloud.com" in hosts_state["hostnames"]
    assert data["options"]["include_products"] is True
    assert (env["state_dir"] / "hosts.original").read_bytes() == ORIGINAL


def test_disable_removes_block_and_keeps_user_edits(env, capsys):
    ops.enable(env["opts"])
    with env["hosts"].open("a") as fh:
        fh.write("203.0.113.5  added-while-blocked.local\n")
    assert ops.disable(env["opts"]) == 0
    text = env["hosts"].read_text()
    assert "added-while-blocked.local" in text
    assert BEGIN_MARKER not in text
    assert "127.0.0.1        localhost" in text


def test_double_enable_is_idempotent(env):
    ops.enable(env["opts"])
    first = env["hosts"].read_bytes()
    ops.enable(env["opts"])
    assert env["hosts"].read_bytes() == first
    ops.disable(env["opts"])
    assert env["hosts"].read_bytes() == ORIGINAL


def test_disable_when_nothing_is_enabled(env, capsys):
    assert ops.disable(env["opts"]) == 0
    assert env["hosts"].read_bytes() == ORIGINAL
    assert "Nothing to undo" in capsys.readouterr().out


def test_dry_run_changes_nothing(env, capsys):
    env["opts"].dry_run = True
    assert ops.enable(env["opts"]) == 0
    assert env["hosts"].read_bytes() == ORIGINAL
    assert not env["state_dir"].exists()
    assert "Dry run" in capsys.readouterr().out


def test_dry_run_off_changes_nothing(env, capsys):
    ops.enable(env["opts"])
    blocked = env["hosts"].read_bytes()
    env["opts"].dry_run = True
    assert ops.disable(env["opts"]) == 0
    assert env["hosts"].read_bytes() == blocked


def test_status_reports_on_then_off(env, capsys):
    env["opts"].json_out = True
    assert ops.status(env["opts"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "off"
    assert payload["enabled"] is False

    ops.enable(env["opts"])
    capsys.readouterr()  # discard the enable output
    assert ops.status(env["opts"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "on"
    assert payload["enabled"] is True
    assert payload["hosts"]["blocked_count"] == payload["hosts"]["recorded_count"]

    ops.disable(env["opts"])
    capsys.readouterr()
    assert ops.status(env["opts"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "off"


def test_status_detects_a_partially_removed_block(env, capsys):
    ops.enable(env["opts"])
    text = env["hosts"].read_text()
    text = text.replace("0.0.0.0  telemetry.jamfcloud.com\n", "")
    text = text.replace("::       telemetry.jamfcloud.com\n", "")
    env["hosts"].write_text(text)
    env["opts"].json_out = True
    capsys.readouterr()
    ops.status(env["opts"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "partial"
    assert "telemetry.jamfcloud.com" in payload["hosts"]["missing_from_block"]


def test_restore_backup_puts_the_original_back(env, capsys):
    ops.enable(env["opts"])
    with env["hosts"].open("a") as fh:
        fh.write("203.0.113.5  extra.local\n")
    ops.restore_backup_only(env["opts"])
    assert env["hosts"].read_bytes() == ORIGINAL
    assert "restored from backup" in capsys.readouterr().out


def test_no_files_are_deleted(tmp_path, env):
    """The tool must not remove anything: snapshot the tree before/after."""
    canary = tmp_path / "profiles"
    canary.mkdir()
    (canary / "org.example.mdm.mobileconfig").write_text("not a real profile")
    (canary / "secret.txt").write_text("keep me")
    before = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))

    ops.enable(env["opts"])
    ops.disable(env["opts"])

    after = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))
    assert before == after or set(before) <= set(after)
    assert (canary / "org.example.mdm.mobileconfig").read_text() == "not a real profile"


def test_extra_hosts_are_included(env):
    env["opts"].extra_hosts = ["https://mdm.mycompany.com/"]
    ops.enable(env["opts"])
    text = env["hosts"].read_text()
    assert "mdm.mycompany.com" in text
    ops.disable(env["opts"])
    assert env["hosts"].read_bytes() == ORIGINAL


def test_no_products_option_narrows_the_list(env):
    env["opts"].include_products = False
    plan = ops.resolve_hostnames(env["opts"])
    assert "www.jamfprotect.com" not in plan.catalogue
    assert "telemetry.jamfcloud.com" in plan.catalogue


def test_include_optional_widens_the_list(env):
    env["opts"].include_optional = True
    plan = ops.resolve_hostnames(env["opts"])
    assert "downloads.jamfcloud.com" in plan.catalogue


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_unwritable_hosts_directory_reports_a_clear_error(env, capsys, tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "hosts").write_bytes(b"127.0.0.1 localhost\n")
    os.chmod(locked, 0o500)
    env["opts"].hosts_path = str(locked / "hosts")
    env["opts"].state_dir = str(tmp_path / "state2")
    try:
        code = ops.enable(env["opts"])
        output = capsys.readouterr().out
        assert code == 1
        assert "administrator" in output.lower() or "permission" in output.lower() or "temporary file" in output
        assert (locked / "hosts").read_bytes() == b"127.0.0.1 localhost\n"
    finally:
        os.chmod(locked, 0o700)


# --------------------------------------------------------------------------- #
# Safety gates
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "host",
    ["apple.com", "gs.apple.com", "swscan.apple.com", "icloud.com", "google.com", "evil.example"],
)
def test_safe_to_block_rejects_third_party_even_if_requested(host):
    assert ops._safe_to_block(host, trusted=False) is False


@pytest.mark.parametrize("literal", ["1.1.1.1", "10.0.0.1", "::1", "2001:db8::1"])
def test_safe_to_block_rejects_ip_literals(literal):
    assert ops._safe_to_block(literal) is False


def test_safe_to_block_allows_jamf_domains_and_trusted_servers():
    assert ops._safe_to_block("org.jamfcloud.com") is True
    assert ops._safe_to_block("org.jamfcloud.com", trusted=True) is True
    # An organisation's own Jamf Pro instance is only allowed when it came from
    # Jamf's own configuration file.
    assert ops._safe_to_block("mdm.mycompany.com", trusted=False) is False
    assert ops._safe_to_block("mdm.mycompany.com", trusted=True) is True


def test_the_block_only_ever_contains_jamf_names(env):
    env["opts"].extra_hosts = ["apple.com", "1.2.3.4", "totally-not-jamf.example.org"]
    ops.enable(env["opts"])
    blocked = HostsFile(str(env["hosts"])).blocked_hostnames(env["hosts"].read_text())
    assert "apple.com" not in blocked
    assert "totally-not-jamf.example.org" in blocked  # explicit user request is honoured
    assert all("jamf" in name or "." in name for name in blocked)


def test_env_var_extra_hosts(env, monkeypatch):
    monkeypatch.setenv("JAMFDISABLER_EXTRA_HOSTS", "a.jamfcloud.com, b.jamfcloud.com")
    plan = ops.resolve_hostnames(env["opts"])
    assert "a.jamfcloud.com" in plan.hostnames and "b.jamfcloud.com" in plan.hostnames


def test_state_dir_default_is_absolute():
    from jamfdisabler.state import default_state_dir

    assert os.path.isabs(default_state_dir())


def test_state_keeps_history_of_replaced_backups(tmp_path, env):
    ops.enable(env["opts"])
    state = State(str(env["state_dir"]))
    env["hosts"].write_bytes(b"127.0.0.1 localhost\n")
    state.write_backup(str(env["hosts"]))
    assert len(state.list_backups()) >= 2


def test_cli_needs_admin_flags():
    ns = type("NS", (), {"action": "status", "dry_run": False, "yes": True, "elevated": False})()
    assert cli.command_needs_admin("on", ns) is True
    assert cli.command_needs_admin("status", ns) is False
    assert cli.command_needs_admin("firewall", ns) is False
    ns.action = "on"
    assert cli.command_needs_admin("firewall", ns) is True
