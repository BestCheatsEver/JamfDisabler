"""Hosts-file surgery: byte-exact round trips and preservation rules."""

from __future__ import annotations

import os

import pytest

from jamfdisabler import hosts as hosts_mod
from jamfdisabler.hosts import HostsFile

NAMES = ["telemetry.jamfcloud.com", "metrics.jamfcloud.com", "patch.jamfcloud.com"]

SAMPLES = {
    "lf_trailing_newline": b"127.0.0.1 localhost\n::1 localhost\n",
    "no_trailing_newline": b"127.0.0.1 localhost",
    "empty": b"",
    "only_newline": b"\n",
    "crlf": b"127.0.0.1 localhost\r\n192.0.2.1 printer.local\r\n",
    "blank_lines_between": b"127.0.0.1 localhost\n\n\n192.0.2.1 printer\n",
    "user_block_untouched": (
        b"127.0.0.1 localhost\n# my own block\n0.0.0.0 ads.example.com\n0.0.0.0 telemetry.jamfcloud.com\n"
    ),
    "latin1_comment": "127.0.0.1 localhost\n# caf\xe9\n".encode("latin-1"),
    "no_final_newline_comments": b"# one\n# two",
    "tabs": b"127.0.0.1\tlocalhost\tlocalhost.localdomain\n",
}


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_round_trip_is_byte_exact(tmp_path, name):
    path = tmp_path / "hosts"
    original = SAMPLES[name]
    path.write_bytes(original)

    hf = HostsFile(str(path))
    result = hf.apply(NAMES)
    assert result.changed
    assert hf.has_block(path.read_bytes().decode("utf-8", "replace"))

    back = hf.revert(expected_extra=NAMES, separator_text=result.separator_text)
    assert back.changed
    assert path.read_bytes() == original, "hosts file was not restored byte-for-byte"


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_render_is_idempotent(tmp_path, name):
    path = tmp_path / "hosts"
    path.write_bytes(SAMPLES[name])
    hf = HostsFile(str(path))

    first = hf.apply(NAMES)
    after_first = path.read_bytes()
    again = hf.apply(NAMES, previous_separator=first.separator_text)
    assert again.already_done
    assert path.read_bytes() == after_first


def test_apply_does_not_touch_unrelated_lines(tmp_path):
    path = tmp_path / "hosts"
    original = SAMPLES["user_block_untouched"]
    path.write_bytes(original)
    hf = HostsFile(str(path))
    hf.apply(NAMES)
    text = path.read_text()
    assert "0.0.0.0 ads.example.com" in text  # user entry before our block
    assert "# my own block" in text
    # The user's own Jamf entry is duplicated by us but never rewritten.
    assert text.count("0.0.0.0 telemetry.jamfcloud.com") >= 1


def test_revert_keeps_foreign_lines_inside_the_block(tmp_path):
    path = tmp_path / "hosts"
    path.write_bytes(b"127.0.0.1 localhost\n")
    hf = HostsFile(str(path))
    first = hf.apply(NAMES)

    text = path.read_text().splitlines()
    end = text.index(hosts_mod.END_MARKER)
    text.insert(end, "198.51.100.7   keep-me.example.com")
    text.insert(end, "# a comment the user added")
    path.write_text("\n".join(text) + "\n")

    back = hf.revert(expected_extra=NAMES, separator_text=first.separator_text)
    result = path.read_text()
    assert "keep-me.example.com" in result
    assert "# a comment the user added" in result
    assert hosts_mod.BEGIN_MARKER not in result
    assert hosts_mod.END_MARKER not in result
    assert len(back.preserved_lines) == 2


def test_missing_end_marker_is_removed_without_leaving_junk(tmp_path):
    """A half-written block must still be removable, leaving no stray markers."""
    path = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n"
    path.write_bytes(original)
    hf = HostsFile(str(path))
    result = hf.apply(NAMES)

    # Simulate a block that lost its end marker (editor crash, disk full, ...)
    path.write_text(path.read_text().split(hosts_mod.END_MARKER)[0])

    back = hf.revert(expected_extra=NAMES, separator_text=result.separator_text)
    assert back.truncated_block
    text = path.read_text()
    assert "jamfcloud.com" not in text
    assert hosts_mod.END_MARKER not in text
    assert hosts_mod.BEGIN_MARKER not in text
    assert path.read_bytes() == original


def test_revert_without_block_is_a_noop(tmp_path):
    path = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n"
    path.write_bytes(original)
    hf = HostsFile(str(path))
    result = hf.revert()
    assert result.already_done and not result.changed
    assert path.read_bytes() == original


def test_apply_creates_missing_hosts_file(tmp_path):
    path = tmp_path / "hosts"
    hf = HostsFile(str(path))
    result = hf.apply(NAMES)
    assert result.changed and path.exists()
    hf.revert(expected_extra=NAMES, separator_text=result.separator_text)
    assert path.read_bytes() == b""


def test_crlf_files_keep_crlf(tmp_path):
    path = tmp_path / "hosts"
    path.write_bytes(SAMPLES["crlf"])
    hf = HostsFile(str(path))
    result = hf.apply(NAMES)
    raw = path.read_bytes()
    assert b"\r\n" in raw
    assert b"\n\n" not in raw.replace(b"\r\n", b"")
    assert result.eol == "\r\n"


def test_latin1_file_survives_round_trip(tmp_path):
    path = tmp_path / "hosts"
    path.write_bytes(SAMPLES["latin1_comment"])
    hf = HostsFile(str(path))
    result = hf.apply(NAMES)
    assert result.encoding in ("latin-1", "utf-8")
    hf.revert(expected_extra=NAMES, separator_text=result.separator_text)
    assert path.read_bytes() == SAMPLES["latin1_comment"]


@pytest.mark.skipif(os.name == "nt", reason="Windows has no POSIX permission bits")
def test_permissions_are_preserved(tmp_path):
    path = tmp_path / "hosts"
    path.write_bytes(b"127.0.0.1 localhost\n")
    os.chmod(path, 0o644)
    hf = HostsFile(str(path))
    hf.apply(NAMES)
    assert (os.stat(path).st_mode & 0o777) == 0o644


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs extra Windows privileges")
def test_symlinked_hosts_writes_through_to_the_target(tmp_path):
    target = tmp_path / "real-hosts"
    target.write_bytes(b"127.0.0.1 localhost\n")
    link = tmp_path / "hosts"
    link.symlink_to(target)

    hf = HostsFile(str(link))
    assert hf.is_symlink
    result = hf.apply(NAMES)
    assert link.is_symlink(), "the symlink itself must not be replaced by a file"
    assert hosts_mod.BEGIN_MARKER in target.read_text()
    hf.revert(expected_extra=NAMES, separator_text=result.separator_text)
    assert target.read_bytes() == b"127.0.0.1 localhost\n"


def test_blocked_hostnames_and_verify(tmp_path):
    path = tmp_path / "hosts"
    path.write_bytes(b"127.0.0.1 localhost\n")
    hf = HostsFile(str(path))
    hf.apply(NAMES)
    assert sorted(NAMES) == hf.blocked_hostnames(path.read_text())
    assert hf.unresolved_expected(NAMES) == []
    assert hf.unresolved_expected(["notblocked.jamfcloud.com"]) == ["notblocked.jamfcloud.com"]


def test_unrelated_sinkhole_entries_are_never_removed(tmp_path):
    """Someone else's ad-blocker style entries must survive an off cycle."""
    path = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n0.0.0.0 doubleclick.net\n0.0.0.0 my-own-thing.example.com\n"
    path.write_bytes(original)
    hf = HostsFile(str(path))
    result = hf.apply(NAMES)
    hf.revert(expected_extra=NAMES, separator_text=result.separator_text)
    assert path.read_bytes() == original


def test_summary_reports_state(tmp_path):
    path = tmp_path / "hosts"
    path.write_bytes(b"127.0.0.1 localhost\n")
    hf = HostsFile(str(path))
    assert hf.summary()["explicit_block"] is False
    hf.apply(NAMES)
    summary = hf.summary()
    assert summary["explicit_block"] is True
    assert summary["blocked_count"] == len(NAMES)


def test_default_hosts_path_is_absolute():
    assert os.path.isabs(hosts_mod.default_hosts_path())


def test_render_reports_what_it_would_do(tmp_path):
    path = tmp_path / "hosts"
    path.write_bytes(b"127.0.0.1 localhost\n")
    hf = HostsFile(str(path))
    new_text, result = hf.render(NAMES)
    assert result.entries_added == len(NAMES)
    assert "0.0.0.0" in new_text and "::" in new_text
    assert path.read_bytes() == b"127.0.0.1 localhost\n"  # render never writes
