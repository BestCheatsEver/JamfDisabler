"""The operations behind the CLI: enable, disable, status, scan.

Design goals, in order:

1. **Never destroy data.**  No file is deleted, no profile is touched, no
   service is stopped.  The only file modified is the hosts file, and only
   between our own markers.
2. **Always reversible.**  The pristine hosts bytes are kept in the state
   directory, and ``disable`` reports honestly whether it managed a
   byte-for-byte restore or had to merge around edits made in the meantime.
3. **Always legible.**  Every step prints what it did, in order, so the user can
   audit the tool by reading its output (or ``log.txt`` in the state dir).
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import APP_NAME, PROJECT_URL, __version__
from . import console as c
from . import firewall as fw
from .endpoints import (
    BLOCK_IPV4,
    catalogue_groups,
    default_hostnames,
    is_jamf_hostname,
    normalise_hostname,
)
from .hosts import HostsError, HostsFile, default_hosts_path
from .state import State, StateError
from .sysinfo import (
    DetectedServer,
    detect_jamf_server,
    find_jamf_executables,
    find_jamf_paths,
    flush_dns,
    is_admin,
    is_managed_device,
    is_third_party_infrastructure,
    jamf_processes,
    looks_like_ip_literal,
    platform_name,
    python_info,
)


@dataclass
class Options:
    """Everything the CLI can change, in one place."""

    no_elevate: bool = False
    hosts_path: Optional[str] = None
    state_dir: Optional[str] = None
    include_products: bool = True
    include_optional: bool = False
    extra_hosts: List[str] = field(default_factory=list)
    auto_server: bool = True
    all_detected: bool = False
    deep_scan: bool = False
    firewall: bool = True
    dry_run: bool = False
    assume_yes: bool = False
    quiet: bool = False
    json_out: bool = False
    force: bool = False
    verify_dns: bool = False
    flush_dns: bool = True

    def state(self) -> State:
        return State(self.state_dir)

    def hosts(self) -> HostsFile:
        return HostsFile(self.hosts_path)


@dataclass
class HostPlan:
    hostnames: List[str] = field(default_factory=list)
    catalogue: List[str] = field(default_factory=list)
    detected: List[DetectedServer] = field(default_factory=list)
    detected_excluded: List[DetectedServer] = field(default_factory=list)
    rejected: List[Tuple[str, str]] = field(default_factory=list)
    extra: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _log(opts: Options, message: str) -> None:
    try:
        opts.state().append_log(message)
    except Exception:
        pass


def resolve_hostnames(opts: Options, quiet: bool = False) -> HostPlan:
    """Work out exactly which hostnames we are going to sinkhole.

    Three sources, all of them optional and all reported before anything is
    written:

    * the built-in catalogue of Jamf endpoints,
    * this machine's own Jamf server, read from Jamf's configuration files,
    * ``--add-host`` / ``JAMFDISABLER_EXTRA_HOSTS`` entries the user supplied.
    """
    detected: List[DetectedServer] = []
    if opts.auto_server:
        detected = detect_jamf_server(deep=opts.deep_scan)

    block: List[str] = []
    excluded: List[DetectedServer] = []
    for item in detected:
        if not _safe_to_block(item.host, trusted=item.trusted):
            excluded.append(item)
            continue
        if item.tier == 1 or opts.all_detected:
            block.append(item.host)
        else:
            excluded.append(item)

    extra: List[str] = []
    rejected: List[Tuple[str, str]] = []
    for value in list(opts.extra_hosts) + _env_extra_hosts():
        clean = normalise_hostname(value)
        if not clean:
            rejected.append((str(value), "not a usable hostname"))
            continue
        if is_third_party_infrastructure(clean) or looks_like_ip_literal(clean):
            rejected.append((clean, "OS/cloud infrastructure or a bare IP - blocking it would break things"))
            continue
        extra.append(clean)

    catalogue = default_hostnames(
        include_products=opts.include_products,
        include_optional=opts.include_optional,
    )
    plan = HostPlan(
        catalogue=catalogue,
        detected=detected,
        detected_excluded=excluded,
        extra=sorted(set(extra)),
        rejected=rejected,
    )
    plan.hostnames = sorted(set(catalogue) | set(block) | set(plan.extra))
    return plan


def _safe_to_block(host: str, trusted: bool = False) -> bool:
    """Final veto before a hostname goes into the block.

    Guarantees: no bare IP literals, no OS/cloud infrastructure, and nothing
    that is not recognisably Jamf-owned unless it was read straight out of
    Jamf's own configuration (an organisation's private Jamf Pro domain).
    """
    clean = normalise_hostname(host)
    if not clean:
        return False
    if is_third_party_infrastructure(clean) or looks_like_ip_literal(clean):
        return False
    return trusted or is_jamf_hostname(clean)


def _env_extra_hosts() -> List[str]:
    raw = os.environ.get("JAMFDISABLER_EXTRA_HOSTS", "")
    return [part for part in raw.replace(";", ",").replace("\n", ",").split(",") if part.strip()]


def _print_plan(plan: HostPlan, opts: Options) -> None:
    c.field("Hostnames to block", str(len(plan.hostnames)))
    c.field("  from catalogue", str(len(plan.catalogue)))
    if plan.detected:
        c.out()
        c.info("Jamf server(s) found on this machine:")
        for item in plan.detected:
            marker = "" if item.tier == 1 or opts.all_detected else "  (not blocked - use --all-detected)"
            c.bullet("{}{}".format(item.host, marker))
            c.note("      from {}{}".format(item.source, "" if item.trusted else "  [scanned]"))
    if plan.extra:
        c.out()
        c.info("Extra hostnames from your options:")
        for host in plan.extra:
            c.bullet(host)
    if plan.rejected:
        c.out()
        for host, reason in plan.rejected:
            c.warn("Refusing to block {}: {}".format(host, reason))


def _print_privacy_note() -> None:
    c.out()
    c.note(
        "Note: the hostname above may identify your school or employer. Keep it out of screenshots and public posts."
    )


def ensure_state_backup(opts: Options, hosts: HostsFile, state: State, data: Dict) -> Dict:
    """Take the pristine hosts backup exactly once, before the first change."""
    existing = state.hosts_state()
    if existing.get("sha256_before") and os.path.isfile(state.backup_path):
        return data
    original = hosts.read_bytes()
    backup_path = state.write_backup(hosts.real_path if os.path.exists(hosts.real_path) else hosts.path)
    with open(backup_path, "rb") as fh:
        backup_bytes = fh.read()
    hosts_state = dict(existing)
    hosts_state.update(
        {
            "path": hosts.path,
            "real_path": hosts.real_path,
            "sha256_before": sha256_hex(backup_bytes),
            "bytes_before": len(backup_bytes),
            "backup": backup_path,
            "backup_sha256": sha256_hex(backup_bytes),
            "first_seen": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
    )
    del original
    data["hosts"] = hosts_state
    return data


# --------------------------------------------------------------------------- #
# enable
# --------------------------------------------------------------------------- #
def enable(opts: Options) -> int:
    state = opts.state()
    hosts = opts.hosts()

    try:
        hosts.summary()  # fail early if the hosts file is unreadable
    except HostsError as exc:
        c.fail(str(exc))
        return 1

    plan = resolve_hostnames(opts)
    if not plan.hostnames:
        c.fail("No hostnames to block - refusing to change anything.")
        return 1

    c.head("Plan")
    _print_plan(plan, opts)
    c.out()
    c.field("Hosts file", "{}".format(hosts.path))
    c.field("State directory", state.dir)
    if hosts.is_symlink:
        c.field("  (symlink to)", hosts.real_path)
    if not opts.firewall or not fw.is_supported():
        c.field("Firewall rules", "not used on this platform")
    else:
        c.field("Firewall rules", "outbound block, one rule per Jamf program")

    if not opts.assume_yes:
        c.out()
        c.info("What this does:")
        c.bullet("Redirects the {} Jamf hostnames above to {} (sinkhole).".format(len(plan.hostnames), BLOCK_IPV4))
        c.bullet("Keeps a copy of your original hosts file so `jamfdisabler off` restores it exactly.")
        c.bullet("Adds clearly named, reversible firewall rules (Windows only).")
        c.out()
        c.info("What this does NOT do:")
        c.bullet("Does not delete, remove or modify configuration profiles.")
        c.bullet("Does not un-enrol the device, remove the Jamf agent or stop services.")
        c.bullet("Does not change any other line of your hosts file.")
        c.out()
        c.warn(
            "This WILL stop Jamf from managing or updating this computer (no inventory, no "
            "policies, no remote scripts) until you run `jamfdisabler off`."
        )
        if is_managed_device():
            c.warn(
                "An MDM enrolment/profile is present on this machine; blocking it may breach "
                "your organisation's policy."
            )
        if not c.confirm("Enable the block now?", default=True, assume_yes=opts.assume_yes):
            c.info("Nothing was changed.")
            return 0

    if opts.dry_run:
        new_text, result = hosts.render(plan.hostnames)
        c.head("Dry run - no changes written")
        c.field("Lines that would be added", str(result.lines_added))
        c.field("Entries", str(result.entries_added))
        already = hosts.has_block(hosts.read_bytes().decode("utf-8", "replace"))
        c.field("Block already present", "yes" if already else "no")
        if result.preserved_lines:
            c.warn(
                "{} non-JamfDisabler line(s) inside a previous block would be preserved.".format(
                    len(result.preserved_lines)
                )
            )
        c.note("First 6 lines of the block that would be written:")
        for line in new_text.splitlines()[-result.lines_added :][:6]:
            c.note("  " + line)
        return 0

    # ------------------------------------------------------------------ write
    c.head("Applying")
    data: Dict = dict(state.load())
    data["enabled"] = True
    data["platform"] = platform_name()
    data["options"] = {
        "include_products": opts.include_products,
        "include_optional": opts.include_optional,
        "auto_server": opts.auto_server,
        "extra_hosts": plan.extra,
        "firewall": bool(opts.firewall and fw.is_supported()),
    }

    try:
        data = ensure_state_backup(opts, hosts, state, data)
        result = hosts.apply(plan.hostnames, previous_separator=data.get("hosts", {}).get("separator_text", ""))
    except (HostsError, StateError) as exc:
        c.fail(str(exc))
        return 1

    if result.already_done:
        c.ok("Hosts sinkhole was already in place ({} entries) - nothing to write.".format(len(result.hostnames)))
    else:
        c.ok(
            "Hosts file updated: {} entries ({} lines), {} line(s) of ours replaced.".format(
                result.entries_added, result.lines_added, result.lines_removed
            )
        )
    if result.preserved_lines:
        c.warn(
            "Preserved {} line(s) inside the block that JamfDisabler did not write.".format(len(result.preserved_lines))
        )

    after = hosts.read_bytes()
    hosts_state = data.get("hosts", {})
    hosts_state.update(
        {
            "path": hosts.path,
            "real_path": hosts.real_path,
            "sha256_after": sha256_hex(after),
            "bytes_after": len(after),
            "encoding": result.encoding,
            "eol": result.eol,
            "separator_text": result.separator_text,
            "hostnames": sorted(plan.hostnames),
            "dynamic_hostnames": sorted({d.host for d in plan.detected}),
            "blocked_dynamic_hostnames": sorted({d.host for d in plan.detected if d.tier == 1 or opts.all_detected}),
            "count": len(result.hostnames) or len(plan.hostnames),
            "applied_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
    )
    data["hosts"] = hosts_state
    state.save(data)

    # ---------------------------------------------------------------- firewall
    if opts.firewall and fw.is_supported():
        exes = find_jamf_executables()
        if not exes:
            c.warn("No Jamf executables found - skipping firewall rules (hosts block is active).")
        else:
            rules = []
            for exe in exes:
                res = fw.block_program(exe)
                for message in res.messages:
                    (c.ok if res.changed else c.note)(message)
                for name in res.rules:
                    if res.changed or fw.rule_installed(name, exe):
                        rules.append({"name": name, "program": exe})
            data = state.load()
            data["firewall"] = {
                "rules": rules,
                "applied_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "platform": platform_name(),
            }
            state.save(data)
    elif not fw.is_supported() and not opts.quiet:
        c.note(
            "Firewall layer: skipped ({} has no supported per-program outbound block; the "
            "hosts sinkhole is the mechanism here).".format(platform_name())
        )

    # -------------------------------------------------------------------- dns
    if opts.flush_dns:
        c.head("DNS cache")
        for label, okay, note in flush_dns():
            (c.ok if okay else c.note)("{} {}".format(label, ("- " + note) if note else ""))

    # ---------------------------------------------------------------- verify
    c.head("Verifying")
    missing = hosts.unresolved_expected(plan.hostnames)
    if missing:
        c.warn("{} hostname(s) are not in the block (first: {})".format(len(missing), missing[0]))
    else:
        c.ok("All {} hostnames are sinkholed in {}".format(len(plan.hostnames), hosts.path))
    if hosts.path != default_hosts_path():
        c.note("Resolver check skipped: this is a custom hosts file the OS does not consult.")
    else:
        for name in plan.hostnames[:3]:
            state_of = hosts.resolves_to_sinkhole(name)
            if state_of is True:
                c.ok("{} resolves to a sinkhole".format(name))
            elif state_of is False:
                c.warn("{} still resolves normally - flush the cache or reboot".format(name))
            else:
                c.note("{} - could not check right now".format(name))

    _log(opts, "enable: {} hostnames blocked in {}".format(len(plan.hostnames), hosts.path))

    c.head("Done")
    c.info("Jamf traffic to those {} hostnames is now blocked on this computer.".format(len(plan.hostnames)))
    undo = "jamfdisabler off"
    c.info("Undo at any time with:  {}".format(c.BOLD + undo + c.RESET if c.use_color() else undo))
    c.note("Nothing was deleted: profiles, the Jamf agent and all other hosts entries are untouched.")
    c.note("Status any time: jamfdisabler status   -   Docs: {}".format(PROJECT_URL))
    return 0


# --------------------------------------------------------------------------- #
# disable
# --------------------------------------------------------------------------- #
def disable(opts: Options, restore_backup: bool = False) -> int:
    state = opts.state()
    hosts = opts.hosts()
    data = state.load()
    hosts_state = state.hosts_state()

    c.head("Undo plan")
    c.field("State directory", state.dir)
    c.field("Hosts file", hosts.path)
    rules = state.firewall_rules()
    c.field("Firewall rules to delete", str(len(rules)))

    if not state.exists():
        c.note("No state file found, so there is no record of a previous install.")
        try:
            present = hosts.has_block(hosts.read_bytes().decode("utf-8", "replace"))
        except HostsError as exc:
            c.fail(str(exc))
            return 1
        if not present:
            c.ok("Nothing to undo - no JamfDisabler block is present.")
            return 0
        c.warn("A JamfDisabler block IS present but its state file is missing.")
        c.info("The block can still be removed safely (only our marked lines are touched).")

    if opts.dry_run:
        c.head("Dry run - nothing changed")
        c.info("Would remove the JamfDisabler block from {}".format(hosts.path))
        for rule in rules:
            c.bullet("Would delete firewall rule {}".format(rule.get("name")))
        return 0

    if not opts.assume_yes and not c.confirm(
        "Remove the block and restore the original hosts file?", default=True, assume_yes=opts.assume_yes
    ):
        c.info("Nothing was changed.")
        return 0

    # ------------------------------------------------------------------ hosts
    c.head("Restoring hosts file")
    try:
        result = hosts.revert(
            expected_extra=hosts_state.get("hostnames", []),
            separator_text=hosts_state.get("separator_text", ""),
            restore_exact=True,
        )
    except HostsError as exc:
        c.fail(str(exc))
        c.note("Tip: `jamfdisabler restore-backup` writes your pristine copy back verbatim.")
        return 1

    if result.already_done:
        c.ok("No JamfDisabler block was present - hosts file left untouched.")
    else:
        c.ok("Removed {} line(s) of our block from {}".format(result.lines_removed, hosts.path))
    if result.preserved_lines:
        c.warn("Kept {} line(s) inside the block that JamfDisabler did not write.".format(len(result.preserved_lines)))
    if result.truncated_block:
        c.warn("The end marker was missing; the damaged block was repaired instead of left behind.")

    # ---------------------------------------------------- byte-exact restore?
    backup = state.read_backup()
    exact = False
    if backup is not None:
        try:
            current = hosts.read_bytes()
        except HostsError as exc:
            c.fail(str(exc))
            return 1
        exact = current == backup
        if not exact and not (restore_backup or opts.force):
            # If the only difference is trailing newlines, the backup still *is*
            # the original file: put it back verbatim instead of reporting a
            # needless merge.
            try:
                cur_text = current.decode(hosts_state.get("encoding", "utf-8") or "utf-8", errors="strict")
                bak_text = backup.decode(hosts_state.get("encoding", "utf-8") or "utf-8", errors="strict")
            except (UnicodeDecodeError, LookupError):
                cur_text = current.decode("latin-1")
                bak_text = backup.decode("latin-1")
            if cur_text.rstrip("\r\n") == bak_text.rstrip("\r\n"):
                try:
                    hosts.restore_bytes(backup)
                    exact = True
                    c.ok("Whitespace at the end of the file adjusted to match the original exactly.")
                except HostsError as exc:
                    c.warn(str(exc))
        if exact:
            c.ok("Hosts file is byte-for-byte identical to the original ({} bytes).".format(len(backup)))
        elif restore_backup or opts.force:
            try:
                hosts.restore_bytes(backup)
            except HostsError as exc:
                c.fail(str(exc))
                return 1
            c.ok("Restored the pristine backup verbatim ({} bytes).".format(len(backup)))
            exact = True
        else:
            c.warn("The hosts file was edited by something else while JamfDisabler was active.")
            c.info("Kept those newer changes and only removed our own lines (safe merge).")
            c.note("Want the original file back exactly? Re-run with --restore-backup (overwrites those edits).")

    # --------------------------------------------------------------- firewall
    if rules:
        c.head("Removing firewall rules")
        fw_result = fw.unblock([str(r.get("name", "")) for r in rules])
        for message in fw_result.messages:
            c.note(message)
        if fw_result.changed:
            c.ok("Deleted {} rule(s).".format(fw_result.changed))
        else:
            c.ok("No rules left to delete.")
    elif fw.is_supported():
        c.note("No JamfDisabler firewall rules were recorded.")

    if opts.flush_dns:
        c.head("DNS cache")
        for label, okay, note in flush_dns():
            (c.ok if okay else c.note)("{} {}".format(label, ("- " + note) if note else ""))

    data["enabled"] = False
    data["last_disabled_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    data.pop("hosts", None)
    data.pop("firewall", None)
    try:
        state.save(data)
    except StateError as exc:
        c.warn(str(exc))

    _log(opts, "disable: block removed from {}".format(hosts.path))

    c.head("Done")
    c.info("The block is off. Jamf traffic is no longer redirected on this computer.")
    c.note("Your original hosts file was kept at {}".format(state.backup_path))
    c.note("Nothing was deleted; the Jamf agent, profiles and settings are exactly as they were.")
    return 0


def restore_backup_only(opts: Options) -> int:
    """Write the pristine backup back, verbatim (explicit user request)."""
    state = opts.state()
    hosts = opts.hosts()
    backup = state.read_backup()
    if backup is None:
        c.fail("No backup found in {} - nothing to restore.".format(state.dir))
        return 1
    c.head("Restore pristine hosts file")
    c.field("Backup", state.backup_path)
    c.field("Size", "{} bytes".format(len(backup)))
    c.field("sha256", sha256_hex(backup)[:16] + "...")
    if opts.dry_run:
        c.note("Dry run - nothing written.")
        return 0
    if not opts.assume_yes and not c.confirm("Overwrite {} with this backup?".format(hosts.path), default=False):
        c.info("Nothing was changed.")
        return 0
    try:
        hosts.restore_bytes(backup)
    except HostsError as exc:
        c.fail(str(exc))
        return 1
    c.ok("{} restored from backup.".format(hosts.path))
    return 0


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #
def status(opts: Options) -> int:
    import json

    state = opts.state()
    hosts = opts.hosts()
    state.load()
    hosts_state = state.hosts_state()
    rules = state.firewall_rules()

    try:
        summary = hosts.summary()
        read_error = ""
    except HostsError as exc:
        summary = {}
        read_error = str(exc)

    recorded = set(hosts_state.get("hostnames", []))
    present_block = bool(summary.get("explicit_block"))
    blocked = set(summary.get("blocked_hostnames", []))
    missing = sorted(recorded - blocked) if present_block and recorded else []
    rule_state: List[str] = []
    if fw.is_supported() and rules:
        _any, present = fw.status([str(r.get("name", "")) for r in rules])
        rule_state = present

    if present_block and (not recorded or not missing):
        overall = "on"
    elif present_block:
        overall = "partial"
    elif hosts_state.get("sha256_before") and not present_block:
        overall = "off"
    else:
        overall = "off"

    if opts.json_out:
        payload = {
            "tool": APP_NAME,
            "version": __version__,
            "enabled": overall == "on",
            "state": overall,
            "hosts": {
                "path": summary.get("path", hosts.path),
                "block_present": present_block,
                "blocked_count": summary.get("blocked_count", 0),
                "recorded_count": len(recorded),
                "missing_from_block": missing,
                "is_symlink": summary.get("is_symlink", False),
                "sha256_before": hosts_state.get("sha256_before"),
                "sha256_after": hosts_state.get("sha256_after"),
                "applied_at": hosts_state.get("applied_at"),
            },
            "firewall": {
                "supported": fw.is_supported(),
                "recorded_rules": len(rules),
                "present_rules": len(rule_state),
            },
            "state_dir": state.dir,
            "manifest_present": state.exists(),
            "error": read_error,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    c.head("JamfDisabler status")
    if read_error:
        c.fail(read_error)
        return 1
    if overall == "on":
        c.ok("State: BLOCKING ({})".format("{} entries active".format(summary.get("blocked_count", 0))))
    elif overall == "partial":
        c.warn("State: PARTIAL ({} of {} expected entries missing)".format(len(missing), len(recorded)))
    else:
        c.info("State: OFF (no JamfDisabler block in the hosts file)")

    c.out()
    c.field("Hosts file", str(summary.get("path")))
    if summary.get("is_symlink"):
        c.field("  symlink target", str(summary.get("real_path")))
    c.field("Block present", "yes" if present_block else "no")
    c.field("Entries in block", str(summary.get("blocked_count", 0)))
    c.field("Recorded entries", str(len(recorded)))
    if hosts_state.get("applied_at"):
        c.field("Applied at", str(hosts_state.get("applied_at")))
    if hosts_state.get("hostnames"):
        c.field("Own Jamf server", ", ".join(hosts_state.get("dynamic_hostnames", [])) or "-")
        c.note("Blocked hostnames are listed with: jamfdisabler list --blocked")
    c.out()
    c.field("Firewall rules", "{} recorded, {} present".format(len(rules), len(rule_state)))
    if not fw.is_supported():
        c.note("Per-program outbound firewall rules are Windows-only; hosts sinkhole is used here.")
    c.field("State directory", state.dir)
    c.field("Backup", state.backup_path if os.path.exists(state.backup_path) else "none")
    c.field("Administrator", "yes" if is_admin() else "no")
    if missing:
        c.out()
        c.warn("Missing from the block (first 5): {}".format(", ".join(missing[:5])))

    if opts.verify_dns:
        c.head("Resolver check")
        if hosts.path != default_hosts_path():
            c.note("Skipped: {} is not the hosts file this OS consults.".format(hosts.path))
            return 0
        names = sorted(recorded)[:8] or sorted(blocked)[:8]
        if not names:
            c.note("Nothing blocked, so nothing to check.")
        for name in names:
            state_of = hosts.resolves_to_sinkhole(name)
            if state_of is True:
                c.ok("{} -> sinkhole".format(name))
            elif state_of is False:
                c.warn("{} still resolves normally".format(name))
            else:
                c.note("{} - unknown".format(name))
    return 0


# --------------------------------------------------------------------------- #
# list / scan
# --------------------------------------------------------------------------- #
def list_hostnames(opts: Options, blocked_only: bool = False) -> int:
    hosts = opts.hosts()
    if blocked_only:
        try:
            names = hosts.blocked_hostnames(hosts.read_bytes().decode("utf-8", "replace"))
        except HostsError as exc:
            c.fail(str(exc))
            return 1
        c.head("Hostnames currently blocked in {}".format(hosts.path))
        if not names:
            c.note("None - the block is off.")
        for name in names:
            c.bullet(name)
        c.out()
        c.info("{} hostname(s)".format(len(names)))
        return 0

    plan = resolve_hostnames(opts)
    c.head("Hostnames JamfDisabler can block")
    for title, group in catalogue_groups():
        if not opts.include_products and "Other Jamf products" in title:
            continue
        if not opts.include_optional and "Optional" in title:
            continue
        c.out()
        c.info(c.BOLD + title + c.RESET if c.use_color() else title)
        for name in group:
            c.bullet(name)
    if plan.detected:
        c.out()
        c.info("Detected on this machine:")
        for item in plan.detected:
            c.bullet("{}  (from {})".format(item.host, item.source))
    if plan.extra:
        c.out()
        c.info("Your extra hostnames:")
        for name in plan.extra:
            c.bullet(name)
    c.out()
    c.info("{} hostname(s) would be blocked with the current options.".format(len(plan.hostnames)))
    c.note("Optional download/update endpoints are included only with --include-optional.")
    return 0


def scan(opts: Options) -> int:
    """Read-only report: what is Jamf doing on this machine right now?"""
    c.head("Read-only scan (nothing is changed)")
    pinfo = python_info()
    c.field("OS", platform_name())
    c.field("Hostname", pinfo["hostname"])
    c.field("Admin rights", pinfo["admin"])
    runtime = "frozen build" if pinfo["frozen"] == "yes" else pinfo["executable"]
    c.field("Python", "{} ({})".format(pinfo["python"], runtime))
    c.field("MDM/profile present", "yes" if is_managed_device() else "not detected")

    c.head("Jamf components found")
    paths = find_jamf_paths()
    if not paths:
        c.info("No Jamf files or applications found on this machine.")
    for path in paths:
        c.bullet(path)

    exes = find_jamf_executables()
    if exes:
        c.out()
        c.info("Executables (candidates for firewall rules):")
        for exe in exes:
            c.bullet(exe)

    c.head("Jamf server this machine talks to")
    detected = detect_jamf_server(deep=True)
    if not detected:
        c.info("Not detected from Jamf's own config files.")
        c.note("You can still block by hostname: pass --add-host yourorg.jamfcloud.com")
    for item in detected:
        (c.ok if item.tier == 1 else c.info)("{}".format(item.host))
        c.note("   from {}{}".format(item.source, "" if item.trusted else "  [scanned]"))
    if detected:
        _print_privacy_note()

    c.head("Running Jamf processes")
    procs = jamf_processes()
    if not procs:
        c.info("None right now.")
    for proc in procs:
        c.bullet(proc[:120])

    c.head("Network activity (best effort)")
    c.note("JamfDisabler does not install a packet sniffer. Use your OS tools if you want a live view:")
    if platform_name() == "macos":
        c.bullet("sudo lsof -i -P | grep -i jamf")
        c.bullet("sudo port list  # or: sudo lsof -iTCP@<server>:443")
    elif platform_name() == "windows":
        c.bullet("netstat -ano | findstr ESTABLISHED")
        c.bullet("Get-NetTCPConnection -RemotePort 443 (PowerShell)")
    else:
        c.bullet("ss -tnp | grep -i jamf")

    c.out()
    c.info("Nothing was changed by this scan.")
    return 0


def firewall_only(opts: Options, turn_on: bool) -> int:
    """Manipulate just the Windows firewall layer."""
    if not fw.is_supported():
        c.warn("Per-program outbound firewall rules are only implemented on Windows.")
        c.info("On macOS/Linux the hosts sinkhole is the only layer; use `jamfdisabler on`.")
        return 0
    state = opts.state()
    if turn_on:
        exes = find_jamf_executables()
        if not exes:
            c.warn("No Jamf executables found - nothing to block.")
            return 1
        c.head("Adding outbound firewall rules")
        accepted = []
        for exe in exes:
            res = fw.block_program(exe, dry_run=opts.dry_run)
            for message in res.messages:
                (c.ok if res.changed else c.note)(message)
            for name in res.rules:
                accepted.append({"name": name, "program": exe})
        data = state.load()
        existing = {r.get("name") for r in state.firewall_rules()}
        merged = state.firewall_rules() + [r for r in accepted if r["name"] not in existing]
        data["firewall"] = {"rules": merged, "applied_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        state.save(data)
        c.ok("{} rule(s) recorded for later removal.".format(len(merged)))
    else:
        rules = state.firewall_rules()
        if not rules:
            c.ok("No JamfDisabler firewall rules recorded.")
            return 0
        c.head("Removing firewall rules")
        res = fw.unblock([str(r.get("name", "")) for r in rules], dry_run=opts.dry_run)
        for message in res.messages:
            c.note(message)
        c.ok("Deleted {} rule(s).".format(res.changed))
        data = state.load()
        data.pop("firewall", None)
        state.save(data)
    return 0
