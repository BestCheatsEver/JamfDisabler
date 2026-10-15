"""Command line interface: ``jamfdisabler <command> [options]``.

Run with no arguments on a desktop (or double-click the built executable) and
you get a small menu; every menu entry is also a command for scripting:

    jamfdisabler on          turn the block on
    jamfdisabler off         turn it off and restore your hosts file
    jamfdisabler status      is it on? what is blocked?
    jamfdisabler scan        read-only: what Jamf software is on this machine?
    jamfdisabler list        the hostnames that can be blocked
    jamfdisabler firewall on|off|status
    jamfdisabler restore-backup
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional, Sequence

from . import APP_NAME, PROJECT_URL, __version__, elevate, ops
from . import console as c
from . import firewall as fw
from .hosts import HostsError, default_hosts_path
from .sysinfo import is_admin, platform_name

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NEEDS_ADMIN = 2
EXIT_ABORTED = 3

EPILOG = """\
examples:
  jamfdisabler on                     block Jamf endpoints (asks for admin if needed)
  jamfdisabler on --dry-run           show exactly what would change, change nothing
  jamfdisabler on --no-firewall       hosts file only (skip Windows firewall rules)
  jamfdisabler off                    undo everything, restore the original hosts file
  jamfdisabler status --verify-dns    check the resolver actually sinkholes the names
  jamfdisabler scan                   read-only report of the Jamf footprint
  jamfdisabler list                   every hostname the tool can block

safety:
  Nothing is ever deleted. Configuration profiles, the Jamf agent and all other
  hosts entries are left exactly as they were. `jamfdisabler off` restores the
  original hosts file byte-for-byte.

docs: {url}
""".format(url=PROJECT_URL)


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def _common_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    group = parser.add_argument_group("common options")
    group.add_argument("--hosts-file", metavar="PATH", default=None, help="use a different hosts file (testing)")
    group.add_argument("--state-dir", metavar="PATH", default=None, help="where to keep the backup/manifest")
    group.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    group.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    group.add_argument("--no-flush-dns", action="store_true", help="skip flushing the DNS cache")
    group.add_argument(
        "--no-elevate",
        action="store_true",
        help="never ask for administrator rights; just try and report errors",
    )
    group.add_argument("--log-file", metavar="PATH", default=None, help=argparse.SUPPRESS)
    group.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    group.add_argument("--pause", action="store_true", help="wait for Enter before exiting")
    group.add_argument("--no-pause", action="store_true", help="never wait for Enter")
    color = parser.add_mutually_exclusive_group()
    color.add_argument("--color", dest="color", action="store_true", default=None, help="force coloured output")
    color.add_argument("--no-color", dest="color", action="store_false", default=None, help="disable coloured output")
    return parser


def _block_selection(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("what to block")
    group.add_argument("--include-optional", action="store_true", help="also block download/update/marketing endpoints")
    group.add_argument("--no-products", action="store_true", help="only core Jamf Pro endpoints, no other products")
    group.add_argument(
        "--add-host", metavar="HOST", action="append", default=[], help="block an extra hostname (repeatable)"
    )
    group.add_argument("--no-auto-server", action="store_true", help="do not auto-detect this machine's Jamf server")
    group.add_argument(
        "--all-detected", action="store_true", help="also block secondary endpoints found in Jamf's config"
    )
    group.add_argument("--deep-scan", action="store_true", help="scan more Jamf files for hostnames (slower)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME.lower(),
        description="{} {} - reversible, non-destructive Jamf network blocker.".format(APP_NAME, __version__),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", "-V", action="version", version="{} {}".format(APP_NAME, __version__))
    common = _common_parser()
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_on = sub.add_parser(
        "on",
        parents=[common],
        aliases=["enable", "start"],
        help="turn the block on (sinkhole Jamf hostnames)",
        description=(
            "Turn the block on: redirect Jamf hostnames to 0.0.0.0/:: and, on Windows, add outbound firewall rules."
        ),
    )
    _block_selection(p_on)
    p_on.add_argument(
        "--no-firewall",
        "--hosts-only",
        dest="no_firewall",
        action="store_true",
        help="only change the hosts file",
    )

    p_off = sub.add_parser(
        "off",
        parents=[common],
        aliases=["disable", "stop", "undo"],
        help="turn the block off and restore the original hosts file",
        description="Turn the block off: remove our lines from the hosts file and delete our firewall rules.",
    )
    p_off.add_argument(
        "--restore-backup",
        action="store_true",
        help="overwrite the hosts file with the pristine backup (discards edits made while blocked)",
    )

    p_status = sub.add_parser(
        "status",
        parents=[common],
        aliases=["st"],
        help="show whether the block is active",
        description="Show the current state, the number of blocked hostnames and the recorded firewall rules.",
    )
    p_status.add_argument("--verify-dns", action="store_true", help="ask the resolver where the names point now")
    p_status.add_argument("--json", dest="json_out", action="store_true", help="machine-readable output")

    p_list = sub.add_parser(
        "list",
        parents=[common],
        help="list the hostnames that can be blocked",
        description="List the built-in Jamf endpoint catalogue plus anything detected on this machine.",
    )
    p_list.add_argument("--blocked", action="store_true", help="only show what is currently in the block")
    _block_selection(p_list)

    p_scan = sub.add_parser(
        "scan",
        parents=[common],
        help="read-only report of the Jamf footprint on this machine",
        description="Look (without changing anything) for Jamf files, processes and server hostnames.",
    )
    p_scan.add_argument("--quick", action="store_true", help="skip the deeper config-file scan")

    p_fw = sub.add_parser(
        "firewall",
        parents=[common],
        help="manage the Windows outbound firewall rules only",
        description="Add or delete the outbound block rules for Jamf programs (Windows only).",
    )
    p_fw.add_argument("action", choices=["on", "off", "status"], nargs="?", default="status")

    sub.add_parser(
        "restore-backup",
        parents=[common],
        help="write the pristine hosts backup back, verbatim",
        description="Overwrite the hosts file with the copy taken before the first change. Asks first.",
    )

    sub.add_parser(
        "help",
        parents=[common],
        help="show this help text",
        description="Show the help text.",
    )

    sub.add_parser(
        "menu",
        parents=[common],
        help="interactive menu (default when run with no arguments)",
        description="Show the interactive menu.",
    )
    return parser


def options_from_args(args: argparse.Namespace) -> ops.Options:
    return ops.Options(
        no_elevate=getattr(args, "no_elevate", False),
        hosts_path=getattr(args, "hosts_file", None),
        state_dir=getattr(args, "state_dir", None),
        include_products=not getattr(args, "no_products", False),
        include_optional=getattr(args, "include_optional", False),
        extra_hosts=list(getattr(args, "add_host", []) or []),
        auto_server=not getattr(args, "no_auto_server", False),
        all_detected=getattr(args, "all_detected", False),
        deep_scan=getattr(args, "deep_scan", False) and not getattr(args, "quick", False),
        firewall=not getattr(args, "no_firewall", False),
        dry_run=getattr(args, "dry_run", False),
        assume_yes=getattr(args, "yes", False),
        quiet=getattr(args, "quiet", False),
        json_out=getattr(args, "json_out", False),
        verify_dns=getattr(args, "verify_dns", False),
        flush_dns=not getattr(args, "no_flush_dns", False),
    )


# --------------------------------------------------------------------------- #
# Elevation
# --------------------------------------------------------------------------- #
def command_needs_admin(command: Optional[str], args: argparse.Namespace) -> bool:
    if command in ("on", "enable", "start", "off", "disable", "stop", "undo", "restore-backup"):
        return True
    if command == "firewall":
        return getattr(args, "action", "status") in ("on", "off")
    return False


def handle_elevation(args: argparse.Namespace, argv: Sequence[str]) -> Optional[int]:
    """Return an exit code when the work was delegated, else ``None``."""
    if not command_needs_admin(args.command, args):
        return None
    if args.dry_run or is_admin() or getattr(args, "elevated", False):
        return None
    if getattr(args, "no_elevate", False) or os.environ.get("JAMFDISABLER_NO_ELEVATE"):
        c.note("--no-elevate: attempting the change without asking for administrator rights.")
        return None

    c.head("Administrator rights")
    c.info("Changing {} needs administrator rights.".format(default_hosts_path()))
    if not args.yes and not c.confirm("Ask the system for administrator rights now?", default=True):
        c.info("Nothing was changed.")
        return EXIT_ABORTED

    log_file = None
    if platform_name() == "windows":
        log_file = elevate.temp_log_file()
    try:
        code = elevate.relaunch_elevated(list(argv), log_file=log_file)
    except elevate.ElevationUnavailable as exc:
        c.fail(str(exc))
        elevate.manual_instructions()
        return EXIT_NEEDS_ADMIN

    if log_file and os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as fh:
                c.raw(fh.read().rstrip("\n"))
        except OSError:
            pass
        try:
            os.remove(log_file)
        except OSError:
            pass
    return code


# --------------------------------------------------------------------------- #
# Interactive menu
# --------------------------------------------------------------------------- #
MENU = """
  1) Turn the block ON       block Jamf endpoints on this computer
  2) Turn the block OFF      restore your original hosts file
  3) Status                  is the block active right now?
  4) Scan this computer      read-only: what Jamf software is present
  5) Show blocked names      the hostnames currently in the block
  6) Document / help
  q) Quit
"""


def interactive_menu(argv: Sequence[str]) -> int:
    c.banner("reversible, non-destructive Jamf network blocker")
    c.info("Platform: {}   Administrator: {}".format(platform_name(), "yes" if is_admin() else "no"))
    c.note("Nothing is deleted; `off` restores your hosts file exactly.")
    code = EXIT_OK
    while True:
        c.raw(MENU)
        choice = c.choose("Choose [1-6, q]:", list("123456q"))
        if choice is None:
            return code
        if choice == "q":
            return code
        if choice == "1":
            code = dispatch("on", _default_args(argv), argv) or code
        elif choice == "2":
            code = dispatch("off", _default_args(argv), argv) or code
        elif choice == "3":
            dispatch("status", _default_args(argv), argv)
        elif choice == "4":
            dispatch("scan", _default_args(argv), argv)
        elif choice == "5":
            dispatch("list", _default_args(argv + ["--blocked"]), argv)
        elif choice == "6":
            c.raw(EPILOG)


def _default_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse ``argv`` with the default command so menu actions can reuse flags."""
    parser = build_parser()
    if not argv:
        argv = ["menu"]
    try:
        return parser.parse_args(list(argv))
    except SystemExit:
        return parser.parse_args(["menu"])


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
def dispatch(command: Optional[str], args: argparse.Namespace, argv: Sequence[str]) -> int:
    opts = options_from_args(args)
    if command in (None, "menu"):
        return interactive_menu(argv)

    elevated = handle_elevation(args, argv)
    if elevated is not None:
        return elevated

    try:
        if command in ("on", "enable", "start"):
            return ops.enable(opts)
        if command in ("off", "disable", "stop", "undo"):
            return ops.disable(opts, restore_backup=getattr(args, "restore_backup", False))
        if command in ("status", "st"):
            return ops.status(opts)
        if command == "list":
            return ops.list_hostnames(opts, blocked_only=getattr(args, "blocked", False))
        if command == "scan":
            return ops.scan(opts)
        if command == "restore-backup":
            return ops.restore_backup_only(opts)
        if command == "firewall":
            action = getattr(args, "action", "status")
            if action == "status":
                rules = opts.state().firewall_rules()
                _installed, present = fw.status([str(r.get("name", "")) for r in rules])
                c.head("Firewall rules (Windows outbound block)")
                if not fw.is_supported():
                    c.note("Per-program outbound rules are Windows-only; this platform uses the hosts sinkhole.")
                    return EXIT_OK
                c.field("Recorded rules", str(len(rules)))
                c.field("Present in firewall", str(len(present)))
                for rule in rules:
                    c.bullet("{}  ->  {}".format(rule.get("name"), rule.get("program")))
                return EXIT_OK
            return ops.firewall_only(opts, turn_on=(action == "on"))
    except KeyboardInterrupt:
        c.out()
        c.warn("Interrupted - no further changes were made.")
        return EXIT_ABORTED
    except HostsError as exc:
        c.fail(str(exc))
        return EXIT_ERROR
    except PermissionError as exc:
        c.fail("Permission denied: {}".format(exc))
        c.note("Re-run with administrator/root rights.")
        return EXIT_NEEDS_ADMIN
    c.fail("Unknown command: {}".format(command))
    return EXIT_ERROR


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    # Freestanding flags can appear before the command: jamfdisabler --version
    if argv and argv[0] in ("-V", "--version"):
        print("{} {}".format(APP_NAME, __version__))
        return EXIT_OK
    # `jamfdisabler --no-color` (flags but no command) means "menu with flags"
    if argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help"):
        argv = ["menu"] + argv
    if not argv:
        args = argparse.Namespace(
            command="menu",
            color=None,
            pause=False,
            no_pause=False,
            yes=False,
            dry_run=False,
            elevated=False,
            log_file=None,
            hosts_file=None,
            state_dir=None,
            no_flush_dns=False,
        )
    else:
        args = parser.parse_args(argv)

    if getattr(args, "color", None) is False:
        c.set_color(False)
    elif getattr(args, "color", None) is True:
        c.set_color(True)

    if getattr(args, "log_file", None):
        c.set_tee(args.log_file)

    if args.command in ("help", None) and argv:
        parser.print_help()
        return EXIT_OK

    try:
        return dispatch(args.command, args, argv)
    finally:
        c.close_tee()


def entry() -> None:
    """``console_scripts`` entry point."""
    code = main()
    _maybe_pause()
    sys.exit(code)


def _maybe_pause() -> None:
    argv = sys.argv[1:]
    frozen = bool(getattr(sys, "frozen", False))
    should_pause = ("--pause" in argv) or (frozen and "--no-pause" not in argv)
    if should_pause:
        c.pause()


if __name__ == "__main__":  # pragma: no cover
    entry()
