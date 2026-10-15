"""Platform helpers: privilege checks, Jamf footprint discovery, DNS cache.

Everything in here is **read-only**.  JamfDisabler never stops services, never
deletes files and never touches configuration profiles, so this module only
*looks* at the machine in order to report and to pick sensible defaults.
"""

from __future__ import annotations

import glob
import os
import plistlib
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .endpoints import is_jamf_hostname, normalise_hostname

PLATFORM_MACOS = "macos"
PLATFORM_WINDOWS = "windows"
PLATFORM_LINUX = "linux"


# --------------------------------------------------------------------------- #
# Platform / privilege
# --------------------------------------------------------------------------- #
def platform_name() -> str:
    if os.name == "nt":
        return PLATFORM_WINDOWS
    try:
        if os.uname().sysname == "Darwin":  # type: ignore[attr-defined]
            return PLATFORM_MACOS
    except Exception:
        pass
    return PLATFORM_LINUX


def is_windows() -> bool:
    return platform_name() == PLATFORM_WINDOWS


def is_macos() -> bool:
    return platform_name() == PLATFORM_MACOS


def is_linux() -> bool:
    return platform_name() == PLATFORM_LINUX


def is_admin() -> bool:
    """True when we can write the hosts file / firewall rules."""
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def hostname() -> str:
    try:
        import socket

        return socket.gethostname()
    except Exception:
        return "unknown"


def run(args: Sequence[str], timeout: float = 20.0, input_text: Optional[str] = None) -> Tuple[int, str, str]:
    """Run a command quietly.  Never raises; returns ``(rc, stdout, stderr)``."""
    kwargs: Dict[str, object] = {}
    if os.name == "nt":
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            list(args),
            input=input_text,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            **kwargs,
        )
    except FileNotFoundError:
        return 127, "", "not found: {}".format(args[0] if args else "")
    except subprocess.TimeoutExpired:
        return 124, "", "timeout running {}".format(" ".join(args[:2]))
    except OSError as exc:
        return 1, "", str(exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


# --------------------------------------------------------------------------- #
# DNS cache
# --------------------------------------------------------------------------- #
def dns_flush_commands() -> List[List[str]]:
    """Best-effort list of commands that drop the resolver's DNS cache."""
    plat = platform_name()
    if plat == PLATFORM_WINDOWS:
        return [["ipconfig", "/flushdns"]]
    if plat == PLATFORM_MACOS:
        return [
            ["dscacheutil", "-flushcache"],
            ["killall", "-HUP", "mDNSResponder"],
        ]
    return [
        ["resolvectl", "flush-caches"],
        ["systemd-resolve", "--flush-caches"],
        ["nscd", "-i", "hosts"],
    ]


def flush_dns(dry_run: bool = False) -> List[Tuple[str, bool, str]]:
    """Flush the DNS cache, trying the platform's tools in order.

    Only the first tool that works is actually run; the rest are reported as
    skipped.  This is purely a cache operation - nothing persistent.
    """
    results: List[Tuple[str, bool, str]] = []
    flushed = False
    for cmd in dns_flush_commands():
        label = " ".join(cmd)
        if dry_run:
            results.append((label, True, "dry-run (not executed)"))
            continue
        if flushed:
            results.append((label, True, "skipped - cache already flushed"))
            continue
        rc, _out, err = run(cmd)
        if rc == 127:
            results.append((label, False, "not available on this system"))
            continue
        if rc == 0:
            results.append((label, True, ""))
            flushed = True
        else:
            results.append((label, False, err.strip()[:120] or "exit code {}".format(rc)))
    return results


# --------------------------------------------------------------------------- #
# Jamf footprint (read-only inspection)
# --------------------------------------------------------------------------- #
MACOS_JAMF_PATHS: Sequence[str] = (
    "/usr/local/jamf",
    "/usr/local/bin/jamf",
    "/usr/local/jamf/bin/jamf",
    "/Library/Application Support/Jamf",
    "/Library/Preferences/com.jamfsoftware.jamf.plist",
    "/Library/Preferences/com.jamf.management.jamfAIDE.plist",
    "/Library/LaunchDaemons/com.jamfsoftware.task.beta.plist",
    "/Library/LaunchDaemons/com.jamfsoftware.jamf.daemon.plist",
    "/Library/LaunchDaemons/com.jamf.management.daemon.plist",
    "/Library/LaunchAgents/com.jamfsoftware.jamf.agent.plist",
    "/Library/LaunchAgents/com.jamf.management.agent.plist",
    "/Library/Application Support/JamfProtect",
    "/Applications/Self Service.app",
    "/Applications/JamfProtect.app",
    "/Applications/Jamf Connect.app",
    "/var/db/jamf",
)

WINDOWS_JAMF_ROOTS: Sequence[str] = (
    r"C:\Program Files\Jamf",
    r"C:\Program Files (x86)\Jamf",
    r"C:\ProgramData\Jamf",
    r"C:\Program Files\Common Files\Jamf",
    r"C:\ProgramData\Jamf Protect",
)

LINUX_JAMF_ROOTS: Sequence[str] = ("/usr/local/jamf", "/opt/jamf", "/etc/jamf", "/var/jamf")

JAMF_CONFIG_FILES: Sequence[str] = (
    "/Library/Preferences/com.jamfsoftware.jamf.plist",
    "/Library/Managed Preferences/com.jamfsoftware.jamf.plist",
    "/Library/Managed Preferences/com.jamf.management.jamf.plist",
    "/etc/jamf/jamf.conf",
    "/etc/jamf/jamf.plist",
    "/opt/jamf/conf/jamf.conf",
)

_URL_RE = re.compile(r"(https?://[A-Za-z0-9\.\-:_]{1,200})", re.IGNORECASE)
_HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})+\.[a-z]{2,24})\b", re.IGNORECASE)


def jamf_roots() -> List[str]:
    plat = platform_name()
    if plat == PLATFORM_MACOS:
        return list(MACOS_JAMF_PATHS)
    if plat == PLATFORM_WINDOWS:
        return list(WINDOWS_JAMF_ROOTS)
    return list(LINUX_JAMF_ROOTS)


def find_jamf_paths() -> List[str]:
    """Paths that exist and belong to Jamf (files or directories)."""
    found: List[str] = []
    for path in jamf_roots():
        for candidate in glob.glob(path):
            if os.path.exists(candidate):
                found.append(candidate)
    return sorted(set(found))


def find_jamf_executables(extra_names: Sequence[str] = ("jamf", "jamfhelper")) -> List[str]:
    """Executables belonging to Jamf - used for outbound firewall rules."""
    exes: List[str] = []
    plat = platform_name()
    if plat == PLATFORM_WINDOWS:
        for root in WINDOWS_JAMF_ROOTS:
            if not os.path.isdir(root):
                continue
            for dirpath, _dirnames, filenames in os.walk(root):
                for name in filenames:
                    if not name.lower().endswith(".exe"):
                        continue
                    low = name.lower()
                    if "jamf" in low or "protect" in low or "selfservice" in low or "self service" in low:
                        exes.append(os.path.join(dirpath, name))
    else:
        for name in extra_names:
            for base in ("/usr/local/jamf/bin", "/usr/local/bin", "/usr/bin", "/opt/jamf/bin"):
                candidate = os.path.join(base, name)
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    exes.append(candidate)
        for pattern in ("/Applications/JamfProtect.app/Contents/**/protect",):
            exes.extend(p for p in glob.glob(pattern, recursive=True) if os.path.isfile(p))
    return sorted(set(exes))


def jamf_processes() -> List[str]:
    """Currently running processes whose command line mentions Jamf."""
    lines: List[str] = []
    if platform_name() == PLATFORM_WINDOWS:
        rc, out, _ = run(["tasklist", "/fo", "csv", "/nh"])
        if rc != 0:
            return []
        for row in out.splitlines():
            cells = [c.strip('"') for c in row.split('","')]
            if cells and any(k in cells[0].lower() for k in ("jamf", "protect", "selfservice")):
                lines.append(cells[0])
    else:
        rc, out, _ = run(["ps", "-Ao", "comm=,args="])
        if rc != 0:
            rc, out, _ = run(["ps", "aux"])
        for row in out.splitlines():
            low = row.lower()
            if ("jamf" in low or "self service" in low or "jamfprotect" in low) and "grep" not in low:
                lines.append(row.strip()[:160])
    return sorted(set(lines))


@dataclass
class DetectedServer:
    """A Jamf server hostname found on this machine.

    ``tier`` 1 means "this is the management server Jamf's agent calls" and is
    blocked by default.  ``tier`` 2 means "some other Jamf endpoint mentioned in
    a config file" and is blocked only when the user opts in.
    """

    host: str
    source: str
    tier: int = 1
    trusted: bool = False


#: Domains we will never auto-block, even if a Jamf config file mentions them.
_NEVER_BLOCK = (
    "apple.com",
    "icloud.com",
    "microsoft.com",
    "windowsupdate.com",
    "google.com",
    "amazonaws.com",
    "akamai.net",
    "localhost",
)


def is_third_party_infrastructure(host: str) -> bool:
    """True for hosts we must never block (Apple/OS/cloud infrastructure)."""
    host = normalise_hostname(host)
    return any(host == d or host.endswith("." + d) for d in _NEVER_BLOCK)


def looks_like_ip_literal(host: str) -> bool:
    """True for bare IPv4/IPv6 literals, which never belong in a hosts block."""
    host = (host or "").strip()
    return bool(re.fullmatch(r"[0-9a-fA-F:.]+", host) and ("." in host or ":" in host))


def _looks_like_jamf_url(value: str) -> bool:
    host = normalise_hostname(value)
    return bool(host) and is_jamf_hostname(host)


def _tier_for_key(key_path: str) -> int:
    low = key_path.lower()
    if any(tag in low for tag in ("jss", "server", "mdm", "management", "enroll")):
        return 1
    return 2


def _detect_from_plist(path: str) -> List[DetectedServer]:
    """Read Jamf's own preference file (read-only) for its server URL."""
    results: List[DetectedServer] = []
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        return results

    def walk(obj: object, key_path: str = "") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                walk(value, "{}.{}".format(key_path, key) if key_path else str(key))
        elif isinstance(obj, (list, tuple)):
            for idx, value in enumerate(obj):
                walk(value, "{}[{}]".format(key_path, idx))
        elif isinstance(obj, str):
            low_key = key_path.lower()
            if not any(tag in low_key for tag in ("url", "server", "host", "jss", "endpoint")):
                return
            if "." not in obj:
                return
            host = normalise_hostname(obj)
            if not host or is_third_party_infrastructure(host):
                return
            tier = _tier_for_key(key_path)
            if is_jamf_hostname(host):
                tier = 1
            results.append(DetectedServer(host=host, source="{} ({})".format(path, key_path), tier=tier, trusted=True))

    walk(data)
    return results


def _detect_from_text(path: str, limit_bytes: int = 65536) -> List[DetectedServer]:
    """Regex-scan a config file for Jamf-owned host names."""
    results: List[DetectedServer] = []
    try:
        with open(path, "rb") as fh:
            blob = fh.read(limit_bytes)
    except (OSError, PermissionError):
        return results
    text = blob.decode("utf-8", errors="ignore")
    seen = set()
    for match in list(_URL_RE.finditer(text)) + list(_HOST_RE.finditer(text)):
        host = normalise_hostname(match.group(1))
        if not host or host in seen or not is_jamf_hostname(host):
            continue
        seen.add(host)
        results.append(DetectedServer(host=host, source=path, tier=1, trusted=False))
    return results


def detect_jamf_server(deep: bool = False) -> List[DetectedServer]:
    """Find this machine's *own* Jamf server hostname(s), if discoverable.

    Values read from Jamf's own preference files are reported as ``trusted`` and
    may be on a custom domain (many organisations run their own Jamf Pro
    instance).  Values found by scanning other files must belong to a
    Jamf-owned domain before they are accepted.
    """
    seen: Dict[str, DetectedServer] = {}

    def add(item: DetectedServer) -> None:
        host = normalise_hostname(item.host)
        if not host:
            return
        item.host = host
        existing = seen.get(host)
        if existing is None or item.tier < existing.tier:
            seen[host] = item

    for path in JAMF_CONFIG_FILES:
        for item in _detect_from_plist(path):
            add(item)

    if deep:
        candidates: List[str] = []
        if platform_name() == PLATFORM_MACOS:
            candidates += glob.glob("/Library/Application Support/Jamf/*")
            candidates += glob.glob("/Library/Application Support/Jamf/**/*.plist", recursive=True)
            candidates += glob.glob("/var/db/jamf/*")
        elif platform_name() == PLATFORM_WINDOWS:
            for root in WINDOWS_JAMF_ROOTS:
                candidates += glob.glob(os.path.join(root, "**", "*.plist"), recursive=True)
                candidates += glob.glob(os.path.join(root, "**", "*.conf"), recursive=True)
                candidates += glob.glob(os.path.join(root, "**", "*.json"), recursive=True)
        else:
            candidates += glob.glob("/etc/jamf/**/*", recursive=True)
        for path in candidates:
            if not os.path.isfile(path) or os.path.getsize(path) > 1_000_000:
                continue
            for item in _detect_from_text(path):
                add(item)

    return [seen[h] for h in sorted(seen)]


def is_managed_device() -> bool:
    """Best-effort, read-only guess at whether an MDM is managing this machine."""
    if platform_name() == PLATFORM_MACOS:
        return os.path.isdir("/var/db/ConfigurationProfiles") or os.path.isdir("/Library/Managed Preferences")
    if platform_name() == PLATFORM_WINDOWS:
        try:
            import winreg  # type: ignore

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Enrollments",
            )
            with key:
                count = winreg.QueryInfoKey(key)[0]
                return count > 0
        except Exception:
            return False
    candidates = ("/var/lib/jamf", "/opt/jamf", "/etc/jamf")
    return any(os.path.exists(p) for p in candidates)


def profiles_present() -> List[str]:
    """Names of configuration profiles, *read only*, if they are easily listed.

    JamfDisabler never installs or removes profiles.  This exists purely so
    ``jamfdisabler scan`` can tell the user what is still on the machine (and
    therefore what will keep existing after Jamf is blocked).
    """
    names: List[str] = []
    if platform_name() != PLATFORM_MACOS:
        return names
    rc, out, _err = run(["profiles", "list", "-all"], timeout=25)
    if rc == 0:
        for line in out.splitlines():
            line = line.strip()
            if line.lower().startswith("attribute: name") or "_name" in line.lower():
                names.append(line)
    return names[:40]


def python_info() -> Dict[str, str]:
    return {
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "platform": platform_name(),
        "frozen": "yes" if getattr(sys, "frozen", False) else "no",
        "admin": "yes" if is_admin() else "no",
        "hostname": hostname(),
    }


def human_list(items: Iterable[str], limit: int = 12) -> List[str]:
    items = list(items)
    if len(items) <= limit:
        return items
    return items[:limit] + ["... and {} more".format(len(items) - limit)]
