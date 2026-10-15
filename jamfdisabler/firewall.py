"""Optional Windows outbound firewall rules (one extra layer, Windows only).

Why Windows only?
-----------------
``netsh advfirewall`` lets an administrator block *outbound* traffic for one
specific program with a named rule that we can find again and delete.  macOS and
Linux have no equivalent command-line facility for blocking outbound traffic per
application (packet filters like pf would need kernel-level redirects, and
``socketfilterfw --blockapp`` only affects incoming connections), so on those
systems JamfDisabler uses the hosts sinkhole only.

Every rule this module creates:

* is **named** with the ``JamfDisabler`` prefix (visible in wf.msc),
* is **outbound only** and applies to **one program**, so it can never affect
  other applications or incoming/remote traffic,
* is recorded in the state manifest and **deleted** by ``jamfdisabler off``.

If ``netsh`` is unavailable or the user is not an administrator, the functions
return a clear error instead of failing hard: the hosts layer still works.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from . import APP_NAME
from .sysinfo import is_admin, run

RULE_PREFIX = "{}-BLOCK".format(APP_NAME)

_NETSH_BLOCK = ["netsh", "advfirewall", "firewall", "add", "rule"]
_NETSH_DELETE = ["netsh", "advfirewall", "firewall", "delete", "rule"]


class FirewallError(Exception):
    pass


@dataclass
class FirewallResult:
    supported: bool = False
    changed: int = 0
    rules: List[str] = field(default_factory=list)
    messages: List[str] = field(default_factory=list)
    dry_run: bool = False


def is_supported() -> bool:
    """Outbound per-program blocking is only implemented on Windows."""
    return os.name == "nt"


def rule_name_for(program: str) -> str:
    digest = hashlib.sha256(os.path.normcase(program).encode("utf-8", "ignore")).hexdigest()[:8]
    base = os.path.basename(program) or "program"
    return "{}-{}-{}".format(RULE_PREFIX, base, digest)


def _run_netsh(args: Sequence[str]) -> "tuple[int, str]":
    rc, out, err = run(["netsh"] + list(args))
    text = (out or "") + (err or "")
    return rc, text


def list_our_rules() -> List[str]:
    """Names of rules we own, as seen by the firewall itself."""
    if not is_supported():
        return []
    rc, text = _run_netsh(["advfirewall", "firewall", "show", "rule", "name=all", "dir=out"])
    if rc != 0:
        return []
    names = []
    for line in text.splitlines():
        if RULE_PREFIX in line:
            match = re.search(r"{}\s+[^\r\n]*".format(re.escape(RULE_PREFIX)), line)
            if match:
                names.append(match.group(0).strip())
    return sorted(set(names))


def rule_installed(name: str, program: Optional[str] = None) -> bool:
    """Check a single rule by name (and, when given, by program path)."""
    if not is_supported():
        return False
    rc, text = _run_netsh(["advfirewall", "firewall", "show", "rule", "name={}".format(name), "dir=out"])
    if rc != 0:
        return False
    if program is None:
        return RULE_PREFIX in text
    # The program path is locale-independent, so it makes a robust check.
    return os.path.normcase(program) in os.path.normcase(text)


def block_program(program: str, dry_run: bool = False) -> FirewallResult:
    """Create one outbound-block rule for ``program``."""
    result = FirewallResult(supported=is_supported())
    if not result.supported:
        result.messages.append("Outbound firewall rules are only available on Windows.")
        return result
    if not os.path.isfile(program):
        result.messages.append("Skipped (not a file): {}".format(program))
        return result

    name = rule_name_for(program)
    result.rules.append(name)
    if rule_installed(name, program):
        result.messages.append("Already blocked: {}".format(program))
        return result
    if dry_run:
        result.dry_run = True
        result.changed += 1
        result.messages.append("Would block outbound traffic for {}".format(program))
        return result

    rc, text = _run_netsh(
        _NETSH_BLOCK
        + [
            "name={}".format(name),
            "dir=out",
            "action=block",
            "program={}".format(program),
            "enable=yes",
            "profile=any",
            "protocol=any",
            "description={}-managed-outbound-block-deleted-by-jamfdisabler-off".format(APP_NAME),
        ]
    )
    if rc == 0:
        result.changed += 1
        result.messages.append("Blocked outbound connections for {}".format(program))
    else:
        result.messages.append("netsh failed for {}: {}".format(program, text.strip()[:200]))
    return result


def unblock(rule_names: Sequence[str], dry_run: bool = False) -> FirewallResult:
    """Delete exactly the named rules (never a wildcard sweep)."""
    result = FirewallResult(supported=is_supported())
    if not result.supported:
        result.messages.append("Outbound firewall rules are only available on Windows.")
        return result
    for name in rule_names:
        if not name.startswith(RULE_PREFIX):
            # Refuse to touch rules we cannot prove are ours.
            result.messages.append("Refusing to delete non-JamfDisabler rule: {}".format(name))
            continue
        if dry_run:
            result.dry_run = True
            result.changed += 1
            continue
        rc, text = _run_netsh(_NETSH_DELETE + ["name={}".format(name), "dir=out"])
        if rc == 0:
            result.changed += 1
        else:
            result.messages.append("Could not delete {}: {}".format(name, text.strip()[:160]))
    return result


def status(rule_names: Sequence[str]) -> "tuple[bool, List[str]]":
    """Return ``(any_rule_present, present_rule_names)``."""
    present = [name for name in rule_names if rule_installed(name)]
    return bool(present), present


def admin_ok() -> bool:
    return is_admin()
