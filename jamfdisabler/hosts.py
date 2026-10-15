"""Reading, blocking and restoring the system ``hosts`` file.

This module deliberately knows nothing about state files or the CLI: it only
manipulates host-file *text*, which makes every safety guarantee easy to test.

Safety rules implemented here
-----------------------------
1. Only lines between our own BEGIN/END markers are ever removed.
2. Inside that region, only ``<sinkhole-address> <jamf-hostname>`` lines and
   JamfDisabler's own comments are removed.  Anything else is preserved.
3. The original file is byte-for-byte restorable: the CLI keeps the pristine
   bytes *and* records the exact separator text that was inserted.
4. Writes are atomic (temp file + ``os.replace``) and preserve mode/ownership.
"""

from __future__ import annotations

import os
import socket
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import APP_NAME, HOSTS_BLOCK_VERSION
from .endpoints import BLOCK_IPV4, BLOCK_IPV6, is_jamf_hostname, normalise_hostname

BEGIN_MARKER = "# >>> {app} block v{v} (managed by {app} - run `jamfdisabler off` to undo) >>>".format(
    app=APP_NAME, v=HOSTS_BLOCK_VERSION
)
END_MARKER = "# <<< {app} block - end <<<".format(app=APP_NAME)

BEGIN_KEY = ">>> {} block".format(APP_NAME)
END_KEY = "<<< {} block".format(APP_NAME)
OWNER_KEY = APP_NAME

#: Opening words of every comment line this tool has ever written inside the
#: block.  Any version's block can therefore be removed cleanly, and a comment
#: the user added is still left alone.
OUR_COMMENT_PREFIXES = (
    "# Added by {}".format(APP_NAME),
    "# {} only redirects".format(APP_NAME),
    "# Nothing is deleted",
    "# These names are only",
)

#: Addresses we accept as "this name goes nowhere".
#: Addresses we accept as "this name goes nowhere".  (S104 is a false
#: positive: these are literal hosts-file addresses, not socket bindings.)
SINKHOLE_ADDRESSES = ("0.0.0.0", "::", "::1", "127.0.0.1", "0", "fe80::1")  # noqa: S104


class HostsError(Exception):
    """Raised for anything that would prevent a safe hosts-file change."""


def default_hosts_path() -> str:
    if os.name == "nt":
        # Windows env var names are case-insensitive; check both spellings.
        root = (
            os.environ.get("SYSTEMROOT")
            or os.environ.get("SystemRoot")  # noqa: SIM112 - Windows spelling
            or "C:\\Windows"
        )
        system32 = "System32"
        # A 32-bit process on 64-bit Windows is redirected to SysWOW64, which is
        # *not* the hosts file the rest of the system uses.  Sysnative is the
        # documented way for such a process to reach the real file.
        if os.environ.get("PROCESSOR_ARCHITEW6432"):
            system32 = "Sysnative"
        return os.path.join(root, system32, "drivers", "etc", "hosts")
    return "/etc/hosts"


def _is_marker(line: str, key: str) -> bool:
    return key in line and line.strip().startswith("#")


@dataclass
class ChangeResult:
    """Outcome of an ``apply``/``revert`` operation."""

    path: str
    changed: bool = False
    already_done: bool = False
    lines_added: int = 0
    lines_removed: int = 0
    entries_added: int = 0
    hostnames: List[str] = field(default_factory=list)
    preserved_lines: List[str] = field(default_factory=list)
    encoding: str = "utf-8"
    eol: str = "\n"
    separator_text: str = ""
    truncated_block: bool = False


@dataclass
class StripResult:
    text: str
    removed: int
    preserved: List[str]
    found: bool
    closed: bool
    separator_removed: bool
    truncated: bool = False


class HostsFile:
    """A hosts file at a given path (defaults to the real system one)."""

    def __init__(self, path: Optional[str] = None):
        self.path = os.path.abspath(path or default_hosts_path())

    # ---------------------------------------------------------------- reading
    @property
    def real_path(self) -> str:
        """The file we actually write to (follows symlinks, e.g. on some distros)."""
        return os.path.realpath(self.path)

    @property
    def is_symlink(self) -> bool:
        try:
            return os.path.islink(self.path) and self.path != self.real_path
        except OSError:
            return False

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def read_bytes(self) -> bytes:
        try:
            with open(self.path, "rb") as fh:
                return fh.read()
        except FileNotFoundError:
            return b""
        except PermissionError as exc:
            raise HostsError(
                "Permission denied reading {}. Administrator/root rights are required "
                "(macOS/Linux: sudo; Windows: run as administrator).".format(self.path)
            ) from exc
        except OSError as exc:
            raise HostsError("Could not read {}: {}".format(self.path, exc)) from exc

    @staticmethod
    def decode(data: bytes) -> Tuple[str, str]:
        for enc in ("utf-8", "utf-8-sig"):
            try:
                return data.decode(enc), enc
            except UnicodeDecodeError:
                continue
        # latin-1 decodes any byte sequence without loss
        return data.decode("latin-1"), "latin-1"

    @staticmethod
    def detect_eol(text: str) -> str:
        lf = text.count("\n")
        crlf = text.count("\r\n")
        if crlf and lf and crlf * 2 >= lf:
            return "\r\n"
        return "\n"

    def load(self) -> Tuple[str, str, str]:
        """Return ``(text, encoding, eol)`` for the current file."""
        data = self.read_bytes()
        text, encoding = self.decode(data)
        return text, encoding, self.detect_eol(text)

    # ------------------------------------------------------------- inspection
    @staticmethod
    def has_block(text: str) -> bool:
        return any(_is_marker(line, BEGIN_KEY) for line in text.splitlines())

    @staticmethod
    def _split(text: str) -> Tuple[List[str], str]:
        """Split into lines *with* their endings, plus any final partial line."""
        if not text:
            return [], ""
        lines = text.splitlines(keepends=True)
        tail = ""
        if lines and not lines[-1].endswith(("\n", "\r")):
            tail = lines.pop()
        return lines, tail

    @staticmethod
    def blocked_hostnames(text: str) -> List[str]:
        """Hostnames mapped to a sinkhole inside our marker region."""
        names: List[str] = []
        inside = False
        for raw in text.splitlines():
            stripped = raw.strip()
            if _is_marker(raw, BEGIN_KEY):
                inside = True
                continue
            if _is_marker(raw, END_KEY):
                inside = False
                continue
            if not inside or not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[0] in SINKHOLE_ADDRESSES:
                names.append(parts[1].lower())
        return sorted(set(names))

    @staticmethod
    def _looks_like_our_entry(line: str, expected: Set[str]) -> bool:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return False
        parts = stripped.split()
        if len(parts) < 2 or parts[0] not in SINKHOLE_ADDRESSES:
            return False
        host = normalise_hostname(parts[1])
        return bool(host) and (host in expected or is_jamf_hostname(host))

    @staticmethod
    def _is_our_comment(line: str) -> bool:
        stripped = line.strip()
        if not stripped.startswith("#"):
            return False
        if OWNER_KEY in stripped:
            return True
        return any(stripped.startswith(prefix) for prefix in OUR_COMMENT_PREFIXES)

    # ------------------------------------------------------------ manipulation
    @staticmethod
    def _render_block(
        hostnames: Sequence[str],
        eol: str,
        ipv4: str = BLOCK_IPV4,
        ipv6: Optional[str] = BLOCK_IPV6,
    ) -> List[str]:
        lines = [BEGIN_MARKER + eol]
        lines.append("# Added by {app}. Fully reversible: run `jamfdisabler off`.".format(app=APP_NAME) + eol)
        lines.append("# Nothing is deleted or un-enrolled - these names are only redirected away from Jamf." + eol)
        for name in hostnames:
            lines.append("{}{}{}".format(ipv4.ljust(9), name, eol))
            if ipv6 is not None:
                lines.append("{}{}{}".format(ipv6.ljust(9), name, eol))
        lines.append(END_MARKER + eol)
        return lines

    def _strip_block(self, text: str, expected: Set[str], separator_text: str = "") -> StripResult:
        """Remove our block (and, if known, the separator we inserted)."""
        if not self.has_block(text):
            return StripResult(text, 0, [], False, True, False, False)

        eol = self.detect_eol(text)
        lines, tail = self._split(text)
        prefix: List[str] = []
        suffix: List[str] = []
        preserved: List[str] = []
        removed = 0
        inside = False
        found = False
        closed = False

        for line in lines:
            if not inside and _is_marker(line, BEGIN_KEY):
                inside = True
                found = True
                continue
            if inside:
                if _is_marker(line, END_KEY):
                    inside = False
                    closed = True
                    continue
                if self._looks_like_our_entry(line, expected) or self._is_our_comment(line):
                    removed += 1
                    continue
                preserved.append(line)  # not ours: keep it
                removed += 1
                continue
            (prefix if not found else suffix).append(line)

        if tail:
            if inside:
                # File ends inside a damaged block: keep the fragment only if it
                # is clearly not one of our own entries.
                if not self._looks_like_our_entry(tail, expected):
                    suffix.append(tail + eol)
            else:
                suffix.append(tail)
        separator_removed = False
        if separator_text and prefix and "".join(prefix).endswith(separator_text):
            joined = "".join(prefix)[: -len(separator_text)]
            prefix = [joined]
            separator_removed = True

        new_text = "".join(prefix) + "".join(preserved) + "".join(suffix)
        return StripResult(new_text, removed, preserved, found, closed, separator_removed, found and not closed)

    def render(self, hostnames: Sequence[str], previous_separator: str = "") -> Tuple[str, ChangeResult]:
        """Return the hosts text that would result from blocking ``hostnames``.

        ``previous_separator`` is the separator recorded in the state manifest.
        Passing it keeps re-applying idempotent: the blank line we inserted is
        removed again before being re-inserted, so the file never grows.
        """
        text, encoding, eol = self.load()
        names = sorted({h for h in (normalise_hostname(n) for n in hostnames) if h})
        expected = set(names) | set(self.blocked_hostnames(text))

        stripped = self._strip_block(text, expected, previous_separator)
        base = stripped.text

        result = ChangeResult(
            path=self.path,
            encoding=encoding,
            eol=eol,
            lines_removed=stripped.removed,
            preserved_lines=stripped.preserved,
            truncated_block=stripped.truncated,
            hostnames=names,
            entries_added=len(names),
        )

        # One blank line between whatever was already there and our block.
        separator = ""
        if base.strip():
            if not base.endswith(("\n", "\r")):
                separator += eol
            if not base.endswith(eol + eol):
                separator += eol
        result.separator_text = separator

        block = self._render_block(names, eol)
        result.lines_added = len(block)
        return base + separator + "".join(block), result

    # ---------------------------------------------------------------- writing
    def _atomic_write(self, payload: bytes) -> None:
        target = self.real_path
        directory = os.path.dirname(target) or "."
        try:
            st = os.stat(target) if os.path.exists(target) else None
        except OSError:
            st = None
        try:
            fd, tmp = tempfile.mkstemp(prefix=".jamfdisabler-", dir=directory)
        except OSError as exc:
            raise HostsError(
                "Cannot create a temporary file next to {}: {}. Administrator/root rights are "
                "required (macOS/Linux: sudo; Windows: run as administrator).".format(target, exc)
            ) from exc
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            if st is not None:
                try:
                    os.chmod(tmp, st.st_mode & 0o7777)
                except OSError:
                    pass
                if os.name != "nt" and hasattr(os, "chown"):
                    try:
                        os.chown(tmp, st.st_uid, st.st_gid)
                    except OSError:
                        pass
            os.replace(tmp, target)
        except PermissionError as exc:
            _silent_remove(tmp)
            raise HostsError(
                "Permission denied writing {}. Administrator/root rights are required "
                "(macOS/Linux: sudo; Windows: run as administrator).".format(target)
            ) from exc
        except OSError as exc:
            _silent_remove(tmp)
            raise HostsError("Could not write {}: {}".format(target, exc)) from exc

    def encode(self, text: str, encoding: str) -> bytes:
        try:
            return text.encode(encoding, errors="strict")
        except (UnicodeEncodeError, LookupError):
            return text.encode("latin-1", errors="replace")

    # ------------------------------------------------------------------ action
    def apply(self, hostnames: Sequence[str], previous_separator: str = "") -> ChangeResult:
        """Sinkhole ``hostnames``.  Idempotent and marker-scoped."""
        new_text, result = self.render(hostnames, previous_separator)
        current, _, _ = self.load()
        if current == new_text:
            result.already_done = True
            result.hostnames = self.blocked_hostnames(current)
            return result
        self._atomic_write(self.encode(new_text, result.encoding))
        result.changed = True
        return result

    def revert(
        self,
        expected_extra: Sequence[str] = (),
        separator_text: str = "",
        restore_exact: bool = True,
    ) -> ChangeResult:
        """Remove our block, putting the file back the way it was."""
        text, encoding, eol = self.load()
        expected = {h for h in (normalise_hostname(n) for n in expected_extra) if h}
        expected |= set(self.blocked_hostnames(text))

        stripped = self._strip_block(text, expected, separator_text if restore_exact else "")
        restored = stripped.text
        result = ChangeResult(
            path=self.path,
            encoding=encoding,
            eol=eol,
            lines_removed=stripped.removed,
            preserved_lines=stripped.preserved,
            truncated_block=stripped.truncated,
            hostnames=sorted(expected),
        )
        if not stripped.found:
            result.already_done = True
            return result

        if restored != text:
            self._atomic_write(self.encode(restored, encoding))
            result.changed = True
        return result

    def restore_bytes(self, data: bytes) -> None:
        """Write ``data`` verbatim (used together with the pristine backup)."""
        self._atomic_write(data)

    def verify(self, hostnames: Sequence[str]) -> List[Tuple[str, bool]]:
        """Check the hosts text really holds a sinkhole entry for every name."""
        text, _, _ = self.load()
        blocked = set(self.blocked_hostnames(text))
        results: List[Tuple[str, bool]] = []
        for name in hostnames:
            clean = normalise_hostname(name)
            if not clean:
                continue
            results.append((clean, clean in blocked))
        return results

    def unresolved_expected(self, hostnames: Sequence[str]) -> List[str]:
        return [name for name, ok in self.verify(hostnames) if not ok]

    def summary(self) -> Dict[str, object]:
        text, encoding, eol = self.load()
        blocked = self.blocked_hostnames(text)
        return {
            "path": self.path,
            "real_path": self.real_path,
            "is_symlink": self.is_symlink,
            "explicit_block": self.has_block(text),
            "blocked_count": len(blocked),
            "blocked_hostnames": blocked,
            "encoding": encoding,
            "eol": repr(eol),
        }

    def resolves_to_sinkhole(self, hostname: str, timeout: float = 2.0) -> Optional[bool]:
        """``True``/``False`` when the OS resolver agrees, ``None`` if unknown.

        A name that fails to resolve counts as blocked too: no connection can be
        made to it either way.
        """
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(timeout)
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            return True
        except OSError:
            return None
        finally:
            socket.setdefaulttimeout(old_timeout)
        addrs = {info[4][0] for info in infos}
        if not addrs:
            return True
        return all(addr in SINKHOLE_ADDRESSES or addr.startswith("127.") for addr in addrs)


def _silent_remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
