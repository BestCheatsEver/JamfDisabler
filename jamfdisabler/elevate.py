"""Ask the operating system for administrator rights, then continue.

The pattern is always the same: the *parent* process does the interactive work
(plan, warnings, confirmation) and then re-runs itself with the same arguments
plus ``--yes --elevated`` so the privileged child never has to ask anything.

* **Linux/BSD** - ``sudo`` keeps our terminal, so output streams live.
* **macOS** - ``osascript ... with administrator privileges`` shows the standard
  system password prompt; the child's output is captured and printed afterwards.
* **Windows** - ``ShellExecuteExW`` with the ``runas`` verb triggers the UAC
  prompt; the child writes to ``--log-file`` which we echo when it finishes.

If elevation is impossible (no sudo, no GUI, UAC declined) the caller prints
manual instructions instead of failing silently.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from typing import List, Optional, Sequence, Tuple

from . import APP_NAME
from . import console as c
from .sysinfo import platform_name


class ElevationUnavailable(Exception):
    pass


def _child_command(extra: Sequence[str]) -> Tuple[str, List[str]]:
    """Return ``(program, args)`` that re-runs this tool with ``extra``."""
    if getattr(sys, "frozen", False):
        return sys.executable, [str(a) for a in extra]
    # Dev/normal install: re-run the interpreter with -m jamfdisabler
    return sys.executable, ["-m", "jamfdisabler"] + [str(a) for a in extra]


def _append_marker(args: Sequence[str]) -> List[str]:
    args = list(args)
    if "--yes" not in args:
        args.append("--yes")
    if "--elevated" not in args:
        args.append("--elevated")
    if "--color" not in args and "--no-color" not in args:
        args.append("--color")
    return args


def _quote_unix(parts: Sequence[str]) -> str:
    import shlex

    return " ".join(shlex.quote(p) for p in parts)


# --------------------------------------------------------------------------- #
# Windows
# --------------------------------------------------------------------------- #
def _relaunch_windows(program: str, args: Sequence[str], log_file: Optional[str]) -> int:
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", ctypes.c_ulong),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIcon", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    SEE_MASK_NOASYNC = 0x00000100
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    info.lpVerb = "runas"
    info.lpFile = program
    info.lpParameters = subprocess.list2cmdline(list(args))
    info.lpDirectory = os.getcwd()
    info.nShow = 1  # SW_SHOWNORMAL

    shell32 = ctypes.windll.shell32
    kernel32 = ctypes.windll.kernel32
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        err = kernel32.GetLastError()
        raise ElevationUnavailable("The elevation prompt was declined or unavailable (error {}).".format(err))
    if not info.hProcess:
        return 0
    try:
        kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)  # INFINITE
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        return int(code.value)
    finally:
        kernel32.CloseHandle(info.hProcess)


# --------------------------------------------------------------------------- #
# macOS
# --------------------------------------------------------------------------- #
def _relaunch_macos(program: str, args: Sequence[str]) -> int:
    inner = _quote_unix([program] + list(args))
    # `do shell script` runs the command as root and hands us its stdout.
    # Ending with `echo __JFD_RC=$?` lets us recover the child's exit status.
    script = 'do shell script "{}; echo __JFD_RC=$?" with administrator privileges'.format(inner.replace('"', '\\"'))
    try:
        proc = subprocess.run(  # noqa: S603
            ["/usr/bin/osascript", "-e", script],
            capture_output=True,
            text=True,
            errors="replace",
        )
    except OSError as exc:
        raise ElevationUnavailable("Could not run osascript: {}".format(exc)) from exc
    if proc.stdout:
        sys.stdout.write(proc.stdout)
        sys.stdout.flush()
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "").strip().splitlines()
        detail = message[-1] if message else "unknown error"
        if "not allowed" in detail or "User canceled" in detail or "-128" in detail:
            raise ElevationUnavailable("The administrator prompt was cancelled.")
        raise ElevationUnavailable(detail[:300])
    code = 0
    for line in (proc.stdout or "").splitlines():
        if line.startswith("__JFD_RC="):
            try:
                code = int(line.split("=", 1)[1].strip())
            except ValueError:
                code = 0
    return code


# --------------------------------------------------------------------------- #
# Linux / BSD
# --------------------------------------------------------------------------- #
def _relaunch_posix(program: str, args: Sequence[str], gui_fallback: bool = True) -> int:
    sudo = shutil.which("sudo")
    if sudo and c.stdin_is_tty():
        try:
            return subprocess.call([sudo, "--"] + [program] + list(args))  # noqa: S603
        except OSError as exc:
            raise ElevationUnavailable("Could not run sudo: {}".format(exc)) from exc
    pkexec = shutil.which("pkexec")
    if pkexec and gui_fallback:
        try:
            return subprocess.call([pkexec] + [program] + list(args))  # noqa: S603
        except OSError as exc:
            raise ElevationUnavailable("Could not run pkexec: {}".format(exc)) from exc
    raise ElevationUnavailable("Neither sudo (with a terminal) nor pkexec is available to gain administrator rights.")


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def relaunch_elevated(argv: Sequence[str], log_file: Optional[str] = None) -> int:
    """Re-run the tool with the same arguments, but elevated.

    Returns the child's exit code.  Raises :class:`ElevationUnavailable` when
    the user declined or no mechanism exists.
    """
    program, base_args = _child_command(list(argv))
    args = _append_marker(base_args)
    if log_file:
        args += ["--log-file", log_file]
    if platform_name() == "windows":
        return _relaunch_windows(program, args, log_file)
    if platform_name() == "macos":
        return _relaunch_macos(program, args)
    return _relaunch_posix(program, args)


def temp_log_file() -> str:
    fd, path = tempfile.mkstemp(prefix="jamfdisabler-", suffix=".log")
    os.close(fd)
    try:
        os.remove(path)
    except OSError:
        pass
    return path


def manual_instructions() -> None:
    c.warn("Administrator rights are required to change the hosts file (and firewall rules).")
    c.info("Run the same command with:")
    if platform_name() == "windows":
        c.bullet("An Administrator PowerShell/CMD window, or right-click the .exe -> 'Run as administrator'")
        c.bullet("PowerShell: Start-Process -Verb RunAs .\\{}.exe".format(APP_NAME))
    elif platform_name() == "macos":
        c.bullet("sudo -E jamfdisabler on      # or: sudo ./jamfdisabler on")
    else:
        c.bullet("sudo jamfdisabler on")
    c.note("Nothing has been changed so far.")
