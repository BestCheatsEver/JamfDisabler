"""Tiny terminal helper: colour, headings, prompts.

No third-party dependencies, works on Windows/macOS/Linux and degrades to
plain ASCII when colour or Unicode is not available.
"""

from __future__ import annotations

import os
import sys

_COLOR_FORCED = None  # type: bool | None
_UNICODE_OK = None  # type: bool | None
_TEE = None  # optional file handle: mirrors all output to a log file

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"


def set_tee(path):
    """Mirror everything printed from now on into ``path`` (append).

    Used when the process runs elevated on Windows/macOS, where the parent
    keeps the console and only sees the child's captured output.
    """
    global _TEE
    try:
        # The handle is intentionally long-lived (closed by close_tee()).
        _TEE = open(path, "a", encoding="utf-8", errors="replace")  # noqa: SIM115
    except OSError:
        _TEE = None
    return _TEE


def close_tee() -> None:
    global _TEE
    if _TEE is not None:
        try:
            _TEE.flush()
            _TEE.close()
        except OSError:
            pass
        _TEE = None


def _write(text: str) -> None:
    """Write one already-final line to the console, escaping nothing."""
    try:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        # Piping into `head` and friends closes stdout early - not an error.
        try:
            sys.stdout.close()
        except (OSError, ValueError):
            pass
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        safe = text.encode(enc, errors="replace").decode(enc, errors="replace")
        try:
            sys.stdout.write(safe + "\n")
        except (OSError, ValueError):
            pass
    except (OSError, ValueError):
        pass


def _emit(text: str = "") -> None:
    """Single funnel for user-visible output (console + optional log file)."""
    if _TEE is not None:
        try:
            _TEE.write("{}\n".format(text))
            _TEE.flush()
        except (OSError, ValueError):
            pass
    _write(text)


def _enable_windows_vt() -> None:
    """Ask the Windows console to interpret ANSI escape sequences."""
    try:  # pragma: no cover - Windows only
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        for handle in (-11, -12):  # stdout, stderr
            h = kernel32.GetStdHandle(handle)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                kernel32.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VT
    except Exception:
        pass


def set_color(enabled: bool | None) -> None:
    """Force colour on/off (``None`` = autodetect)."""
    global _COLOR_FORCED
    _COLOR_FORCED = enabled


def use_color() -> bool:
    if _COLOR_FORCED is not None:
        return bool(_COLOR_FORCED)
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("JAMFDISABLER_COLOR", "").lower() in ("0", "never", "false"):
        return False
    if os.environ.get("JAMFDISABLER_COLOR", "").lower() in ("1", "always", "true"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        if not sys.stdout.isatty():
            return False
    except Exception:
        return False
    if os.name == "nt":
        _enable_windows_vt()
    return True


def use_unicode() -> bool:
    global _UNICODE_OK
    if _UNICODE_OK is None:
        enc = (getattr(sys.stdout, "encoding", None) or "").lower()
        _UNICODE_OK = "utf" in enc and os.environ.get("TERM") != "dumb"
    return bool(_UNICODE_OK)


def _c(text: str, colour: str) -> str:
    if not use_color():
        return text
    return "{}{}{}".format(colour, text, RESET)


def sym(name: str) -> str:
    """Return a glyph, falling back to ASCII."""
    table = {
        "ok": ("✔", "+"),
        "fail": ("✖", "x"),
        "warn": ("!", "!"),
        "arrow": ("→", "->"),
        "bullet": ("•", "-"),
        "shield": ("🛡", "#"),
        "lock": ("🔒", "L"),
    }
    uni, ascii_ = table.get(name, ("", ""))
    return uni if use_unicode() else ascii_


def out(text: str = "") -> None:
    _emit(text)


def head(title: str) -> None:
    _emit()
    _emit(_c(title, BOLD + CYAN))
    _emit(_c("-" * min(len(title), 60), DIM))


def ok(text: str) -> None:
    _emit("  {} {}".format(_c(sym("ok"), GREEN), text))


def fail(text: str) -> None:
    _emit("  {} {}".format(_c(sym("fail"), RED), text))


def warn(text: str) -> None:
    _emit("  {} {}".format(_c(sym("warn"), YELLOW), text))


def info(text: str) -> None:
    _emit("  {}".format(text))


def note(text: str) -> None:
    _emit("  {}".format(_c(text, DIM)))


def bullet(text: str) -> None:
    _emit("   {} {}".format(_c(sym("bullet"), DIM), text))


def field(label: str, value: str, width: int = 20) -> None:
    _emit("  {}{}".format(_c(label.ljust(width), DIM), value))


def raw(text: str = "") -> None:
    _emit(text)


def _readline(prompt: str) -> str | None:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        _emit()
        return None


def confirm(question: str, default: bool = False, assume_yes: bool = False) -> bool:
    """Ask a yes/no question.  Returns ``default`` when there is no TTY."""
    suffix = "[Y/n]" if default else "[y/N]"
    if assume_yes:
        info("{} {}".format(question, _c("(auto-confirmed by --yes)", DIM)))
        return True
    if not stdin_is_tty():
        note("{} {} -> not a terminal, assuming '{}'".format(question, suffix, "yes" if default else "no"))
        return default
    answer = _readline("{} {} ".format(question, suffix))
    if answer is None:
        return False
    answer = answer.strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes", "1", "true", "on")


def choose(question: str, choices: list, default: str | None = None) -> str | None:
    """Ask for one of ``choices`` (single characters).  ``None`` = no TTY."""
    if not stdin_is_tty():
        return default
    answer = _readline("{} ".format(question))
    if answer is None:
        return None
    answer = answer.strip().lower()
    if not answer:
        return default
    if answer in choices:
        return answer
    warn("Unrecognised choice: {!r}".format(answer))
    return None


def stdin_is_tty() -> bool:
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        return False


def stdout_is_tty() -> bool:
    try:
        return sys.stdout is not None and sys.stdout.isatty()
    except Exception:
        return False


def pause(message: str = "Press Enter to close...") -> None:
    """Keep a double-clicked window open (best effort)."""
    if not stdin_is_tty():
        return
    try:
        input("\n" + message)
    except (EOFError, KeyboardInterrupt):
        pass


def banner(subtitle: str = "") -> None:
    _emit()
    _emit(_c("  JamfDisabler", BOLD + BLUE))
    if subtitle:
        _emit("  {}".format(_c(subtitle, DIM)))
    _emit()
