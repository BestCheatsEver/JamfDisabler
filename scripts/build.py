#!/usr/bin/env python3
"""Build the stand-alone JamfDisabler executable for the current platform.

    python scripts/build.py                 # one-file build into dist/
    python scripts/build.py --onedir        # folder build (starts faster)
    python scripts/build.py --zipapp        # portable .pyz (no PyInstaller needed)
    python scripts/build.py --clean         # wipe build/ and dist/ first

PyInstaller cannot cross-compile: run this on the OS you want a binary for.
On macOS and Windows you need Python 3.8+ installed, nothing else.

``--zipapp`` produces a single file that runs anywhere Python 3.8+ exists,
without PyInstaller and without a compiler:

    ./dist/JamfDisabler.pyz on       # unix
    python dist\\JamfDisabler.pyz on   # windows
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY = os.path.join(REPO_ROOT, "scripts", "entry_point.py")


def default_name() -> str:
    return "JamfDisabler.exe" if os.name == "nt" else "JamfDisabler"


def check_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed. Install it with:")
        print("    {} -m pip install pyinstaller".format(sys.executable))
        raise SystemExit(1) from None


def build_zipapp(name: str, dist_dir: str) -> str:
    """Create a single-file ``.pyz`` that only needs a Python interpreter."""
    import tempfile
    import zipapp

    os.makedirs(dist_dir, exist_ok=True)
    out = os.path.join(dist_dir, "{}.pyz".format(name if not name.endswith(".exe") else name[:-4]))
    stage = tempfile.mkdtemp(prefix="jamfdisabler-stage-")
    try:
        shutil.copytree(
            os.path.join(REPO_ROOT, "jamfdisabler"),
            os.path.join(stage, "jamfdisabler"),
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        with open(os.path.join(stage, "__main__.py"), "w", encoding="utf-8") as fh:
            fh.write(
                "import sys\n"
                "from jamfdisabler.cli import entry, _maybe_pause\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    try:\n"
                "        entry()\n"
                "    except SystemExit as exc:\n"
                "        _maybe_pause()\n"
                "        sys.exit(exc.code)\n"
            )
        if os.path.exists(out):
            os.remove(out)
        zipapp.create_archive(
            stage,
            target=out,
            interpreter="/usr/bin/env python3",
            compressed=True,
        )
        if os.name != "nt":
            # Make the .pyz directly executable; it is built from our own tree.
            os.chmod(out, 0o755)  # noqa: S103
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return out


def build_args(name: str, onefile: bool, extra: list) -> list:
    args = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--console",
        "--name",
        name,
        "--paths",
        REPO_ROOT,
    ]
    args.append("--onefile" if onefile else "--onedir")
    if os.name == "nt":
        # Keep the window open when the exe is double-clicked: handled by the
        # app itself via --pause (see cli._maybe_pause).
        pass
    args += extra
    args.append(ENTRY)
    return args


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description="Build a stand-alone JamfDisabler executable.")
    parser.add_argument("--name", default=default_name(), help="output executable name")
    parser.add_argument("--onedir", action="store_true", help="build a folder instead of a single file")
    parser.add_argument("--dist", default=os.path.join(REPO_ROOT, "dist"), help="output directory")
    parser.add_argument("--clean", action="store_true", help="remove build/ and dist/ before building")
    parser.add_argument(
        "--zipapp",
        action="store_true",
        help="build a portable single-file .pyz instead of a PyInstaller binary",
    )
    parser.add_argument("--workpath", default=os.path.join(REPO_ROOT, "build"), help="PyInstaller work dir")
    parser.add_argument("--specpath", default=REPO_ROOT, help="where to write the .spec file")
    parser.add_argument("extra", nargs="*", help="extra arguments passed straight to PyInstaller")
    args = parser.parse_args(argv)

    if args.clean:
        for path in (args.workpath, args.dist):
            shutil.rmtree(path, ignore_errors=True)

    if args.zipapp:
        out = build_zipapp(args.name, args.dist)
        print("==> built: {}".format(out))
        print("==> try it: {} --version".format(out))
        print("==> run it: {} on    (needs Python 3.8+ on the target machine)".format(out))
        return 0

    check_pyinstaller()

    name = args.name
    if os.name != "nt" and name.endswith(".exe"):
        name = name[: -len(".exe")]

    cmd = build_args(name, not args.onedir, args.extra)
    cmd += ["--distpath", args.dist, "--workpath", args.workpath, "--specpath", args.specpath]

    print("==> {}".format(" ".join(cmd)))
    print("==> building on {} {}".format(platform.system(), platform.machine()))
    rc = subprocess.call(cmd, cwd=REPO_ROOT)
    if rc != 0:
        print("Build failed (exit code {}).".format(rc))
        return rc

    target = os.path.join(args.dist, name + (".exe" if os.name == "nt" else ""))
    if not os.path.exists(target) and os.path.isdir(target):
        target = os.path.join(target, name)
    print()
    print("==> built: {}".format(target))
    print("==> try it: {} --version".format(target))
    if os.name != "nt":
        print("==> and:    sudo {} on".format(target))
    else:
        print('==> and:    "{}" on   (in an Administrator terminal)'.format(target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
