#!/usr/bin/env python3
"""PyInstaller launcher for the stand-alone builds.

PyInstaller needs a real script file (not a package path) so that relative
imports inside the package resolve correctly; this is that file.
"""

from __future__ import annotations

import sys

from jamfdisabler.cli import _maybe_pause, entry

if __name__ == "__main__":
    try:
        entry()
    except SystemExit:
        raise
    except KeyboardInterrupt:  # pragma: no cover
        _maybe_pause()
        sys.exit(130)
