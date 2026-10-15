"""Allow ``python -m jamfdisabler`` and ``python jamfdisabler/__main__.py``."""

from __future__ import annotations

import sys

from .cli import _maybe_pause, main


def _run() -> None:
    code = main()
    _maybe_pause()
    sys.exit(code)


if __name__ == "__main__":
    _run()
