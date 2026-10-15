"""JamfDisabler - a reversible, non-destructive Jamf network blocker.

JamfDisabler is a small, cross-platform utility that stops Jamf software on
*your own* computer from talking to Jamf's servers.  It does this by adding a
clearly-marked block to the system ``hosts`` file (and, optionally on Windows,
a set of named outbound firewall rules).

Everything it does is:

* **Reversible**  - ``jamfdisabler off`` puts the hosts file back exactly the
  way it was and deletes the firewall rules it created.
* **Non-destructive** - it never deletes configuration profiles, never
  un-enrols a device, never stops or disables Jamf services, and never touches
  ``hosts`` entries it did not write itself.
* **Visible** - every change is labelled with the tool's own name; nothing is
  hidden, disguised or made persistent behind your back.

See ``docs/SAFETY.md`` for the full list of guarantees.
"""

from __future__ import annotations

APP_NAME = "JamfDisabler"
__version__ = "1.0.0"
VERSION = __version__

#: Where releases/instructions live.  Used in user-facing messages.
PROJECT_URL = "https://github.com/BestCheatsEver/JamfDisabler"

#: Marker used inside the hosts file.  Keep in sync with ``hosts.py``.
HOSTS_BLOCK_VERSION = 1

__all__ = ["APP_NAME", "PROJECT_URL", "HOSTS_BLOCK_VERSION", "__version__", "VERSION"]
