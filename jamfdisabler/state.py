"""Persistent state: where the backup lives and what we actually changed.

JamfDisabler keeps a small JSON "manifest" plus a pristine backup of the
hosts file.  The manifest is what makes ``off`` able to be *exact*: it records
the byte-level details of the original file and the names of every firewall
rule we created.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from typing import Any, Dict, List, Optional

from . import APP_NAME, __version__

MANIFEST_NAME = "manifest.json"
MANIFEST_VERSION = 1

HOSTS_BACKUP_NAME = "hosts.original"


def _is_macos() -> bool:
    try:
        return os.uname().sysname == "Darwin"  # type: ignore[attr-defined]
    except Exception:
        return False


def default_state_dir() -> str:
    """Return the per-machine state directory (not created yet)."""
    override = os.environ.get("JAMFDISABLER_STATE_DIR")
    if override:
        return os.path.abspath(os.path.expanduser(override))
    if os.name == "nt":
        base = os.environ.get("PROGRAMDATA") or os.environ.get("ALLUSERSPROFILE") or "C:\\ProgramData"
        return os.path.join(base, APP_NAME)
    if _is_macos():
        return "/var/db/{}".format(APP_NAME)
    # Linux and anything else
    return os.path.join(os.environ.get("XDG_STATE_HOME") or "/var/lib", APP_NAME)


class StateError(Exception):
    pass


class State:
    """Reads/writes ``manifest.json`` and keeps the hosts backup."""

    def __init__(self, state_dir: Optional[str] = None):
        self.dir = os.path.abspath(os.path.expanduser(state_dir or default_state_dir()))
        self._manifest: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------ paths
    @property
    def manifest_path(self) -> str:
        return os.path.join(self.dir, MANIFEST_NAME)

    @property
    def backup_path(self) -> str:
        return os.path.join(self.dir, HOSTS_BACKUP_NAME)

    @property
    def log_path(self) -> str:
        return os.path.join(self.dir, "log.txt")

    # -------------------------------------------------------------- manifest
    def exists(self) -> bool:
        return os.path.isfile(self.manifest_path)

    def load(self) -> Dict[str, Any]:
        if self._manifest is not None:
            return self._manifest
        if not self.exists():
            self._manifest = {}
            return self._manifest
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            raise StateError("Could not read state file {}: {}".format(self.manifest_path, exc)) from exc
        if not isinstance(data, dict):
            raise StateError("State file {} is corrupt (not a JSON object)".format(self.manifest_path))
        self._manifest = data
        return data

    def save(self, data: Dict[str, Any]) -> None:
        data = dict(data)
        data.setdefault("version", MANIFEST_VERSION)
        data["tool"] = APP_NAME
        data["tool_version"] = __version__
        data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self._ensure_dir()
        tmp = self.manifest_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, self.manifest_path)
        self._manifest = data

    def update(self, **fields: Any) -> Dict[str, Any]:
        data = dict(self.load())
        data.update(fields)
        self.save(data)
        return data

    def clear(self) -> None:
        for path in (self.manifest_path,):
            try:
                os.remove(path)
            except OSError:
                pass
        self._manifest = {}

    # ---------------------------------------------------------------- backups
    def _ensure_dir(self) -> None:
        try:
            os.makedirs(self.dir, exist_ok=True)
        except OSError as exc:  # pragma: no cover - depends on filesystem rights
            raise StateError("Could not create state directory {}: {}".format(self.dir, exc)) from exc

    def write_backup(self, source_path: str) -> str:
        """Copy ``source_path`` to the state dir, keeping older backups."""
        self._ensure_dir()
        if os.path.isfile(self.backup_path):
            stamp = time.strftime("%Y%m%d-%H%M%S")
            keep = os.path.join(self.dir, "hosts.original.{}".format(stamp))
            try:
                shutil.copy2(self.backup_path, keep)
            except OSError:
                pass
        if not os.path.exists(source_path):
            # Nothing on disk to copy: remember that fact as an empty backup so
            # a later `off` still knows the original state.
            try:
                with open(self.backup_path, "wb") as fh:
                    fh.write(b"")
            except OSError as exc:
                raise StateError("Could not write backup {}: {}".format(self.backup_path, exc)) from exc
            return self.backup_path
        try:
            shutil.copy2(source_path, self.backup_path)
        except OSError as exc:
            raise StateError("Could not back up {}: {}".format(source_path, exc)) from exc
        return self.backup_path

    def read_backup(self) -> Optional[bytes]:
        try:
            with open(self.backup_path, "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def list_backups(self) -> List[str]:
        if not os.path.isdir(self.dir):
            return []
        names = [n for n in sorted(os.listdir(self.dir)) if n.startswith("hosts.original")]
        return [os.path.join(self.dir, n) for n in names]

    def append_log(self, line: str) -> None:
        """Best-effort plaintext log so the user can audit what happened."""
        try:
            self._ensure_dir()
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write("{} {}\n".format(time.strftime("%Y-%m-%dT%H:%M:%S%z"), line))
        except OSError:
            pass

    # ------------------------------------------------------------------ magic
    def hosts_state(self) -> Dict[str, Any]:
        data = self.load()
        hosts = data.get("hosts")
        return hosts if isinstance(hosts, dict) else {}

    def firewall_rules(self) -> List[Dict[str, Any]]:
        data = self.load()
        rules = data.get("firewall_rules")
        if not isinstance(rules, list):
            return []
        return [r for r in rules if isinstance(r, dict)]

    def blocked_hostnames(self) -> List[str]:
        hosts = self.hosts_state()
        names = hosts.get("hostnames")
        if isinstance(names, list):
            return [str(n) for n in names]
        return []
