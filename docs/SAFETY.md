# Safety and reversibility guarantees

JamfDisabler is built around one rule: **the machine must be exactly as it was
after `jamfdisabler off`** — or, when that is impossible because something else
edited the same files, the tool must say so plainly instead of clobbering them.

This document lists the guarantees, how each one is implemented, and how each
one is tested.

---

## 1. Guarantees

| # | Guarantee | Implementation | Test |
|---|---|---|---|
| 1 | No file is ever deleted | nothing in the codebase calls `os.remove`/`shutil.rmtree` on system paths; only the temp file created during an atomic write is unlinked, and only on the error path | `tests/test_ops.py::test_no_files_are_deleted` |
| 2 | Only the hosts file is modified, and only between our markers | `hosts.py::_strip_block` walks lines and removes only entries inside the BEGIN/END region | `tests/test_hosts.py::test_revert_without_block_is_a_noop`, `test_apply_does_not_touch_unrelated_lines` |
| 3 | Lines we did not write are never removed | inside the region, a line is removed only if it maps a Jamf-owned hostname to a sinkhole address, or is one of our own comment lines; everything else is collected and re-inserted | `tests/test_ops.py::test_disable_removes_block_and_keeps_user_edits`, `test_hosts.py::test_revert_keeps_foreign_lines_inside_the_block` |
| 4 | The original hosts file is recoverable byte-for-byte | a pristine copy (`hosts.original`) is taken before the first change; `off` compares the result against it | `tests/test_hosts.py::test_round_trip_is_byte_exact` (11 file shapes) |
| 5 | Re-running `on` never grows the file | the separator text we insert is recorded in the manifest and stripped again before re-inserting | `tests/test_hosts.py::test_render_is_idempotent`, `test_ops.py::test_double_enable_is_idempotent` |
| 6 | Edits made while the block was active survive `off` | after removing our lines, the result is compared to the backup; if they differ, the merge result is written and reported | `tests/test_ops.py::test_disable_removes_block_and_keeps_user_edits` |
| 7 | Writes are atomic and preserve permissions | temp file in the same directory → `fsync` → `os.replace`, mode (and ownership on Unix) copied from the original | `tests/test_hosts.py::test_permissions_are_preserved` |
| 8 | Symlinked hosts files are followed, not replaced | writes go to `os.path.realpath(path)` | `tests/test_hosts.py::test_symlinked_hosts_writes_through_to_the_target` |
| 9 | No third-party hostname can enter the block | catalogue entries must match a Jamf-owned domain; auto-detected names must either match a Jamf domain or come from Jamf's own config files; OS/cloud infrastructure and bare IPs are always refused | `tests/test_endpoints.py::test_catalogue_contains_no_third_party_domains`, `tests/test_ops.py::test_safe_to_block_*`, `test_the_block_only_ever_contains_jamf_names` |
| 10 | No profiles, agents or services are touched | there is no code path that reads/writes profiles, launch daemons, services or registry keys of Jamf; `find_jamf_paths()` only stats paths | `tests/test_ops.py::test_no_files_are_deleted` |
| 11 | No persistence, no hidden state | the only artifacts are the hosts block, the Windows firewall rules, and the state directory (backup, manifest, log) | reviewed in `state.py`, `firewall.py` |
| 12 | `--dry-run` performs no writes at all | `ops.enable/disable/restore_backup_only` return before touching disk | `tests/test_ops.py::test_dry_run_changes_nothing`, `test_cli.py::test_dry_run_never_writes` |

---

## 2. What exactly is written where

### 2.1 Hosts file

```
127.0.0.1        localhost          ← your file, never touched
::1              localhost          ← your file, never touched

# >>> JamfDisabler block v1 (managed by JamfDisabler - run `jamfdisabler off` to undo) >>>
# Added by JamfDisabler. Fully reversible: run `jamfdisabler off`.
# JamfDisabler only redirects these names: nothing is deleted, un-enrolled or disabled.
0.0.0.0  telemetry.jamfcloud.com
::       telemetry.jamfcloud.com
... one line per address family and hostname ...
# <<< JamfDisabler block - end <<<
```

Inside the brackets we remove: our own three comment lines, and any line whose
address is a sinkhole (`0.0.0.0`, `::`, `::1`, `127.0.0.1`, `0`, `fe80::1`) *and*
whose hostname is either in the recorded list, in the catalogue, or otherwise
recognisably Jamf-owned. Everything else found inside the region is preserved and
re-inserted outside it.

### 2.2 State directory

| Platform | Path |
|---|---|
| macOS | `/var/db/JamfDisabler/` |
| Windows | `C:\ProgramData\JamfDisabler\` |
| Linux | `/var/lib/JamfDisabler/` |

Override with `--state-dir PATH` or `JAMFDISABLER_STATE_DIR`.

```
manifest.json          what we changed, and how to undo it (see below)
hosts.original         pristine bytes of your hosts file
hosts.original.<ts>    previous backups, kept if you enable twice
log.txt                one line per enable/disable, with a timestamp
```

`manifest.json`:

```json
{
  "version": 1,
  "tool": "JamfDisabler",
  "tool_version": "1.0.0",
  "enabled": true,
  "platform": "macos",
  "hosts": {
    "path": "/etc/hosts",
    "real_path": "/etc/hosts",
    "sha256_before": "…", "sha256_after": "…",
    "bytes_before": 267, "bytes_after": 5331,
    "encoding": "utf-8", "eol": "\n", "separator_text": "\n",
    "hostnames": ["account.jamf.com", "…"],
    "dynamic_hostnames": ["yourorg.jamfcloud.com"],
    "count": 76,
    "applied_at": "2026-01-01T12:00:00+0000",
    "backup": "/var/db/JamfDisabler/hosts.original",
    "backup_sha256": "…"
  },
  "firewall": { "rules": [{"name": "JamfDisabler-BLOCK-jamf.exe-1a2b3c4d", "program": "C:\\…"}] },
  "options": { "include_products": true, "include_optional": false, "auto_server": true }
}
```

`off` clears the `hosts` and `firewall` sections (so nothing stale can be
re-applied later) but keeps `hosts.original`, which is why `restore-backup` still
works after a disable.

### 2.3 Windows firewall rules

One rule per Jamf executable, always `dir=out`, `action=block`, `program=<path>`,
`profile=any`, `enable=yes`, and a name prefixed `JamfDisabler-BLOCK-`. They are
removed individually by name; `firewall.py::unblock` refuses to delete any rule
whose name does not start with that prefix, so a mistyped manifest can never
delete unrelated firewall configuration.

---

## 3. Failure modes, deliberately chosen

| Situation | What happens | Why |
|---|---|---|
| Not an administrator | Nothing is written; the tool either asks for elevation or prints the exact command to re-run | never guess at privilege escalation |
| Hosts file read-only / locked | The change fails with a clear message; the file is untouched | no attribute fiddling, no forcing |
| `END` marker missing (crash, editor) | Entries and our comments inside the damaged region are still removed, foreign lines are preserved, and the tool warns `truncated_block` | a half-written block must not become permanent litter |
| Someone edits the hosts file while blocked | `off` removes only our lines, keeps their edit, and says so | the user's newer intent outranks our backup |
| Only trailing newlines differ from the backup | The pristine backup is written back verbatim | cosmetic differences should not be reported as a conflict |
| State file missing but block present | The block is still removed safely (catalogue + Jamf-domain detection identifies our lines) | recovery without the state file |
| Elevation declined / cancelled | Exit code 2 with manual instructions, nothing changed | never retry in a loop |
| Anything unexpected | `off` remains available and safe; `restore-backup` overwrites with the pristine copy | worst case is recoverable |

---

## 4. What the tool never touches (audited list)

* `/Library/Managed Preferences/**`, `/var/db/ConfigurationProfiles/**`,
  `.mobileconfig` files anywhere
* `/Library/Application Support/Jamf/**`, `/usr/local/jamf/**`,
  `/Applications/Self Service.app`, `/Applications/JamfProtect.app`
* `C:\Program Files\Jamf\**`, `C:\ProgramData\Jamf\**`, registry keys under
  `HKLM\SOFTWARE\Jamf` / `HKLM\SOFTWARE\Microsoft\Enrollments`
* `launchctl`, `systemctl`, `sc.exe`, `schtasks` — never invoked
* Apple's APNs infrastructure (`*.push.apple.com`) — never blocked
* Any hosts line outside our markers, at any time

`jamfdisabler scan` *reads* some of these paths (names, sizes, existence) purely
to report what is present. Reading is all it does.

---

## 5. Verifying a build yourself

```bash
git clone https://github.com/BestCheatsEver/JamfDisabler
cd JamfDisabler
python -m pytest -q                 # 90+ tests, runs as a normal user
grep -rn "os.remove\|rmtree\|unlink" jamfdisabler/   # only the temp-file cleanup
python -m jamfdisabler scan         # read-only
python -m jamfdisabler on --dry-run --hosts-file /tmp/hosts \
                          --state-dir /tmp/state --no-color
diff /tmp/hosts <(printf '127.0.0.1 localhost\n')   # unchanged
```

Or point it at a throwaway file and watch the whole cycle:

```bash
printf '127.0.0.1 localhost\n' > /tmp/hosts.example
cp /tmp/hosts.example /tmp/hosts.example.bak
python -m jamfdisabler on  --hosts-file /tmp/hosts.example --state-dir /tmp/jd --yes
python -m jamfdisabler off --hosts-file /tmp/hosts.example --state-dir /tmp/jd --yes
cmp /tmp/hosts.example /tmp/hosts.example.bak && echo "byte-identical"
```
