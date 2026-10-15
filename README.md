# JamfDisabler

**Stop Jamf from phoning home — reversibly, and without breaking anything.**

JamfDisabler is a small, dependency-free utility for your own Mac, Windows PC or
Linux box that redirects Jamf's server hostnames to a dead end, so the Jamf agent
can no longer check in, upload inventory, run policies or send telemetry. Turn it
off again and your machine is exactly as it was — byte for byte.

```
jamfdisabler on        # block Jamf (asks for your password)
jamfdisabler status    # is it on?
jamfdisabler off       # undo everything, restore the original hosts file
```

No daemons. No kernel extensions. No deleted profiles. No un-enrolment. No
hidden leftovers.

<p align="center">
  <em>Runs on macOS (Apple silicon + Intel), Windows 10/11 and Linux — as a
  single executable, or with <code>python3 -m jamfdisabler</code>.</em>
</p>

---

## Table of contents

- [Quick start](#quick-start)
  - [macOS](#macos)
  - [Windows](#windows)
  - [Linux](#linux)
  - [No download: run from source](#no-download-run-from-source)
- [Commands](#commands)
- [What it blocks](#what-it-blocks)
- [What it does *not* do](#what-it-does-not-do)
- [How it stays harmless](#how-it-stays-harmless)
- [The full build (single-file executables)](#the-full-build-single-file-executables)
- [Verify it works](#verify-it-works)
- [Troubleshooting](#troubleshooting)
- [Limitations and honesty section](#limitations-and-honesty-section)
- [Legal and ethical note](#legal-and-ethical-note)
- [Development](#development)

---

## Quick start

### macOS

There is no build step and no Python required if you use the prebuilt binary
from the [releases page](https://github.com/BestCheatsEver/JamfDisabler/releases):

1. Download `JamfDisabler-macos-arm64` (Apple silicon) or
   `JamfDisabler-macos-x86_64` (Intel).
2. `chmod +x` it, then run it. macOS will ask for your password, because writing
   `/etc/hosts` requires administrator rights — that is the *only* privileged
   action.

```bash
# one-liner: download the right binary and run the interactive menu
curl -fsSL https://raw.githubusercontent.com/BestCheatsEver/JamfDisabler/main/install.sh | bash

# or, after installing, from any terminal:
sudo jamfdisabler on        # turn it on
jamfdisabler status         # check
sudo jamfdisabler off       # turn it off again
```

Running the app with **no arguments** shows a menu, so you can also just
double-click it in Finder (Terminal opens): `1) Turn the block ON`, `2) Turn the
block OFF`, `3) Status`, `4) Scan this Mac`.

### Windows

1. Download **`JamfDisabler-windows-x86_64.exe`** from
   [releases](https://github.com/BestCheatsEver/JamfDisabler/releases).
2. Double-click it. That opens the interactive menu. For the `on`/`off`
   commands, run it **as administrator** (right-click → *Run as administrator*),
   because editing `C:\Windows\System32\drivers\etc\hosts` and adding firewall
   rules needs it.

```powershell
# one-liner install (no admin needed for the install itself)
powershell -ExecutionPolicy Bypass -File .\install.ps1 -AddToPath

jamfdisabler on      # in an Administrator terminal
jamfdisabler status
jamfdisabler off
```

On Windows you get a second layer: named **outbound firewall rules** for each
Jamf program found on the machine (`netsh advfirewall`), created and deleted by
this tool only. See [What it blocks](#what-it-blocks).

### Linux

```bash
curl -fsSL https://raw.githubusercontent.com/BestCheatsEver/JamfDisabler/main/install.sh | bash
sudo jamfdisabler on && jamfdisabler status
```

Linux rarely runs Jamf software, but the tool is fully functional there (handy
for labs, VMs and imaging machines, and it works the same under WSL).

### No download: run from source

Python 3.8+ is all you need — the tool has **zero third-party dependencies**.

```bash
git clone https://github.com/BestCheatsEver/JamfDisabler.git
cd JamfDisabler
python3 -m jamfdisabler            # interactive menu
sudo python3 -m jamfdisabler on    # or pip install . && sudo jamfdisabler on
```

---

## Commands

| Command | What it does | Needs admin |
|---|---|---|
| `jamfdisabler` | interactive menu (default when run with no arguments) | only for `on`/`off` |
| `jamfdisabler on` | sinkhole the Jamf hostnames (+ Windows firewall rules) | yes |
| `jamfdisabler off` | remove our lines, delete our firewall rules, restore the original hosts file | yes |
| `jamfdisabler status` | is the block active, how many names, which rules | no |
| `jamfdisabler status --json` | same, machine-readable | no |
| `jamfdisabler list` | every hostname the tool can block | no |
| `jamfdisabler list --blocked` | only what is blocked right now | no |
| `jamfdisabler scan` | read-only report: Jamf files, processes and the server this machine talks to | no |
| `jamfdisabler firewall on\|off\|status` | manage only the Windows firewall layer | yes for on/off |
| `jamfdisabler restore-backup` | write your pristine hosts file back, verbatim | yes |

Useful flags:

| Flag | Meaning |
|---|---|
| `--dry-run` | show exactly what would change; write nothing |
| `-y`, `--yes` | don't ask for confirmation (for scripts) |
| `--no-firewall` | hosts file only (skip the Windows firewall rules) |
| `--include-optional` | also block download/update/marketing endpoints |
| `--no-products` | only core Jamf Pro endpoints, none of the other Jamf products |
| `--add-host HOST` | block an extra hostname (repeatable) |
| `--no-auto-server` | don't auto-detect this machine's own Jamf server |
| `--all-detected` | also block secondary Jamf endpoints found in config files |
| `--no-elevate` | never ask for admin rights; just try and report errors |
| `--no-flush-dns` | skip flushing the DNS cache |
| `--no-color` | plain output (also honours `$NO_COLOR`) |

Aliases: `enable`/`start` = `on`, `disable`/`stop`/`undo` = `off`, `st` = `status`.

---

## What it blocks

`jamfdisabler on` writes a clearly marked block into your system hosts file that
points Jamf-owned hostnames at `0.0.0.0` / `::`. Your computer then refuses the
connection locally — **no packet is ever sent to Jamf**, and no DNS lookup is
made for those names.

Three groups, all listed by `jamfdisabler list`:

1. **Core (always):** telemetry and analytics (`telemetry.jamfcloud.com`,
   `metrics.jamfcloud.com`, …), Jamf's hosted services the agent and the Jamf Pro
   server call out to (`jamf-patch`, `hw-model-names`, `csa`, `ics`, `jamfpush`,
   cloud distribution points), plus Jamf's web/account domains.
2. **Other Jamf products (default on):** Jamf Protect, Jamf Connect, Jamf
   School/Now/ZuluDesk, Setup/Reset, legacy `jamfsoftware.com` names.
3. **This machine's own Jamf server (default on):** read out of Jamf's own
   configuration (for example `jss_url` in
   `/Library/Preferences/com.jamfsoftware.jamf.plist`). Your organisation's
   private Jamf Pro domain is included here, which is what actually stops
   check-ins. Only values found in *Jamf's own* config files are trusted this
   way; anything found by scanning other files must belong to a Jamf-owned
   domain (`*.jamfcloud.com`, `*.jamf.com`, …).

Optional extras (`--include-optional`): download, update, marketing and shop
endpoints.

On **Windows**, in addition to the hosts layer, the tool creates one
**outbound, per-program block rule** for every Jamf executable it finds
(`netsh advfirewall`), named `JamfDisabler-BLOCK-<program>-<hash>`. They are
listed in `wf.msc`, recorded in the state file, and deleted by
`jamfdisabler off`. macOS and Linux cannot do this — see
[Limitations](#limitations-and-honesty-section).

The full catalogue, with sources, is in [docs/ENDPOINTS.md](docs/ENDPOINTS.md).

---

## What it does *not* do

This is the part most "Jamf removal scripts" get wrong. JamfDisabler will not:

- ❌ delete, move, rename or modify **configuration profiles** or `.mobileconfig`
  files (not even the Jamf one)
- ❌ un-enrol the device or remove the MDM enrolment
- ❌ delete `/Library/Application Support/Jamf`, `C:\Program Files\Jamf`, or any
  other application files
- ❌ stop, disable or unload a **service/launch daemon/scheduled task**
- ❌ touch, rewrite or reformat any hosts entry it did not write
- ❌ install a persistence mechanism (no launch agent, no service, no startup
  entry, no kernel extension)
- ❌ hide itself, rename files, or make changes you cannot see and reverse
- ❌ require any dependency, or contact any server itself

Those things break machines, break other people's data, and cannot be undone.
If you want Jamf *gone* rather than *silenced*, ask your IT department — this
tool intentionally does not do that.

---

## How it stays harmless

Five concrete mechanisms, all covered by the test suite:

1. **Marker-scoped removal.** Everything we add lives between
   `# >>> JamfDisabler block ... >>>` and `# <<< JamfDisabler block - end <<<`.
   `off` removes only lines inside that region — and inside it, only lines that
   map a Jamf hostname to a sinkhole address. Anything else you put there is
   preserved.
2. **Pristine backup.** Before the first change, the original hosts file is
   copied to the state directory (unchanged, including its mode). `off` verifies
   the result against it and reports whether it managed a byte-for-byte restore.
   If something else edited the file while the block was active, your newer edits
   win: only our own lines are removed, and the tool tells you so.
3. **Atomic writes.** The hosts file is written through a temporary file in the
   same directory followed by a rename, so a crash or power loss can never leave
   it half-written. Permissions and, on Unix, ownership are preserved. Symlinked
   hosts files (some distros) are followed rather than replaced.
4. **Nothing is deleted.** Not one file, profile or service is removed by `on`,
   `off`, `status` or `scan`.
5. **Everything is reversible.** `jamfdisabler off` (or `restore-backup`) puts
   your machine back; deleting the executable afterwards leaves no trace except
   the state directory listed below, which you can delete by hand.

State (backup + manifest + log) lives in:

| Platform | Location |
|---|---|
| macOS | `/var/db/JamfDisabler/` |
| Windows | `C:\ProgramData\JamfDisabler\` |
| Linux | `/var/lib/JamfDisabler/` |

Full details, including the exact manifest schema: [docs/SAFETY.md](docs/SAFETY.md).

---

## The full build (single-file executables)

The repository ships a build pipeline so you (or CI) can produce a **stand-alone
executable** — no Python, no dependencies, one file.

```bash
python scripts/build.py                 # -> dist/JamfDisabler  (or .exe)
python scripts/build.py --onedir        # a folder, starts a bit faster
python scripts/build.py --zipapp        # -> dist/JamfDisabler.pyz (no PyInstaller needed)
python scripts/build.py --clean         # wipe build/ and dist/ first
```

If PyInstaller is not an option (no compiler, corporate policy, exotic CPU),
`--zipapp` produces **one portable file** that needs nothing but a Python 3.8+
interpreter on the target machine — 40 kB instead of 12 MB:

```bash
python scripts/build.py --zipapp
./dist/JamfDisabler.pyz on            # macOS / Linux
python dist\JamfDisabler.pyz on        # Windows
```

Requirements: Python 3.8+ and `pip install pyinstaller` (or
`pip install -e ".[build]"`). PyInstaller cannot cross-compile, so run it on the
OS you are targeting.

Prebuilt binaries are produced by GitHub Actions
([`.github/workflows/build.yml`](.github/workflows/build.yml)) on macOS
(arm64 + Intel), Windows and Linux, attached to every
[release](https://github.com/BestCheatsEver/JamfDisabler/releases):

| Platform | Asset |
|---|---|
| macOS Apple silicon | `JamfDisabler-macos-arm64` |
| macOS Intel | `JamfDisabler-macos-x86_64` (built on `macos-15-intel`) |
| Windows 10/11 x64 | `JamfDisabler-windows-x86_64.exe` |
| Linux x86_64 | `JamfDisabler-linux-x86_64` |
| Any OS with Python | `JamfDisabler.pyz` (portable single file) |

Tag a release to publish them all at once:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

To cut a release by hand, run the **build** workflow from the Actions tab (it
attaches artifacts even without a tag).

The binaries are not code-signed, so Windows SmartScreen and macOS Gatekeeper
will warn the first time. On macOS, right-click → *Open*, or
`xattr -d com.apple.quarantine JamfDisabler-macos-arm64`. On Windows,
*More info* → *Run anyway*. Every byte of source that goes into them is in this
repository, and you can always build your own with one command.

---

## Verify it works

Trust, but verify — the tool is designed to make this easy.

```bash
$ jamfdisabler status
  ✔ State: BLOCKING (76 entries active)

$ jamfdisabler status --verify-dns       # ask the OS resolver where names point
  ✔ telemetry.jamfcloud.com -> sinkhole
  ✔ metrics.jamfcloud.com -> sinkhole
```

Manual checks:

```bash
# macOS / Linux
getent hosts telemetry.jamfcloud.com      # -> 0.0.0.0 (or nothing at all)

# Windows PowerShell
Resolve-DnsName telemetry.jamfcloud.com   # -> 0.0.0.0

# the Jamf agent will now fail fast, locally
sudo /usr/local/bin/jamf checkJSSConnection
```

`jamfdisabler scan` (read-only) also prints the Jamf files, the running Jamf
processes and the server hostname this machine was configured for, so you can
see what you are dealing with *before* changing anything.

---

## Troubleshooting

**"Permission denied" / nothing happens.**
The hosts file needs admin rights. Re-run with `sudo` (macOS/Linux) or from an
Administrator terminal / *Run as administrator* (Windows). The tool asks for
elevation automatically when it can, and tells you the exact command when it
cannot.

**The block is on, but Jamf still seems to talk to something.**
Run `jamfdisabler status` and look at `Entries in block` vs `Recorded entries`.
Then check the three usual suspects:

1. **DNS over HTTPS / a VPN or a private DNS resolver** that ignores the hosts
   file. Turn DoH off in your browser/OS resolver, or use the Windows firewall
   layer (`jamfdisabler on` with the firewall enabled) which works regardless of
   DNS.
2. **A hard-coded IP address** — the hosts file only redirects *names*. Only the
   Windows firewall layer stops IP-literal traffic.
3. **Another device** (a different Mac, an iPhone, the Jamf server itself) is
   still reporting. This tool only affects the computer it runs on.

**Jamf came back / the machine got managed again.**
`status` will show `PARTIAL` if something rewrote our lines. Re-run
`jamfdisabler on` — it re-applies idempotently. Some management suites periodically
re-assert the hosts file; the Windows firewall layer survives that.

**The hosts file changed while the block was active.**
`off` refuses to overwrite your newer edits: it removes only our lines and tells
you it did a safe merge. Use `jamfdisabler off --restore-backup` to force the
original file back (this discards those edits), or `jamfdisabler restore-backup`.

**I want to be certain nothing is left behind.**
`jamfdisabler off` then `jamfdisabler status` (expect `State: OFF`), and delete
the state directory from the table above. That removes the only files this tool
ever created.

**Undo everything and walk away.**
```bash
sudo jamfdisabler off          # block removed, firewall rules deleted
sudo rm -rf /var/db/JamfDisabler     # macOS (see table for other OSes)
rm ~/.local/bin/jamfdisabler   # or wherever you installed the binary
```

---

## Limitations and honesty section

Nothing that only edits a hosts file can be a perfect firewall, and pretending
otherwise would be dishonest:

- **Names, not addresses.** The hosts layer stops connections to *hostnames*.
  Traffic straight to an IP, or through a DoH resolver that ignores the hosts
  file, is unaffected. The optional Windows firewall layer is the answer to
  both, and it exists only on Windows because macOS/Linux have no supported
  per-application outbound block that a tool like this can create and cleanly
  remove.
- **Application Transport Security / certificate pinning** is not involved
  either way: we block before the connection is attempted.
- **Other devices are not affected.** Each machine needs its own copy.
- **Managed machines.** If the Mac has a `profiles` enrolment, the MDM push
  channel (APNs, `*.push.apple.com`) is untouched by design — we do not touch
  Apple's infrastructure. The agent simply cannot reach its Jamf server.
- **It is not undetectable, and it is not meant to be.** Everything is labelled
  with the tool's name; `status`, `scan` and `off` are all available to whoever
  administers the machine.
- **Nothing here defeats management permanently.** Re-enrolling, re-running the
  management agent with a cached config, or a reinstall restores normal
  behaviour — usually as soon as you run `jamfdisabler off`.

---

## Legal and ethical note

JamfDisabler is a **privacy tool for computers you own or are authorised to
administer**. Use it to stop telemetry and management traffic on your own
hardware, in a lab, or in a VM you control.

If the machine is owned by your school or employer, managing it is usually a
condition of using it (and often a licensing requirement). Blocking the agent
there may break agreements you have with them, could be against their policy,
and can leave the machine unpatched or out of compliance. Prefer talking to your
IT department; this tool deliberately does not make itself hard to find or
impossible to undo.

Licensed under the [MIT License](LICENSE). No warranty of any kind.

---

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest            # 90+ tests, no network, no root needed
ruff check .
ruff format --check .
```

Layout:

```
jamfdisabler/
  cli.py         argument parsing, commands, interactive menu, exit codes
  ops.py         enable / disable / status / scan orchestration
  hosts.py       hosts-file surgery (marker-scoped, atomic, byte-exact restore)
  endpoints.py   the Jamf endpoint catalogue + hostname normalisation
  firewall.py    Windows-only per-program outbound rules (netsh)
  elevate.py     self-elevation on macOS / Windows / Linux
  state.py       backup + manifest (JSON) + audit log
  sysinfo.py     platform bits: Jamf footprint discovery, DNS flush, privileges
  console.py     tiny terminal helper (colour, prompts, log tee)
scripts/
  build.py       PyInstaller build for the current platform
  entry_point.py launcher used by the executables
tests/           92 tests: hosts round-trips, safety gates, CLI, end-to-end
```

Contributions that make the tool *more* reversible, *less* destructive or
*better documented* are very welcome. Features that delete, hide or permanently
disable things are out of scope by design.
