# The Jamf endpoint catalogue

Everything JamfDisabler blocks is a hostname owned and operated by Jamf. Nothing
else can enter the block: the safety gates in `jamfdisabler/ops.py`
(`_safe_to_block`) and `jamfdisabler/endpoints.py` (`is_jamf_hostname`,
`filter_jamf_only`) reject anything that is not recognisably Jamf's, plus a short
deny-list of OS/cloud infrastructure (`apple.com`, `icloud.com`, `google.com`,
`microsoft.com`, `amazonaws.com`, `akamai.net`, `windowsupdate.com`) and any bare
IP address.

`jamfdisabler list` prints the live list for your platform and options.

---

## Recognised Jamf-owned domains

Only hostnames under these registrable domains can ever be blocked
automatically:

```
jamfcloud.com      jamf.com        jamfsw.com       jamfsoftware.com
jamfschool.com     jamfnow.com     jamfconnect.com  jamfprotect.com
zuludesk.com
```

An organisation's *own* Jamf Pro domain (for example `mdm.mycompany.com`) is
different: it is only ever blocked when it was read out of **Jamf's own
configuration files**, because that is the machine telling us where its
management server lives.

---

## Group 1 — core (always blocked)

| Hostname | Why |
|---|---|
| `telemetry.jamfcloud.com`, `metrics.jamfcloud.com`, `analytics.jamfcloud.com`, `pendo.jamfcloud.com`, `updates.jamfcloud.com` | Jamf's telemetry / "customer experience" reporting endpoints |
| `patch.jamfcloud.com`, `jamf-patch.jamfcloud.com` | patch-reporting lookups for the software update catalogue |
| `hw-model-names.services.jamfcloud.com` | hardware model-name service |
| `csa.services.jamfcloud.com`, `ics.services.jamfcloud.com` | Jamf Cloud Services connection used by the Jamf Pro server |
| `jamfpush.jamfcloud.com`, `resources.jamfcloud.com` | push proxy and hosted resources |
| `use1-jcds.services.jamfcloud.com`, `use1-jcdsdownloads.services.jamfcloud.com` (and the `euc1-`, `euw2-`, `apne1-`, `apse2-` equivalents) | Jamf Cloud Distribution Points — package and app downloads |
| `account.jamf.com`, `id.jamf.com`, `auth.jamfcloud.com`, `login.jamfcloud.com`, `my.jamf.com` | Jamf account / SSO endpoints used by the agent and admin tools |
| `jamf.com`, `www.jamf.com`, `docs.jamf.com`, `learn.jamf.com`, `support.jamf.com`, `community.jamf.com`, `nation.jamf.com`, `jamfnation.jamfsoftware.com`, `resources.jamf.com`, `trust.jamf.com`, `status.jamf.com`, `trainingcatalog.jamf.com`, `cdn.jamf.com` | Jamf's own web properties (help, status, docs, CDN) |

## Group 2 — other Jamf products (blocked by default, `--no-products` to skip)

| Hostname | Product |
|---|---|
| `protect.jamfcloud.com`, `*.protect.jamfcloud.com`, `protect.jamf.com`, `jamfprotect.com` | Jamf Protect |
| `connect.jamfcloud.com`, `jamfconnect.com` | Jamf Connect |
| `school.jamfcloud.com`, `jamfschool.com`, `jamfnow.com`, `zuludesk.com` | Jamf School / Jamf Now / ZuluDesk |
| `setup.jamfcloud.com`, `reset.jamfcloud.com`, `jamfsetup.jamfcloud.com`, `jamfreset.jamfcloud.com`, `business.jamfcloud.com` | Setup / Reset / Business Plan helpers used during enrolment |
| `jamfsw03.jamfsoftware.com`, `jamfsoftware.com`, `casper.jamfsoftware.com` | legacy Jamf Software / Casper Suite names |

`*.*` wildcards in the source list are expanded into concrete names (the base
domain plus common service prefixes) because some resolvers ignore wildcard
entries in a hosts file, and because a concrete list is auditable.

## Group 3 — detected on your machine (blocked by default)

Read from Jamf's own configuration, for example:

| Source | Key | Example value |
|---|---|---|
| `/Library/Preferences/com.jamfsoftware.jamf.plist` (macOS) | `jss_url` | `https://yourorg.jamfcloud.com/` |
| `/Library/Managed Preferences/com.jamfsoftware.jamf.plist` | `jss_url` | same, pushed by a profile |
| `/Library/Application Support/Jamf/**/*.plist` (with `--deep-scan`) | any `*url*`, `*server*`, `*host*` key | e.g. a patch server |
| `C:\ProgramData\Jamf\**\*.plist` / `*.json` (Windows, with `--deep-scan`) | same | same |

Values from these files are treated as *trusted*: an organisation running its own
Jamf Pro instance on a private domain is exactly the case that matters most, and
the value came from Jamf itself.

Everything else found by scanning is only accepted when it matches one of the
Jamf-owned domains above.

Keys whose name contains `jss`, `server`, `mdm`, `management` or `enroll` are
tier 1 (blocked); other URL-ish keys are tier 2 (reported by `scan`, blocked with
`--all-detected`), so a stray reference in a Jamf config file cannot silently
block something unexpected.

## Group 4 — optional (`--include-optional`)

Download, update, marketing, events and shop endpoints
(`downloads.jamfcloud.com`, `cdn.jamfcloud.com`, `assets.jamf.com`,
`images.jamf.com`, `info.jamf.com`, `pages.jamf.com`, `go.jamf.com`,
`get.jamf.com`, `content.jamf.com`, `marketing.jamf.com`, `events.jamf.com`,
`jobs.jamf.com`, `careers.jamf.com`, `shop.jamf.com`, `store.jamf.com`,
`trial.jamf.com`, `sandbox.jamfcloud.com`, `partner.jamf.com`,
`partners.jamf.com`).

Off by default: these are the endpoints most likely to be needed for a
legitimate download or a re-enrolment, and blocking them buys little privacy.

## Endpoints that are deliberately *not* blocked

| Endpoint | Reason |
|---|---|
| `*.push.apple.com`, `*.push-apple.com.akadns.net` | Apple Push Notification service — used by MDM *and* by your iMessage, Mail, calendar and other apps. Blocking it breaks unrelated Apple services. |
| `*.apple.com`, `swscan.apple.com`, `gs.apple.com` | Apple software update, certificate validation, activation |
| `*.microsoft.com`, `login.microsoftonline.com`, `graph.microsoft.com` | Microsoft/Intune endpoints that some organisations legitimately use; blocking them would be out of scope |
| Your local network, DNS servers, NTP | out of scope and would break the machine |

## Add your own

```bash
jamfdisabler on --add-host custom.jamfcloud.com --add-host mdm.mycompany.com
JAMFDISABLER_EXTRA_HOSTS="a.jamfcloud.com,b.jamfcloud.com" jamfdisabler on
```

Explicit hostnames are honoured (including private domains), but IP literals and
the OS/cloud infrastructure deny-list are still refused with a printed reason —
blocking `swscan.apple.com` would break your machine's updates, so the tool says
no rather than obeying.

## Sources

The catalogue was compiled from Jamf's own documentation and network
requirements:

* Jamf Pro — *Permitting Inbound/Outbound Traffic with Jamf Cloud*: the cloud
  distribution point hostnames (`use1-jcds…`, `euc1-jcds…`, `euw2-jcds…`,
  `apne1-jcds…`, `apse2-jcds…`) and the outbound IP ranges.
* Jamf Pro — *Network Ports Used by Jamf Pro*: `jamf-patch.jamfcloud.com`,
  `hw-model-names.services.jamfcloud.com`, `csa.services.jamfcloud.com`,
  `ics.services.jamfcloud.com`, customer-experience-metrics submissions.
* Jamf School — *Firewall Ports, IP Addresses and URLs*: the `*.jamfcloud.com`
  wildcard requirement and `school.jamfcloud.com`.
* Jamf community/technical notes: `*.protect.jamfcloud.com` for Jamf Protect.

Because Jamf can add hostnames at any time, the catalogue lives in one small file
(`jamfdisabler/endpoints.py`) and is covered by tests — pull requests that add
documented endpoints, with the source in the description, are welcome.
