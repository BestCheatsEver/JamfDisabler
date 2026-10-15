"""The Jamf endpoint catalogue that gets written into the hosts file.

Everything listed here is a hostname owned and operated by Jamf.  We *sinkhole*
those names (point them at 0.0.0.0/::), which means the operating system never
sends a single packet to them - the Jamf agent simply gets "connection refused"
locally instead of reaching Jamf's servers.

The lists are split so the user can pick a level:

``core``      - management / inventory / telemetry endpoints.  Blocking these
                stops check-ins, inventory uploads and usage reporting.  This
                is the default and is what "stops Jamf talking to its servers".
``products``  - other Jamf products (Protect, Connect, School, ...).  Also
                blocked by default; harmless if you do not have them.
``optional``  - download / update / marketing endpoints.  Blocked on request
                (``--include-optional``) because they are the ones most likely
                to be needed by a legitimate app install or re-enrolment.

Wildcards in the list (``*.services.jamfcloud.com``) are expanded into the
concrete host names Jamf documents.  We deliberately avoid writing wildcards
themselves into ``hosts`` - some resolvers ignore them and they hide which
names are actually covered.

Nothing here is ever *deleted* from the machine: no profiles, no agents, no
files.  Blocking a name only changes where the name resolves to.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence, Set

# --------------------------------------------------------------------------- #
# Registrable domains owned by Jamf.  Used as an allow-list when we auto-detect
# an organisation's own Jamf server so we can never block an unrelated domain.
# --------------------------------------------------------------------------- #
JAMF_DOMAINS: Sequence[str] = (
    "jamfcloud.com",
    "jamf.com",
    "jamfsw.com",
    "jamfsoftware.com",
    "jamfschool.com",
    "jamfnow.com",
    "jamfconnect.com",
    "jamfprotect.com",
    "zuludesk.com",
)

CORE_HOSTNAMES: Sequence[str] = (
    # Telemetry / analytics / "customer experience" reporting
    "metrics.jamfcloud.com",
    "telemetry.jamfcloud.com",
    "analytics.jamfcloud.com",
    "pendo.jamfcloud.com",
    "updates.jamfcloud.com",
    # Jamf-hosted services the agent and Jamf Pro server call out to
    "patch.jamfcloud.com",
    "jamf-patch.jamfcloud.com",
    "hw-model-names.services.jamfcloud.com",
    "csa.services.jamfcloud.com",
    "ics.services.jamfcloud.com",
    "resources.jamfcloud.com",
    "jamfpush.jamfcloud.com",
    # Jamf Pro cloud distribution points (package/download traffic)
    "use1-jcds.services.jamfcloud.com",
    "use1-jcdsdownloads.services.jamfcloud.com",
    "euc1-jcds.services.jamfcloud.com",
    "euc1-jcdsdownloads.services.jamfcloud.com",
    "euw2-jcds.services.jamfcloud.com",
    "euw2-jcdsdownloads.services.jamfcloud.com",
    "apne1-jcds.services.jamfcloud.com",
    "apne1-jcdsdownloads.services.jamfcloud.com",
    "apse2-jcds.services.jamfcloud.com",
    "apse2-jcdsdownloads.services.jamfcloud.com",
    # Jamf web properties / account services / docs
    "www.jamf.com",
    "jamf.com",
    "my.jamf.com",
    "account.jamf.com",
    "id.jamf.com",
    "auth.jamfcloud.com",
    "login.jamfcloud.com",
    "docs.jamf.com",
    "learn.jamf.com",
    "community.jamf.com",
    "nation.jamf.com",
    "jamfnation.jamfsoftware.com",
    "resources.jamf.com",
    "trust.jamf.com",
    "status.jamf.com",
    "trainingcatalog.jamf.com",
    "support.jamf.com",
    "cdn.jamf.com",
)

PRODUCT_HOSTNAMES: Sequence[str] = (
    # Jamf Protect
    "*.protect.jamfcloud.com",
    "protect.jamfcloud.com",
    "protect.jamf.com",
    "jamfprotect.com",
    "www.jamfprotect.com",
    # Jamf Connect
    "connect.jamfcloud.com",
    "jamfconnect.com",
    "www.jamfconnect.com",
    # Jamf School / Jamf Now / Zuludesk
    "school.jamfcloud.com",
    "jamfschool.com",
    "www.jamfschool.com",
    "jamfnow.com",
    "www.jamfnow.com",
    "zuludesk.com",
    "www.zuludesk.com",
    # Jamf Business Plan / Setup / Reset / Configurator helpers
    "setup.jamfcloud.com",
    "reset.jamfcloud.com",
    "business.jamfcloud.com",
    "jamfsetup.jamfcloud.com",
    "jamfreset.jamfcloud.com",
    # Legacy Jamf Software / Casper Suite host names
    "jamfsw03.jamfsoftware.com",
    "jamfsoftware.com",
    "www.jamfsoftware.com",
    "casper.jamfsoftware.com",
)

OPTIONAL_HOSTNAMES: Sequence[str] = (
    "downloads.jamfcloud.com",
    "cdn.jamfcloud.com",
    "assets.jamf.com",
    "images.jamf.com",
    "info.jamf.com",
    "pages.jamf.com",
    "go.jamf.com",
    "get.jamf.com",
    "content.jamf.com",
    "marketing.jamf.com",
    "events.jamf.com",
    "jobs.jamf.com",
    "careers.jamf.com",
    "shop.jamf.com",
    "store.jamf.com",
    "trial.jamf.com",
    "sandbox.jamfcloud.com",
    "partner.jamf.com",
    "partners.jamf.com",
)

#: Well-known Jamf Cloud hostnames used for discovery/help output.
KNOWN_CLOUD_SUFFIX = "jamfcloud.com"

BLOCK_IPV4 = "0.0.0.0"  # noqa: S104 - a hosts-file address, not a socket bind
BLOCK_IPV6 = "::"


def _expand(entries: Iterable[str]) -> List[str]:
    """Turn wildcard entries into the concrete names Jamf documents."""
    expanded: List[str] = []
    for entry in entries:
        entry = entry.strip().lower().rstrip(".")
        if not entry:
            continue
        if entry.startswith("*."):
            base = entry[2:]
            expanded.append(base)
            for prefix in (
                "www",
                "api",
                "cdn",
                "eu",
                "us",
                "ap",
                "app",
                "admin",
                "downloads",
                "enroll",
                "mdm",
                "push",
                "static",
            ):
                expanded.append("{}.{}".format(prefix, base))
        else:
            expanded.append(entry)
    return expanded


def default_hostnames(
    include_products: bool = True,
    include_optional: bool = False,
    extra: Sequence[str] = (),
    auto_detected: Sequence[str] = (),
) -> List[str]:
    """Build the sorted, de-duplicated list of hostnames to sinkhole."""
    names: Set[str] = set(_expand(CORE_HOSTNAMES))
    if include_products:
        names.update(_expand(PRODUCT_HOSTNAMES))
    if include_optional:
        names.update(_expand(OPTIONAL_HOSTNAMES))
    for name in list(auto_detected) + list(extra):
        cleaned = normalise_hostname(name)
        if cleaned:
            names.add(cleaned)
    return sorted(names)


def normalise_hostname(value: str) -> str:
    """Extract a bare hostname from a URL, host or ``host:port`` string.

    Returns ``""`` when the value does not look like a hostname.
    """
    if not value:
        return ""
    text = str(value).strip().strip("\"'")
    text = text.split("#", 1)[0].strip()
    for scheme in ("https://", "http://", "ftp://"):
        if text.lower().startswith(scheme):
            text = text[len(scheme) :]
            break
    # strip path/query
    for sep in ("/", "?", " "):
        if sep in text:
            text = text.split(sep, 1)[0]
    # strip credentials
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    # strip port
    if text.startswith("["):  # [::1]:443
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        host, _, port = text.partition(":")
        if port.isdigit():
            text = host
    text = text.strip().strip(".").lower()
    if not text or len(text) > 253:
        return ""
    if " " in text or any(ch in text for ch in ("\\", "/", "\n", "\t")):
        return ""
    if "." not in text:
        return ""
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-._")
    if any(ch not in allowed for ch in text):
        return ""
    return text


def is_jamf_hostname(hostname: str) -> bool:
    """True when ``hostname`` belongs to a Jamf-owned registrable domain.

    This is the safety gate for auto-detected servers: JamfDisabler will never
    block a hostname that is not recognisably Jamf's.
    """
    host = normalise_hostname(hostname)
    if not host:
        return False
    return any(host == d or host.endswith("." + d) for d in JAMF_DOMAINS)


def filter_jamf_only(hostnames: Iterable[str]) -> List[str]:
    """Return only the Jamf-owned names from ``hostnames`` (de-duplicated)."""
    out: Set[str] = set()
    for name in hostnames:
        if is_jamf_hostname(name):
            out.add(normalise_hostname(name))
    return sorted(n for n in out if n)


def all_known_hostnames() -> List[str]:
    """Every hostname the catalogue can block (used by ``jamfdisabler list``)."""
    return default_hostnames(include_products=True, include_optional=True)


def catalogue_groups() -> List[tuple]:
    """Human-readable groups for ``jamfdisabler list``."""
    return [
        ("Core: management, inventory, telemetry", sorted(_expand(CORE_HOSTNAMES))),
        ("Other Jamf products", sorted(_expand(PRODUCT_HOSTNAMES))),
        ("Optional: downloads, updates, marketing", sorted(_expand(OPTIONAL_HOSTNAMES))),
    ]
