"""The endpoint catalogue must only ever contain Jamf-owned names."""

from __future__ import annotations

import pytest

from jamfdisabler import endpoints


def test_normalise_variants():
    assert endpoints.normalise_hostname("https://Org.jamfcloud.com/") == "org.jamfcloud.com"
    assert endpoints.normalise_hostname("http://org.jamfcloud.com:8443/path?x=1") == "org.jamfcloud.com"
    assert endpoints.normalise_hostname("  org.jamfcloud.com.  ") == "org.jamfcloud.com"
    assert endpoints.normalise_hostname("user:pw@org.jamfcloud.com") == "org.jamfcloud.com"
    assert endpoints.normalise_hostname("[::1]:443") == "::1" or endpoints.normalise_hostname("[::1]:443") == ""
    assert endpoints.normalise_hostname("not a host") == ""
    assert endpoints.normalise_hostname("single") == ""
    assert endpoints.normalise_hostname("") == ""
    assert endpoints.normalise_hostname("org.jamfcloud.com#comment") == "org.jamfcloud.com"


def test_is_jamf_hostname():
    assert endpoints.is_jamf_hostname("org.jamfcloud.com")
    assert endpoints.is_jamf_hostname("deep.sub.jamfcloud.com")
    assert endpoints.is_jamf_hostname("jamf.com")
    assert endpoints.is_jamf_hostname("myorg.mycompany.com") is False
    assert endpoints.is_jamf_hostname("notjamf.com") is False
    assert endpoints.is_jamf_hostname("") is False


def test_filter_jamf_only_drops_everything_else():
    given = ["a.jamfcloud.com", "evil.com", "jamf.com", "apple.com", "protect.jamfcloud.com"]
    assert endpoints.filter_jamf_only(given) == [
        "a.jamfcloud.com",
        "jamf.com",
        "protect.jamfcloud.com",
    ]


def test_catalogue_contains_no_third_party_domains():
    """Safety: we must never ship a hostname that is not Jamf's."""
    for name in endpoints.all_known_hostnames():
        assert endpoints.is_jamf_hostname(name), "catalogue contains non-Jamf host: {}".format(name)


def test_catalogue_never_contains_wildcards():
    for name in endpoints.all_known_hostnames():
        assert "*" not in name


def test_catalogue_has_no_duplicates_and_is_sorted():
    names = endpoints.all_known_hostnames()
    assert names == sorted(set(names))


def test_option_toggles_change_the_list():
    core_only = endpoints.default_hostnames(include_products=False, include_optional=False)
    with_products = endpoints.default_hostnames(include_products=True, include_optional=False)
    with_optional = endpoints.default_hostnames(include_products=True, include_optional=True)
    assert set(core_only) < set(with_products) < set(with_optional)
    assert "telemetry.jamfcloud.com" in core_only
    assert "www.jamfprotect.com" in with_products
    assert "downloads.jamfcloud.com" in with_optional


def test_wildcards_expand_to_concrete_names():
    expanded = endpoints._expand(["*.protect.jamfcloud.com"])
    assert "protect.jamfcloud.com" in expanded
    assert "www.protect.jamfcloud.com" in expanded
    assert all(not name.startswith("*.") for name in expanded)


def test_extra_and_auto_detected_are_merged_and_normalised():
    names = endpoints.default_hostnames(
        include_products=False,
        extra=["HTTPS://Extra.Jamfcloud.com/x"],
        auto_detected=["https://MyOrg.jamfcloud.com/"],
    )
    assert "extra.jamfcloud.com" in names
    assert "myorg.jamfcloud.com" in names
    assert names == sorted(set(names))


def test_default_hostnames_rejects_garbage():
    names = endpoints.default_hostnames(extra=["", "not a hostname", "../../etc/passwd"])
    for bad in ("../../etc/passwd", "not a hostname"):
        assert bad not in names


@pytest.mark.parametrize(
    "host",
    [
        "telemetry.jamfcloud.com",
        "metrics.jamfcloud.com",
        "patch.jamfcloud.com",
        "analytics.jamfcloud.com",
        "use1-jcdsdownloads.services.jamfcloud.com",
    ],
)
def test_known_telemetry_endpoints_present(host):
    assert host in endpoints.all_known_hostnames()
