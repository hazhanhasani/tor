import pytest

from torpanel.warp import WarpAssistError, normalize_warp_domains, xray_domain_rules


def test_normalize_warp_domains_accepts_urls_wildcards_and_deduplicates():
    result = normalize_warp_domains(
        "https://check-host.net/path\n*.example.com\nEXAMPLE.com.\n# comment"
    )
    assert result == ["check-host.net", "example.com"]
    assert xray_domain_rules(result) == ["domain:check-host.net", "domain:example.com"]


def test_normalize_warp_domains_rejects_invalid_host():
    with pytest.raises(WarpAssistError):
        normalize_warp_domains("not a domain")
