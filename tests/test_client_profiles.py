import base64
import json
import uuid

import pytest

from torpanel.client_profiles import (
    ClientProfileError, build_client_profile, parse_reality_uri, profile_json
)


URI = (
    "vless://11111111-2222-4333-8444-555555555555@203.0.113.5:21001"
    "?security=reality&encryption=none"
    "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "&fp=chrome&spx=%2Fsample&type=tcp"
    "&flow=xtls-rprx-vision&sni=www.example.com"
    "&sid=0011223344556677#Tor%20FI"
)


def test_real_user_uri_is_parsed_without_leaking_fields():
    parsed = parse_reality_uri(URI)
    assert parsed["address"] == "203.0.113.5"
    assert parsed["port"] == 21001
    assert parsed["serverName"] == "www.example.com"
    assert parsed["spiderX"] == "/sample"


def test_do_h_is_proxied_and_arbitrary_udp_is_blocked():
    config = build_client_profile(URI)
    assert config["dns"]["servers"][0]["address"].startswith("https://")
    assert config["dns"]["tag"] == "dns-module"
    assert config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert config["outbounds"][0]["mux"]["enabled"] is False
    rules = config["routing"]["rules"]
    assert rules[0]["port"] == "53"
    assert rules[0]["outboundTag"] == "dns-out"
    assert rules[1] == {"type": "field", "network": "udp", "outboundTag": "block"}
    assert rules[-1]["inboundTag"] == ["dns-module"]
    assert rules[-1]["outboundTag"] == "proxy"
    assert config["outbounds"][0]["tag"] == "proxy"
    assert all(i["listen"] == "127.0.0.1" for i in config["inbounds"])
    assert "223.5.5.5" not in profile_json(URI)
    json.loads(profile_json(URI))


@pytest.mark.parametrize("bad_uri", [
    "vless://not-a-uuid@203.0.113.5:21001?security=reality",
    "vless://11111111-2222-4333-8444-555555555555@203.0.113.5:21001?security=tls",
    URI.replace("type=tcp", "type=ws"),
    URI.replace("sid=0011223344556677", "sid=not-hex"),
    URI.replace("&fp=chrome", "&pbk=duplicate&fp=chrome"),
    URI.replace("spx=%2Fsample", "spx=not-relative"),
    URI.replace("sni=www.example.com", "sni=bad hostname"),
])
def test_invalid_or_unsupported_links_fail_closed(bad_uri):
    with pytest.raises(ClientProfileError):
        build_client_profile(bad_uri)
