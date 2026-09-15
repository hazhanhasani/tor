import base64

from torpanel.xui import (
    build_synced_config,
    derive_managed_inbound_password,
    managed_inbound_payload,
    normalize_api_token,
)


def fake_decrypt(value):
    return "secret"


def test_sync_preserves_unmanaged_and_puts_api_first():
    original = {
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}, {"tag": "torloc-old", "protocol": "shadowsocks", "settings": {}}],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "outboundTag": "torloc-old", "inboundTag": ["old"]},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
        ]},
    }
    locations = [{"slug": "de-123", "name": "Germany", "enabled": True, "inbound_tags": ["inbound-1"],
                  "gateway_port": 31001, "xui_inbound_port": 22001,
                  "ss_method": "2022-blake3-aes-128-gcm", "ss_password": "enc"}]
    result = build_synced_config(original, locations, "203.0.113.5", fake_decrypt)
    tags = [x.get("tag") for x in result["outbounds"]]
    assert "direct" in tags and "torloc-old" not in tags and "torloc-de-123" in tags
    rules = result["routing"]["rules"]
    assert rules[0]["outboundTag"] == "api"
    assert rules[1]["outboundTag"] == "torloc-de-123"
    assert rules[1]["inboundTag"] == ["torloc-in-de-123", "inbound-1"]
    assert rules[-1]["outboundTag"] == "blocked"


def test_outbound_and_managed_route_exist_without_manual_inbounds():
    original = {"outbounds": [], "routing": {"rules": []}}
    locations = [{"slug": "de-auto", "name": "Germany", "enabled": True, "inbound_tags": [],
                  "gateway_port": 31001, "xui_inbound_port": 22001,
                  "ss_method": "2022-blake3-aes-128-gcm", "ss_password": "enc"}]
    result = build_synced_config(original, locations, "203.0.113.5", fake_decrypt)
    assert result["outbounds"][0]["tag"] == "torloc-de-auto"
    assert result["routing"]["rules"][0]["inboundTag"] == ["torloc-in-de-auto"]
    assert result["routing"]["rules"][0]["outboundTag"] == "torloc-de-auto"


def test_disabled_location_is_not_added():
    original = {"outbounds": [], "routing": {"rules": []}}
    locations = [{"slug": "nl-x", "name": "NL", "enabled": False, "inbound_tags": ["x"], "gateway_port": 31002,
                  "xui_inbound_port": 22002,
                  "ss_method": "2022-blake3-aes-128-gcm", "ss_password": "enc"}]
    result = build_synced_config(original, locations, "host", fake_decrypt)
    assert result["outbounds"] == []
    assert result["routing"]["rules"] == []


def test_managed_inbound_uses_separate_deterministic_ss2022_key():
    loc = {
        "id": 1,
        "slug": "de-test",
        "name": "Germany",
        "country_code": "DE",
        "xui_inbound_port": 22001,
        "ss_password": "encrypted-gateway-secret",
    }
    first = derive_managed_inbound_password(loc, fake_decrypt)
    second = derive_managed_inbound_password(loc, fake_decrypt)
    assert first == second
    assert len(base64.b64decode(first)) == 32
    payload = managed_inbound_payload(loc, fake_decrypt)
    assert payload["protocol"] == "shadowsocks"
    assert payload["tag"] == "torloc-in-de-test"
    assert payload["port"] == 22001
    assert payload["settings"]["method"] == "2022-blake3-aes-256-gcm"
    assert payload["settings"]["password"] == first
    assert payload["settings"]["password"] != fake_decrypt(loc["ss_password"])


def test_normalize_api_token_accepts_raw_and_bearer():
    assert normalize_api_token(" abc123 ") == "abc123"
    assert normalize_api_token("Bearer abc123") == "abc123"
    assert normalize_api_token("bearer   abc123 ") == "abc123"
