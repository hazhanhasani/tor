from torpanel.xui import build_synced_config


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
                  "gateway_port": 31001, "ss_method": "2022-blake3-aes-128-gcm", "ss_password": "enc"}]
    result = build_synced_config(original, locations, "203.0.113.5", fake_decrypt)
    tags = [x.get("tag") for x in result["outbounds"]]
    assert "direct" in tags and "torloc-old" not in tags and "torloc-de-123" in tags
    rules = result["routing"]["rules"]
    assert rules[0]["outboundTag"] == "api"
    assert rules[1]["outboundTag"] == "torloc-de-123"
    assert rules[-1]["outboundTag"] == "blocked"


def test_disabled_location_is_not_added():
    original = {"outbounds": [], "routing": {"rules": []}}
    locations = [{"slug": "nl-x", "name": "NL", "enabled": False, "inbound_tags": ["x"], "gateway_port": 31002,
                  "ss_method": "2022-blake3-aes-128-gcm", "ss_password": "enc"}]
    result = build_synced_config(original, locations, "host", fake_decrypt)
    assert result["outbounds"] == []
    assert result["routing"]["rules"] == []
