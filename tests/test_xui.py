import torpanel.xui as xui_module
import base64

from torpanel.xui import (
    XUIClient,
    XUISettings,
    build_synced_config,
    managed_inbound_payload,
    normalize_api_token,
)
from torpanel.vless import managed_inbound_reality_identity


def fake_decrypt(value):
    return "secret"


def test_sync_preserves_unmanaged_and_puts_api_first():
    original = {
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}, {"tag": "torloc-old", "protocol": "vless", "settings": {}}],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "outboundTag": "torloc-old", "inboundTag": ["old"]},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
        ]},
    }
    locations = [{"slug": "de-123", "name": "Germany", "enabled": True, "inbound_tags": ["inbound-1"],
                  "gateway_port": 31001, "xui_inbound_port": 22001,
                  "ss_method": "vless-reality", "ss_password": "enc"}]
    result = build_synced_config(original, locations, "203.0.113.5", fake_decrypt)
    tags = [x.get("tag") for x in result["outbounds"]]
    assert "direct" in tags and "torloc-old" not in tags and "torloc-de-123" in tags
    tor_out = next(x for x in result["outbounds"] if x.get("tag") == "torloc-de-123")
    assert tor_out["protocol"] == "vless"
    assert tor_out["settings"]["flow"] == "xtls-rprx-vision"
    assert tor_out["streamSettings"]["security"] == "reality"
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


def test_managed_inbound_is_vless_reality_with_stable_separate_identity():
    loc = {
        "id": 1,
        "slug": "de-test",
        "name": "Germany",
        "country_code": "DE",
        "xui_inbound_port": 22001,
        "ss_password": "encrypted-gateway-secret",
    }
    first = managed_inbound_reality_identity(loc, fake_decrypt)
    second = managed_inbound_reality_identity(loc, fake_decrypt)
    assert first == second
    payload = managed_inbound_payload(loc, fake_decrypt)
    assert payload["protocol"] == "vless"
    assert payload["tag"] == "torloc-in-de-test"
    assert payload["port"] == 22001
    assert payload["settings"]["decryption"] == "none"
    assert payload["settings"]["clients"][0]["id"] == first.client_id
    assert payload["settings"]["clients"][0]["flow"] == "xtls-rprx-vision"
    assert payload["streamSettings"]["security"] == "reality"
    assert payload["streamSettings"]["realitySettings"]["privateKey"] == first.private_key


def test_normalize_api_token_accepts_raw_and_bearer():
    assert normalize_api_token(" abc123 ") == "abc123"
    assert normalize_api_token("Bearer abc123") == "abc123"
    assert normalize_api_token("bearer   abc123 ") == "abc123"


def test_native_warp_rule_precedes_tor_and_is_idempotent():
    settings = XUISettings(
        base_url="https://panel.example.com/",
        api_token="token",
        gateway_host="203.0.113.5",
        verify_tls=True,
        managed_inbound_mode="cloudflare",
        cdn_domain="edge.example.com",
        cdn_port=8443,
        cdn_ws_path="/edge",
    )
    original = {
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "warp", "protocol": "wireguard", "settings": {"secretKey": "x"}},
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "ruleTag": "torloc-warp",
                    "inboundTag": ["torloc-cdn"],
                    "domain": ["domain:old.example"],
                    "outboundTag": "warp",
                }
            ]
        },
    }
    locations = [{
        "slug": "de-123",
        "name": "Germany",
        "enabled": True,
        "inbound_tags": [],
        "gateway_port": 31001,
        "xui_inbound_port": 0,
        "ss_method": "2022-blake3-aes-128-gcm",
        "ss_password": "enc",
    }]
    result = build_synced_config(
        original,
        locations,
        "203.0.113.5",
        fake_decrypt,
        settings,
        warp_enabled=True,
        warp_mode="domains",
        warp_domains=["check-host.net"],
        warp_inbound_tags=["torloc-cdn"],
    )
    warp_rules = [
        rule for rule in result["routing"]["rules"]
        if rule.get("ruleTag") == "torloc-warp"
    ]
    assert len(warp_rules) == 1
    assert warp_rules[0]["outboundTag"] == "warp"
    assert warp_rules[0]["inboundTag"] == ["torloc-cdn"]
    assert warp_rules[0]["domain"] == [
        "domain:check-host.net",
        "domain:challenges.cloudflare.com",
    ]
    assert result["routing"]["rules"].index(warp_rules[0]) < next(
        i for i, rule in enumerate(result["routing"]["rules"])
        if rule.get("outboundTag") == "torloc-de-123"
    )


def test_build_native_3xui_warp_outbound_shape():
    data = {
        "private_key": "private-base64",
        "client_id": base64.b64encode(bytes([1, 2, 3])).decode(),
    }
    config = {
        "config": {
            "client_id": data["client_id"],
            "interface": {
                "addresses": {
                    "v4": "172.16.0.2",
                    "v6": "2606:4700:110:8abc::2",
                }
            },
            "peers": [{
                "public_key": "peer-public",
                "endpoint": {"host": "engage.cloudflareclient.com:2408"},
            }],
        }
    }
    outbound = XUIClient.build_warp_outbound(data, config)
    assert outbound["tag"] == "warp"
    assert outbound["protocol"] == "wireguard"
    settings = outbound["settings"]
    assert settings["mtu"] == 1420
    assert settings["secretKey"] == "private-base64"
    assert settings["address"] == [
        "172.16.0.2/32",
        "2606:4700:110:8abc::2/128",
    ]
    assert settings["reserved"] == [1, 2, 3]
    assert settings["domainStrategy"] == "ForceIPv4v6"
    assert settings["noKernelTun"] is True
    assert settings["peers"] == [{
        "publicKey": "peer-public",
        "endpoint": "engage.cloudflareclient.com:2408",
    }]


def test_wireguard_keypair_is_raw_base64_32_bytes():
    private_key, public_key = XUIClient._wireguard_keypair()
    assert len(base64.b64decode(private_key)) == 32
    assert len(base64.b64decode(public_key)) == 32


def test_ensure_warp_outbound_repairs_stale_native_outbound(monkeypatch):
    client = XUIClient(XUISettings(
        base_url="https://panel.example.com/",
        api_token="token",
        gateway_host="203.0.113.5",
        verify_tls=True,
    ))
    data = {
        "private_key": "fresh-secret",
        "client_id": base64.b64encode(bytes([1, 2, 3])).decode(),
    }
    warp_cfg = {
        "config": {
            "client_id": data["client_id"],
            "interface": {"addresses": {"v4": "172.16.0.2"}},
            "peers": [{
                "public_key": "fresh-peer",
                "endpoint": {"host": "engage.cloudflareclient.com:2408"},
            }],
        }
    }
    monkeypatch.setattr(client, "warp_data", lambda: data)
    monkeypatch.setattr(client, "warp_config", lambda: warp_cfg)

    original = {
        "outbounds": [{
            "tag": "warp",
            "protocol": "wireguard",
            "settings": {
                "secretKey": "stale-secret",
                "sockopt": {"mark": 7},
            },
        }],
        "routing": {"rules": []},
    }
    updated, changed = client.ensure_warp_outbound(original)
    assert changed is True
    outbound = updated["outbounds"][0]
    assert outbound["settings"]["secretKey"] == "fresh-secret"
    assert outbound["settings"]["peers"][0]["publicKey"] == "fresh-peer"
    assert outbound["settings"]["sockopt"] == {"mark": 7}
    assert original["outbounds"][0]["settings"]["secretKey"] == "stale-secret"



def test_sync_runtime_has_set_setting_dependency():
    assert callable(xui_module.set_setting)

def test_connection_reports_sanaei_panel_and_xray_versions(monkeypatch):
    client = XUIClient(XUISettings(
        base_url="https://panel.example.com/",
        api_token="token",
        gateway_host="127.0.0.1",
        verify_tls=True,
    ))

    def fake_request(method, path, **kwargs):
        if path == "/panel/api/inbounds/options":
            return {"success": True, "obj": [{"id": 1, "tag": "in-1", "port": 443}]}
        if path == "/panel/api/server/status":
            return {"success": True, "obj": {
                "panelVersion": "3.8.5",
                "xray": {"version": "26.9.9", "state": 1},
            }}
        raise AssertionError(path)

    monkeypatch.setattr(client, "_request", fake_request)
    result = client.test_connection()
    assert result["inbound_count"] == 1
    assert result["panel_version"] == "3.8.5"
    assert result["xray_version"] == "26.9.9"


def test_connection_works_when_optional_status_endpoint_is_unavailable(monkeypatch):
    client = XUIClient(XUISettings(
        base_url="https://panel.example.com/", api_token="token",
        gateway_host="127.0.0.1", verify_tls=True,
    ))

    def fake_request(method, path, **kwargs):
        if path == "/panel/api/inbounds/options":
            return {"success": True, "obj": [{"id": 1, "tag": "in-1"}]}
        raise xui_module.XUIError("Endpoint API پیدا نشد (HTTP 404)")

    monkeypatch.setattr(client, "_request", fake_request)
    result = client.test_connection()
    assert result["inbound_count"] == 1
    assert result["panel_version"] == ""
    assert result["xray_version"] == ""


def test_reconcile_match_rejects_reality_without_3xui_public_metadata():
    loc = {
        "id": 1, "slug": "de-test", "name": "Germany", "country_code": "DE",
        "xui_inbound_port": 21000, "ss_password": "enc",
    }
    expected = managed_inbound_payload(loc, fake_decrypt)
    broken_reality = dict(expected["streamSettings"]["realitySettings"])
    broken_reality.pop("settings", None)
    broken = {
        **expected,
        "streamSettings": {**expected["streamSettings"], "realitySettings": broken_reality},
    }
    assert xui_module._inbound_matches(broken, expected) is False



def test_repair_existing_managed_payload_preserves_real_clients_and_removes_bootstrap():
    loc = {
        "id": 1,
        "slug": "fi-test",
        "name": "Finland",
        "country_code": "FI",
        "xui_inbound_port": 21001,
        "ss_password": "enc",
    }
    expected = managed_inbound_payload(loc, fake_decrypt)
    bootstrap = expected["settings"]["clients"][0]
    current = {
        **expected,
        "shareAddrStrategy": "custom",
        "shareAddr": "edge.example.com",
        "settings": {
            **expected["settings"],
            "clients": [
                {
                    "id": "11111111-2222-4333-8444-555555555555",
                    "email": "alice@example.com",
                    "flow": "",
                    "enable": True,
                    "subId": "keep-me",
                    "totalGB": 123,
                },
                bootstrap,
            ],
        },
    }

    repaired = xui_module._repair_existing_managed_payload(current, expected)
    clients = repaired["settings"]["clients"]
    assert [row["email"] for row in clients] == ["alice@example.com"]
    assert clients[0]["id"] == "11111111-2222-4333-8444-555555555555"
    assert clients[0]["subId"] == "keep-me"
    assert clients[0]["totalGB"] == 123
    assert clients[0]["flow"] == "xtls-rprx-vision"
    assert repaired["shareAddrStrategy"] == "custom"
    assert repaired["shareAddr"] == "edge.example.com"


def test_reconcile_managed_inbound_does_not_delete_existing_users(monkeypatch):
    loc = {
        "id": 7,
        "slug": "fr-test",
        "name": "France",
        "country_code": "FR",
        "enabled": True,
        "gateway_port": 31001,
        "socks_port": 19050,
        "xui_inbound_port": 21000,
        "ss_password": "enc",
        "inbound_tags": [],
    }
    expected = managed_inbound_payload(loc, fake_decrypt)
    current = {
        **expected,
        "settings": {
            **expected["settings"],
            "clients": [{
                "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "email": "real-user@example.com",
                "flow": "",
                "enable": True,
                "subId": "existing-sub",
            }],
        },
    }

    class FakeClient:
        settings = XUISettings(
            base_url="https://panel.example.com/",
            api_token="token",
            gateway_host="203.0.113.5",
            verify_tls=True,
            managed_inbound_mode="legacy",
        )

        def __init__(self):
            self.updated = None

        def list_inbounds(self):
            return [{"id": 9, "tag": "torloc-in-fr-test", "port": 21000, "protocol": "vless"}]

        def get_inbound(self, inbound_id):
            return current

        def update_inbound(self, inbound_id, payload):
            self.updated = payload
            return {}

        def delete_inbound(self, inbound_id):
            raise AssertionError("must not delete managed inbound")

    monkeypatch.setattr(xui_module, "set_location_xui_inbound_port", lambda *_: None)
    client = FakeClient()
    result = xui_module.reconcile_managed_inbounds(client, [loc], fake_decrypt)
    assert result["updated"] == 1
    assert client.updated is not None
    assert [c["email"] for c in client.updated["settings"]["clients"]] == ["real-user@example.com"]
    assert client.updated["settings"]["clients"][0]["flow"] == "xtls-rprx-vision"


def test_build_synced_config_is_idempotent_for_noop_sync():
    locations = [{
        "slug": "de-stable",
        "name": "Germany",
        "country_code": "DE",
        "enabled": True,
        "gateway_port": 31001,
        "socks_port": 19050,
        "xui_inbound_port": 21000,
        "ss_password": "enc",
        "inbound_tags": [],
    }]
    original = {
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
        "routing": {"rules": []},
    }
    first = build_synced_config(original, locations, "203.0.113.5", fake_decrypt)
    second = build_synced_config(first, locations, "203.0.113.5", fake_decrypt)
    assert second == first
