import uuid

import pytest

from torpanel.xui import XUISettings, build_synced_config
from torpanel.xui_cdn import (
    CDN_MANAGED_TAG,
    CDNProfileError,
    build_cdn_inbound_payload,
    derive_vless_id,
    managed_cdn_client_uri,
    managed_client_email,
    reconcile_cdn_inbound,
)


def fake_decrypt(value):
    return "super-secret-gateway-key"


def cdn_settings():
    return XUISettings(
        base_url="https://panel.example.com:2053/secret/",
        api_token="token",
        gateway_host="127.0.0.1",
        verify_tls=True,
        managed_inbound_mode="cloudflare",
        cdn_domain="edge.example.com",
        cdn_port=8443,
        cdn_ws_path="/edge-AbCd1234",
        cdn_reject_unknown_sni=True,
    )


def location(slug="de-123", name="Germany", cc="DE", port=31001):
    return {
        "slug": slug,
        "name": name,
        "country_code": cc,
        "enabled": True,
        "inbound_tags": [],
        "gateway_port": port,
        "xui_inbound_port": 0,
        "ss_method": "2022-blake3-aes-128-gcm",
        "ss_password": "encrypted",
    }


def test_cdn_vless_id_is_stable_secret_derived_uuid():
    loc = location()
    first = derive_vless_id(loc, fake_decrypt)
    second = derive_vless_id(loc, fake_decrypt)
    assert first == second
    assert uuid.UUID(first).version == 4
    other = derive_vless_id(location("fr-456", "France", "FR", 31002), fake_decrypt)
    assert other != first


def test_shared_cdn_inbound_uses_panel_certificate_and_one_client_per_location():
    settings = cdn_settings()
    locations = [
        location(),
        location("fr-456", "France", "FR", 31002),
    ]
    payload = build_cdn_inbound_payload(
        locations,
        settings,
        {
            "webCertFile": "/root/cert/example.com/fullchain.pem",
            "webKeyFile": "/root/cert/example.com/privkey.pem",
        },
        fake_decrypt,
    )

    assert payload["tag"] == CDN_MANAGED_TAG
    assert payload["protocol"] == "vless"
    assert payload["port"] == 8443
    assert len(payload["settings"]["clients"]) == 2
    assert payload["settings"]["decryption"] == "none"
    assert all(client["tgId"] == 0 for client in payload["settings"]["clients"])
    assert all(isinstance(client["tgId"], int) for client in payload["settings"]["clients"])
    assert payload["streamSettings"]["network"] == "ws"
    assert payload["streamSettings"]["security"] == "tls"
    assert payload["streamSettings"]["wsSettings"]["path"] == "/edge-AbCd1234"
    tls = payload["streamSettings"]["tlsSettings"]
    assert tls["serverName"] == "edge.example.com"
    assert tls["rejectUnknownSni"] is True
    assert tls["minVersion"] == "1.2"
    assert tls["maxVersion"] == "1.3"
    assert tls["certificates"][0]["certificateFile"] == "/root/cert/example.com/fullchain.pem"
    assert tls["certificates"][0]["keyFile"] == "/root/cert/example.com/privkey.pem"


def test_cdn_routes_shared_inbound_by_client_email_to_each_tor_exit():
    settings = cdn_settings()
    locations = [
        location(),
        location("fr-456", "France", "FR", 31002),
    ]
    config = build_synced_config(
        {"outbounds": [], "routing": {"rules": []}},
        locations,
        "127.0.0.1",
        fake_decrypt,
        settings,
    )

    rules = config["routing"]["rules"]
    de = next(rule for rule in rules if rule.get("user") == [managed_client_email(locations[0])])
    fr = next(rule for rule in rules if rule.get("user") == [managed_client_email(locations[1])])
    assert de["inboundTag"] == [CDN_MANAGED_TAG]
    assert de["outboundTag"] == "torloc-de-123"
    assert fr["outboundTag"] == "torloc-fr-456"


def test_generated_cloudflare_client_link_has_tls_ws_sni_host_and_fingerprint():
    loc = location()
    uri = managed_cdn_client_uri(loc, cdn_settings(), fake_decrypt)
    assert uri.startswith("vless://")
    assert "@edge.example.com:8443?" in uri
    assert "security=tls" in uri
    assert "type=ws" in uri
    assert "sni=edge.example.com" in uri
    assert "host=edge.example.com" in uri
    assert "fp=chrome" in uri
    assert "path=%2Fedge-AbCd1234" in uri


def test_reconcile_rejects_port_used_by_another_xui_inbound():
    class FakeClient:
        settings = cdn_settings()

        def list_inbounds(self):
            return [
                {
                    "id": 7,
                    "tag": "manual-ws",
                    "remark": "Existing WS",
                    "port": 8443,
                }
            ]

    with pytest.raises(CDNProfileError, match="8443"):
        reconcile_cdn_inbound(FakeClient(), [location()], fake_decrypt)
