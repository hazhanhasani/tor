import uuid

import pytest

import torpanel.xui_cdn as xui_cdn
from torpanel.xui import XUISettings, build_synced_config
from torpanel.xui_cdn import (
    CDN_MANAGED_REMARK,
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
    assert payload["settings"]["encryption"] == "none"
    assert all(client["tgId"] == 0 for client in payload["settings"]["clients"])
    assert all(isinstance(client["tgId"], int) for client in payload["settings"]["clients"])
    assert all(uuid.UUID(client["subId"]).version == 4 for client in payload["settings"]["clients"])
    assert payload["streamSettings"]["network"] == "ws"
    assert payload["streamSettings"]["security"] == "tls"
    ws = payload["streamSettings"]["wsSettings"]
    assert ws["path"] == "/edge-AbCd1234"
    assert ws["host"] == "edge.example.com"
    assert ws["headers"]["Host"] == "edge.example.com"
    assert ws["heartbeatPeriod"] == 30
    tls = payload["streamSettings"]["tlsSettings"]
    assert tls["serverName"] == "edge.example.com"
    assert tls["rejectUnknownSni"] is True
    assert tls["minVersion"] == "1.2"
    assert tls["maxVersion"] == "1.3"
    assert tls["cipherSuites"] == ""
    assert tls["disableSystemRoot"] is False
    assert tls["enableSessionResumption"] is False
    assert tls["alpn"] == ["h3", "h2", "http/1.1"]
    assert tls["settings"]["fingerprint"] == "randomized"
    sniffing = payload["sniffing"]
    assert sniffing["enabled"] is True
    assert sniffing["routeOnly"] is True
    assert sniffing["destOverride"] == ["http", "tls"]

    cert = tls["certificates"][0]
    assert cert["certificateFile"] == "/root/cert/example.com/fullchain.pem"
    assert cert["keyFile"] == "/root/cert/example.com/privkey.pem"
    assert cert["useFile"] is True
    assert cert["usage"] == "encipherment"
    assert cert["ocspStapling"] == 0
    assert cert["buildChain"] is False


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
    assert "alpn=h3%2Ch2%2Chttp%2F1.1" in uri
    assert "path=%2Fedge-AbCd1234" in uri


def test_reconcile_auto_selects_free_cloudflare_port(monkeypatch):
    saved = {}
    monkeypatch.setattr(xui_cdn, "set_setting", lambda key, value: saved.__setitem__(key, value))

    class FakeClient:
        settings = cdn_settings()

        def __init__(self):
            self.rows = [{
                "id": 7,
                "tag": "manual-ws",
                "remark": "Existing WS",
                "port": 8443,
            }]

        def list_inbounds(self):
            return list(self.rows)

        def get_web_cert_files(self):
            return {
                "webCertFile": "/root/cert/example.com/fullchain.pem",
                "webKeyFile": "/root/cert/example.com/privkey.pem",
            }

        def add_inbound(self, payload):
            self.rows.append({
                "id": 8,
                "tag": payload["tag"],
                "remark": payload["remark"],
                "protocol": payload["protocol"],
                "port": payload["port"],
            })

    client = FakeClient()
    result = reconcile_cdn_inbound(client, [location()], fake_decrypt)
    assert result["created"] == 1
    assert result["cdn_port"] == 443
    assert client.settings.cdn_port == 443
    assert saved["xui_cdn_port"] == "443"
    assert any(row["port"] == 443 for row in client.rows)


def test_reconcile_adopts_existing_managed_remark_with_generated_tag(monkeypatch):
    monkeypatch.setattr(xui_cdn, "set_setting", lambda key, value: None)
    settings = cdn_settings()
    settings.cdn_port = 2087

    class FakeClient:
        def __init__(self):
            self.settings = settings
            self.updated = None

        def list_inbounds(self):
            return [{
                "id": 12,
                "tag": "in-2087-tcp",
                "remark": xui_cdn.CDN_MANAGED_REMARK,
                "protocol": "vless",
                "port": 2087,
            }]

        def get_web_cert_files(self):
            return {
                "webCertFile": "/root/cert/example.com/fullchain.pem",
                "webKeyFile": "/root/cert/example.com/privkey.pem",
            }

        def get_inbound(self, inbound_id):
            assert inbound_id == 12
            return {
                "id": 12,
                "tag": "in-2087-tcp",
                "remark": xui_cdn.CDN_MANAGED_REMARK,
                "protocol": "vless",
                "port": 2087,
                "enable": True,
                "settings": {"clients": [], "decryption": "none", "encryption": "none"},
                "streamSettings": {},
                "sniffing": {},
            }

        def update_inbound(self, inbound_id, payload):
            self.updated = (inbound_id, payload)

    client = FakeClient()
    result = reconcile_cdn_inbound(client, [location()], fake_decrypt)
    assert result["created"] == 0
    assert result["updated"] == 1
    assert result["cdn_inbound_tag"] == "in-2087-tcp"
    assert client.updated[0] == 12
    assert client.updated[1]["tag"] == "in-2087-tcp"


def test_cdn_routes_can_use_actual_generated_inbound_tag():
    settings = cdn_settings()
    loc = location()
    config = build_synced_config(
        {"outbounds": [{"tag": "warp", "protocol": "wireguard", "settings": {}}],
         "routing": {"rules": []}},
        [loc],
        "127.0.0.1",
        fake_decrypt,
        settings,
        warp_enabled=True,
        warp_mode="domains",
        warp_domains=["check-host.net"],
        warp_inbound_tags=[],
        managed_cdn_tag="in-2087-tcp",
    )
    rules = config["routing"]["rules"]
    warp_rule = next(rule for rule in rules if rule.get("ruleTag") == "torloc-warp")
    tor_rule = next(rule for rule in rules if rule.get("user") == [managed_client_email(loc)])
    assert warp_rule["inboundTag"] == ["in-2087-tcp"]
    assert tor_rule["inboundTag"] == ["in-2087-tcp"]


def test_reconcile_moves_existing_managed_inbound_away_from_conflicting_port(monkeypatch):
    saved = {}
    monkeypatch.setattr(xui_cdn, "set_setting", lambda key, value: saved.__setitem__(key, value))
    settings = cdn_settings()
    settings.cdn_port = 8443

    class FakeClient:
        def __init__(self):
            self.settings = settings
            self.updated = None
            self.rows = [
                {
                    "id": 12,
                    "tag": xui_cdn.CDN_MANAGED_TAG,
                    "remark": xui_cdn.CDN_MANAGED_REMARK,
                    "protocol": "vless",
                    "port": 10000,
                },
                {
                    "id": 7,
                    "tag": "manual-8443",
                    "remark": "Manual inbound",
                    "protocol": "vless",
                    "port": 8443,
                },
            ]

        def list_inbounds(self):
            return list(self.rows)

        def get_web_cert_files(self):
            return {
                "webCertFile": "/root/cert/example.com/fullchain.pem",
                "webKeyFile": "/root/cert/example.com/privkey.pem",
            }

        def get_inbound(self, inbound_id):
            assert inbound_id == 12
            return {
                "id": 12,
                "tag": xui_cdn.CDN_MANAGED_TAG,
                "remark": xui_cdn.CDN_MANAGED_REMARK,
                "protocol": "vless",
                "port": 10000,
                "enable": True,
                "settings": {"clients": [], "decryption": "none", "encryption": "none"},
                "streamSettings": {},
                "sniffing": {},
            }

        def update_inbound(self, inbound_id, payload):
            self.updated = (inbound_id, payload)

    client = FakeClient()
    result = reconcile_cdn_inbound(client, [location()], fake_decrypt)
    assert result["updated"] == 1
    assert result["cdn_port"] == 443
    assert client.settings.cdn_port == 443
    assert client.updated[0] == 12
    assert client.updated[1]["port"] == 443
    assert saved["xui_cdn_port"] == "443"


def test_reconcile_retries_when_port_becomes_busy_during_add(monkeypatch):
    saved = {}
    monkeypatch.setattr(xui_cdn, "set_setting", lambda key, value: saved.__setitem__(key, value))

    class FakeClient:
        settings = cdn_settings()

        def __init__(self):
            self.rows = []
            self.add_calls = 0

        def list_inbounds(self):
            return list(self.rows)

        def get_web_cert_files(self):
            return {
                "webCertFile": "/root/cert/example.com/fullchain.pem",
                "webKeyFile": "/root/cert/example.com/privkey.pem",
            }

        def add_inbound(self, payload):
            self.add_calls += 1
            if self.add_calls == 1:
                self.rows.append({
                    "id": 44,
                    "tag": "racing-inbound",
                    "remark": "Created by another operation",
                    "protocol": "vless",
                    "port": payload["port"],
                })
                raise RuntimeError(f"Port {payload['port']} already exists")
            self.rows.append({
                "id": 45,
                "tag": payload["tag"],
                "remark": payload["remark"],
                "protocol": payload["protocol"],
                "port": payload["port"],
            })

    client = FakeClient()
    result = reconcile_cdn_inbound(client, [location()], fake_decrypt)
    assert client.add_calls == 2
    assert result["created"] == 1
    assert result["cdn_port"] == 443
    assert saved["xui_cdn_port"] == "443"
    assert any(row["id"] == 45 and row["port"] == 443 for row in client.rows)


def test_sanaei_385_retries_multiple_hidden_awg_relay_conflicts(monkeypatch):
    saved = {}
    monkeypatch.setattr(xui_cdn, "set_setting", lambda k, v: saved.__setitem__(k, v))

    class FakeClient:
        settings = cdn_settings()
        def __init__(self):
            self.rows = []
            self.ports = []
        def list_inbounds(self):
            return list(self.rows)
        def get_web_cert_files(self):
            return {"webCertFile": "/cert.pem", "webKeyFile": "/key.pem"}
        def add_inbound(self, payload):
            port = payload["port"]
            self.ports.append(port)
            if len(self.ports) < 3:
                raise RuntimeError(
                    f"port {port} (TCP) already forwarded on inbound AWG by its client"
                )
            self.rows.append({
                "id": 40, "tag": "in-2083-tcp",
                "remark": xui_cdn.CDN_MANAGED_REMARK, "port": port,
            })

    client = FakeClient()
    result = reconcile_cdn_inbound(client, [location()], fake_decrypt)
    assert client.ports == [8443, 443, 2083]
    assert result["created"] == 1
    assert result["cdn_port"] == 2083
    assert result["cdn_inbound_tag"] == "in-2083-tcp"
    assert saved["xui_cdn_port"] == "2083"


def test_sanaei_385_failed_create_keeps_legacy_inbound_and_port(monkeypatch):
    saved = {}
    monkeypatch.setattr(xui_cdn, "set_setting", lambda k, v: saved.__setitem__(k, v))

    class FakeClient:
        settings = cdn_settings()
        def __init__(self):
            self.deleted = []
            self.ports = []
        def list_inbounds(self):
            return [{"id": 6, "tag": "torloc-in-de-123",
                     "remark": "Existing legacy", "port": 22001}]
        def get_web_cert_files(self):
            return {"webCertFile": "/cert.pem", "webKeyFile": "/key.pem"}
        def add_inbound(self, payload):
            self.ports.append(payload["port"])
            raise RuntimeError(f"port {payload['port']} already forwarded on AWG")
        def delete_inbound(self, inbound_id):
            self.deleted.append(inbound_id)

    client = FakeClient()
    with pytest.raises(CDNProfileError, match="پورت"):
        reconcile_cdn_inbound(client, [location()], fake_decrypt)
    assert client.deleted == []
    assert client.settings.cdn_port == 8443
    assert saved == {}
    assert len(set(client.ports)) == 5  # 2053 is reserved for the panel itself.


def test_sanaei_385_retains_legacy_after_successful_cdn_create(monkeypatch):
    monkeypatch.setattr(xui_cdn, "set_setting", lambda k, v: None)

    class FakeClient:
        settings = cdn_settings()
        def __init__(self):
            self.rows = [
                {"id": 7, "tag": "torloc-in-de-123", "port": 22001},
            ]
            self.events = []
        def list_inbounds(self):
            return list(self.rows)
        def get_web_cert_files(self):
            return {"webCertFile": "/cert.pem", "webKeyFile": "/key.pem"}
        def add_inbound(self, payload):
            self.events.append("create")
            self.rows.append({
                "id": 8, "tag": payload["tag"],
                "remark": payload["remark"], "port": payload["port"],
            })
        def delete_inbound(self, inbound_id):
            self.events.append("delete")
            self.rows = [row for row in self.rows if row["id"] != inbound_id]

    client = FakeClient()
    result = reconcile_cdn_inbound(client, [location()], fake_decrypt)
    assert result["created"] == 1
    assert result["removed"] == 0
    assert client.events == ["create"]
    assert [row["id"] for row in client.rows] == [7, 8]
    assert result["preserved_legacy_tags"] == ["torloc-in-de-123"]



def test_cdn_reconcile_preserves_operator_clients(monkeypatch):
    loc = location()
    settings = cdn_settings()
    certs = {"webCertFile": "/etc/x-ui/cert.pem", "webKeyFile": "/etc/x-ui/key.pem"}
    base = build_cdn_inbound_payload([loc], settings, certs, fake_decrypt)
    current = {
        **base,
        "id": 55,
        "settings": {
            **base["settings"],
            "clients": [
                {
                    "id": "11111111-2222-4333-8444-555555555555",
                    "email": "operator@example.com",
                    "flow": "",
                    "limitIp": 2,
                    "totalGB": 999,
                    "expiryTime": 0,
                    "enable": True,
                    "tgId": 0,
                    "subId": "operator-sub",
                    "comment": "keep",
                    "reset": 0,
                },
                *base["settings"]["clients"],
            ],
        },
    }

    class FakeClient:
        def __init__(self):
            self.settings = settings
            self.updated = None

        def list_inbounds(self):
            return [{"id": 55, "tag": CDN_MANAGED_TAG, "remark": CDN_MANAGED_REMARK, "port": settings.cdn_port}]

        def get_web_cert_files(self):
            return certs

        def get_inbound(self, inbound_id):
            return current

        def update_inbound(self, inbound_id, payload):
            self.updated = payload
            return {}

    client = FakeClient()
    result = reconcile_cdn_inbound(client, [loc], fake_decrypt)
    assert result["updated"] == 0
    assert client.updated is None

    # Force a transport change; the update payload must still retain the operator client.
    current["streamSettings"]["wsSettings"]["heartbeatPeriod"] = 5
    result = reconcile_cdn_inbound(client, [loc], fake_decrypt)
    assert result["updated"] == 1
    emails = [row["email"] for row in client.updated["settings"]["clients"]]
    assert "operator@example.com" in emails
    assert managed_client_email(loc) in emails


def test_cdn_merge_does_not_reset_managed_clients_or_subscription_ids():
    loc = location()
    settings = cdn_settings()
    certs = {"webCertFile": "/cert.pem", "webKeyFile": "/key.pem"}
    expected = build_cdn_inbound_payload([loc], settings, certs, fake_decrypt)
    live = dict(expected["settings"]["clients"][0])
    live.update(
        {"enable": False, "totalGB": 987654, "expiryTime": 77777,
         "subId": "original-subscription", "comment": "keep this customer"}
    )
    current = {
        **expected,
        "settings": {
            **expected["settings"],
            "clients": [
                {"email": "other@domain.test", "id": "external-user", "enable": True},
                live,
            ],
        },
    }
    merged = xui_cdn.merge_preserved_cdn_clients(current, expected)
    by_email = {row["email"]: row for row in merged["settings"]["clients"]}
    assert by_email[live["email"]] == live
    assert by_email["other@domain.test"]["id"] == "external-user"


def test_no_enabled_locations_disables_generated_clients_without_deleting_inbound():
    settings = cdn_settings()
    loc = location()
    base = build_cdn_inbound_payload(
        [loc], settings,
        {"webCertFile": "/cert.pem", "webKeyFile": "/key.pem"}, fake_decrypt
    )

    class Client:
        def __init__(self):
            self.settings = settings
            self.updated = None
            self.deleted = []

        def list_inbounds(self):
            return [{"id": 3, "tag": CDN_MANAGED_TAG,
                     "remark": CDN_MANAGED_REMARK, "port": 8443}]

        def get_inbound(self, inbound_id):
            return {
                **base, "id": inbound_id,
                "settings": {
                    **base["settings"],
                    "clients": [
                        *base["settings"]["clients"],
                        {"id": "external", "email": "manual@example.com", "enable": True},
                    ],
                },
            }

        def update_inbound(self, inbound_id, payload):
            self.updated = payload

        def delete_inbound(self, inbound_id):
            self.deleted.append(inbound_id)

    client = Client()
    result = reconcile_cdn_inbound(client, [], fake_decrypt)
    assert result["removed"] == 0
    assert result["updated"] == 1
    assert client.deleted == []
    by_email = {
        row["email"]: row for row in client.updated["settings"]["clients"]
    }
    assert not by_email[managed_client_email(loc)]["enable"]
    assert by_email["manual@example.com"]["enable"]


def test_new_manual_location_does_not_create_cdn_client_or_inbound():
    settings = cdn_settings()
    loc = location("fr-manual", "France", "FR", 31010)
    loc["xui_auto_client"] = False
    loc["inbound_tags"] = ["existing-vless"]

    class Client:
        def __init__(self):
            self.settings = settings
        def list_inbounds(self):
            return [{"id": 10, "tag": "existing-vless", "port": 10005}]
        def get_web_cert_files(self):
            raise AssertionError("CDN certificate is not needed for a manual route")
        def add_inbound(self, payload):
            raise AssertionError("Manual location must not create an inbound")
        def update_inbound(self, inbound_id, payload):
            raise AssertionError("Manual location must not rewrite clients")

    result = reconcile_cdn_inbound(Client(), [loc], fake_decrypt)
    assert result["created"] == result["updated"] == result["removed"] == 0
    assert result["cdn_managed_emails"] == []
    assert result["cdn_inbound_tag"] == ""

    routed = build_synced_config(
        {"outbounds": [], "routing": {"rules": []}}, [loc], "127.0.0.1",
        fake_decrypt, settings, cdn_managed_emails=set(),
        managed_cdn_tag=result["cdn_inbound_tag"],
    )
    assert len(routed["routing"]["rules"]) == 1
    assert routed["routing"]["rules"][0]["inboundTag"] == ["existing-vless"]
    assert "user" not in routed["routing"]["rules"][0]


def test_manual_location_does_not_add_user_to_existing_shared_cdn():
    settings = cdn_settings()
    old = location()
    new = location("fr-manual", "France", "FR", 31002)
    new["xui_auto_client"] = False
    new["inbound_tags"] = ["existing-vless"]
    certs = {"webCertFile": "/cert.pem", "webKeyFile": "/key.pem"}
    current = build_cdn_inbound_payload([old], settings, certs, fake_decrypt)

    class Client:
        def __init__(self):
            self.settings = settings
        def list_inbounds(self):
            return [
                {"id": 1, "tag": CDN_MANAGED_TAG, "remark": CDN_MANAGED_REMARK,
                 "port": settings.cdn_port},
                {"id": 10, "tag": "existing-vless", "port": 10005},
            ]
        def get_inbound(self, inbound_id):
            return current
        def get_web_cert_files(self):
            return certs
        def add_inbound(self, payload):
            raise AssertionError("CDN inbound is already present")
        def update_inbound(self, inbound_id, payload):
            raise AssertionError("Adding manual location must not add CDN client")

    result = reconcile_cdn_inbound(Client(), [old, new], fake_decrypt)
    assert result["created"] == result["updated"] == result["removed"] == 0
    assert result["cdn_managed_emails"] == [managed_client_email(old)]
    assert managed_client_email(new) not in result["cdn_managed_emails"]


def test_existing_shared_cdn_is_not_rewritten_for_manual_only_locations():
    settings = cdn_settings()
    manual = location()
    manual["xui_auto_client"] = False
    manual["inbound_tags"] = ["existing-vless"]
    class Client:
        def __init__(self):
            self.settings = settings
        def list_inbounds(self):
            return [
                {"id": 1, "tag": CDN_MANAGED_TAG,
                 "remark": CDN_MANAGED_REMARK, "port": settings.cdn_port},
                {"id": 10, "tag": "existing-vless", "port": 10005},
            ]
        def get_inbound(self, inbound_id):
            return {"settings": {"clients": [
                {"id": "old", "email": "real@example.com", "enable": True}
            ]}}
        def get_web_cert_files(self):
            raise AssertionError("No TLS read for unchanged manual-only route")
        def update_inbound(self, inbound_id, payload):
            raise AssertionError("Shared CDN must remain untouched")

    result = reconcile_cdn_inbound(Client(), [manual], fake_decrypt)
    assert result["updated"] == result["created"] == 0
    assert result["cdn_managed_emails"] == []
