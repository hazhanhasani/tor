from torpanel.pasarguard import build_synced_core_config
from torpanel.panel_sync import build_xui_hybrid_config
import torpanel.pasarguard as pg
import torpanel.panel_sync as panel_sync


def _assert_current_freedom_schema(outbound):
    assert outbound["protocol"] == "freedom"
    assert outbound["settings"] == {}
    assert outbound["streamSettings"]["sockopt"]["domainStrategy"] == "UseIPv4"
    assert "domainStrategy" not in outbound["settings"]


def test_pasarguard_builds_tor_and_tunnel_routes(monkeypatch):
    monkeypatch.setattr(pg, "pasarguard_tor_tags", lambda slug: ["pg-in"] if slug == "de-a" else [])
    monkeypatch.setattr(pg, "tunnel_panel_tags", lambda uuid, provider: ["pg-tunnel"] if provider == "pasarguard" else [])
    original = {
        "inbounds": [{"tag": "pg-in"}, {"tag": "pg-tunnel"}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "tlm-pg-tor-old"}],
        "routing": {"rules": [{"type": "field", "outboundTag": "tlm-pg-tunnel-old"}]},
    }
    locations = [{
        "slug": "de-a", "name": "Germany", "enabled": True,
        "gateway_port": 31001, "ss_method": "vless-reality", "ss_password": "enc",
    }]
    links = [{"uuid": "11111111-2222-3333-4444-555555555555", "enabled": True, "iran_overlay_ip": "10.203.0.1"}]
    config = build_synced_core_config(
        original, locations, gateway_host="127.0.0.1", decrypt_password=lambda _: "secret", tunnel_links=links
    )
    by_tag = {row["tag"]: row for row in config["outbounds"]}
    assert "direct" in by_tag
    assert "tlm-pg-tor-de-a" in by_tag
    assert by_tag["tlm-pg-tor-de-a"]["protocol"] == "vless"
    assert by_tag["tlm-pg-tor-de-a"]["settings"]["flow"] == "xtls-rprx-vision"
    assert by_tag["tlm-pg-tor-de-a"]["streamSettings"]["security"] == "reality"
    tunnel_tag = next(tag for tag in by_tag if tag.startswith("tlm-pg-tunnel-"))
    assert by_tag[tunnel_tag]["sendThrough"] == "10.203.0.1"
    _assert_current_freedom_schema(by_tag[tunnel_tag])
    rules = config["routing"]["rules"]
    assert any(row.get("inboundTag") == ["pg-in"] and row.get("outboundTag") == "tlm-pg-tor-de-a" for row in rules)
    assert any(row.get("inboundTag") == ["pg-tunnel"] and row.get("outboundTag") == tunnel_tag for row in rules)
    assert not any(str(row.get("outboundTag", "")).endswith("old") for row in rules)


def test_xui_builds_hybrid_source_route(monkeypatch):
    monkeypatch.setattr(panel_sync, "tunnel_panel_tags", lambda uuid, provider: ["in-a"] if provider == "xui" else [])
    original = {
        "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "tlm-tunnel-old"}],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "outboundTag": "tlm-tunnel-old"},
        ]},
    }
    links = [{"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "enabled": True, "iran_overlay_ip": "10.203.0.5"}]
    config = build_xui_hybrid_config(original, links)
    tunnel = next(row for row in config["outbounds"] if row["tag"].startswith("tlm-tunnel-"))
    assert tunnel["sendThrough"] == "10.203.0.5"
    _assert_current_freedom_schema(tunnel)
    assert config["routing"]["rules"][0]["outboundTag"] == "api"
    assert any(row.get("inboundTag") == ["in-a"] and row.get("outboundTag") == tunnel["tag"] for row in config["routing"]["rules"])


def test_sync_all_panels_combines_xui_tor_and_tunnel_changes(monkeypatch):
    called = []

    monkeypatch.setattr(panel_sync, "xui_configured", lambda: True)
    monkeypatch.setattr(panel_sync, "pasarguard_configured", lambda: False)
    monkeypatch.setattr(panel_sync, "list_tunnel_links", lambda: [
        {"uuid": "existing-tunnel", "enabled": True}
    ])
    monkeypatch.setattr(
        panel_sync, "tunnel_panel_tags",
        lambda uuid, provider: ["manual-inbound"] if provider == "xui" else [],
    )

    def sync_once(locations, decrypt_password, *, tunnel_links):
        called.append(tunnel_links)
        return {"xray_updated": 1, "created": 0, "removed": 0}

    monkeypatch.setattr(panel_sync, "sync_locations", sync_once)
    monkeypatch.setattr(
        panel_sync, "sync_xui_hybrid",
        lambda: (_ for _ in ()).throw(
            AssertionError("do not apply Xray configuration twice")
        ),
    )
    results = panel_sync.sync_all_panels([], lambda x: x)
    assert len(called) == 1
    assert results["xui"]["ok"] is True
    assert results["xui"]["tunnel_routes"] == 1


def test_pasarguard_skips_write_and_restart_for_unchanged_config(monkeypatch):
    settings = pg.PasarGuardSettings(
        base_url="https://pg.example.com/", api_key="token", core_id=1,
        verify_tls=True, restart_nodes=True, gateway_host="127.0.0.1",
    )
    monkeypatch.setattr(pg, "current_settings", lambda: settings)
    monkeypatch.setattr(pg, "list_tunnel_links", lambda: [])

    class Client:
        def __init__(self, settings):
            self.settings = settings

        def get_core(self):
            return {"id": 1, "name": "core", "config": {
                "inbounds": [], "outbounds": [], "routing": {"rules": []},
            }}

        def update_core(self, core, config):
            raise AssertionError("no write or node restart on an unchanged config")

    monkeypatch.setattr(pg, "PasarGuardClient", Client)
    result = pg.sync_pasarguard([], lambda x: x)
    assert result["core_updated"] == 0
