import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet

os.environ.setdefault("TORPANEL_FERNET_KEY", Fernet.generate_key().decode())

import torpanel.helper as helper
from torpanel.helper import gateway_config, validation_temp_path
from torpanel.security import encrypt_secret


def test_gateway_blocks_udp_and_routes_tcp_to_tor(monkeypatch):
    monkeypatch.setattr(helper, "get_setting", lambda key, default="": default)
    loc = {
        "slug": "de-test", "gateway_port": 31001, "socks_port": 19050,
        "ss_method": "2022-blake3-aes-128-gcm",
        "ss_password": encrypt_secret(base64.b64encode(b"x" * 32).decode()),
    }
    cfg = gateway_config([loc])
    assert cfg["inbounds"][0]["listen"] == "0.0.0.0"
    assert cfg["inbounds"][0]["settings"]["network"] == "tcp"
    assert cfg["outbounds"][1]["protocol"] == "socks"
    assert cfg["routing"]["rules"][0]["network"] == "udp"
    assert cfg["routing"]["rules"][0]["outboundTag"] == "blocked"
    assert cfg["routing"]["rules"][1]["outboundTag"] == "tor-de-test"


def test_validation_temp_path_keeps_json_suffix():
    path = Path("/etc/tor-location-manager/xray-gateway.json")
    temp = validation_temp_path(path)
    assert temp.name == "xray-gateway.new.json"
    assert temp.suffix == ".json"


def test_direct_tor_transport_adds_no_bridge_lines(monkeypatch):
    monkeypatch.setattr(helper, "get_setting", lambda key, default="": "direct" if key == "tor_transport_mode" else default)
    assert helper._tor_bridge_lines() == []


def test_obfs4_transport_normalizes_bridge_lines(monkeypatch):
    settings = {
        "tor_transport_mode": "obfs4",
        "tor_bridge_lines": "Bridge obfs4 192.0.2.10:443 ABC cert=test iat-mode=0\nobfs4 192.0.2.11:8443 DEF cert=test2 iat-mode=0",
    }
    monkeypatch.setattr(helper, "get_setting", lambda key, default="": settings.get(key, default))
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/obfs4proxy")
    monkeypatch.setattr(Path, "exists", lambda self: True)
    lines = helper._tor_bridge_lines()
    assert lines[0] == "UseBridges 1"
    assert lines[1] == "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy"
    assert lines[2].startswith("Bridge obfs4 192.0.2.10:443")
    assert lines[3].startswith("Bridge obfs4 192.0.2.11:8443")


def test_torrc_binds_location_traffic_to_tunnel_source(monkeypatch):
    monkeypatch.setattr(helper, "get_setting", lambda key, default="": "direct" if key == "tor_transport_mode" else default)
    loc = {"slug": "de-test", "socks_port": 19050, "country_code": "DE"}
    text = helper.torrc_for(loc, "10.203.0.1")
    assert "OutboundBindAddress 10.203.0.1" in text
    assert "ExitNodes {de}" in text


def test_local_tunnel_source_uses_matching_iran_agent(monkeypatch, tmp_path):
    agent = tmp_path / "agent.json"
    agent.write_text(json.dumps({"node_uuid": "iran-node-1"}), encoding="utf-8")
    monkeypatch.setattr(helper, "NODE_AGENT_CONFIG", agent)
    settings = {"tor_auto_tunnel_all_locations": "1", "tor_tunnel_link_uuid": ""}
    monkeypatch.setattr(helper, "get_setting", lambda key, default="": settings.get(key, default))
    monkeypatch.setattr(helper, "list_tunnel_links", lambda: [{
        "uuid": "link-1", "enabled": 1, "iran_node_uuid": "iran-node-1",
        "foreign_node_uuid": "foreign-node-1", "iran_overlay_ip": "10.203.0.1",
        "active_transport": "direct",
    }])
    assert helper.local_tor_tunnel_source_ip() == "10.203.0.1"


def test_unmatched_or_foreign_agent_does_not_bind_tor(monkeypatch, tmp_path):
    agent = tmp_path / "agent.json"
    agent.write_text(json.dumps({"node_uuid": "foreign-node-1"}), encoding="utf-8")
    monkeypatch.setattr(helper, "NODE_AGENT_CONFIG", agent)
    monkeypatch.setattr(helper, "get_setting", lambda key, default="": "1" if key == "tor_auto_tunnel_all_locations" else default)
    monkeypatch.setattr(helper, "list_tunnel_links", lambda: [{
        "uuid": "link-1", "enabled": 1, "iran_node_uuid": "iran-node-1",
        "foreign_node_uuid": "foreign-node-1", "iran_overlay_ip": "10.203.0.1",
        "active_transport": "direct",
    }])
    assert helper.local_tor_tunnel_source_ip() == ""


def test_atomic_write_is_idempotent(tmp_path):
    path = tmp_path / "sample.conf"
    assert helper.atomic_write(path, "same\n") is True
    assert helper.atomic_write(path, "same\n") is False


def test_gateway_routes_selected_domains_to_warp_before_tor(monkeypatch):
    settings = {
        "warp_assist_enabled": "1",
        "warp_proxy_port": "40000",
        "warp_assist_domains": "check-host.net\nexample.com",
    }
    monkeypatch.setattr(helper, "get_setting", lambda key, default="": settings.get(key, default))
    loc = {
        "slug": "de-test", "gateway_port": 31001, "socks_port": 19050,
        "ss_method": "2022-blake3-aes-128-gcm",
        "ss_password": encrypt_secret(base64.b64encode(b"x" * 32).decode()),
    }
    cfg = gateway_config([loc])
    warp = next(out for out in cfg["outbounds"] if out.get("tag") == "warp-assist")
    assert warp["protocol"] == "socks"
    assert warp["settings"] == {"address": "127.0.0.1", "port": 40000}
    inbound = cfg["inbounds"][0]
    assert inbound["sniffing"]["enabled"] is True
    assert inbound["sniffing"]["routeOnly"] is True
    rules = cfg["routing"]["rules"]
    assert rules[0]["outboundTag"] == "blocked"
    assert rules[1]["outboundTag"] == "warp-assist"
    assert rules[1]["domain"] == ["domain:check-host.net", "domain:example.com", "domain:challenges.cloudflare.com"]
    assert rules[2]["outboundTag"] == "tor-de-test"
