import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet

os.environ.setdefault("TORPANEL_FERNET_KEY", Fernet.generate_key().decode())

import torpanel.helper as helper
from torpanel.helper import gateway_config, validation_temp_path
from torpanel.security import encrypt_secret


def test_gateway_blocks_udp_and_routes_tcp_to_tor():
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
