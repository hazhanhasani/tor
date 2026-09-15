import base64

import pytest

from torpanel import db
from torpanel.tunnels import (
    TunnelError,
    create_link,
    desired_config,
    enroll_node,
    heartbeat,
    issue_enrollment,
)


def wg_key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "panel.db")
    db.init_db()


def test_hybrid_link_enrollment_and_desired_config():
    link = create_link("Iran ↔ Germany", mode="auto", kill_switch=True)
    assert link["subnet_cidr"].endswith("/30")
    assert 52000 <= link["foreign_wg_port"] <= 59999
    assert 22000 <= link["iran_frp_control_port"] <= 29999
    assert 40000 <= link["iran_frp_proxy_port"] <= 47999

    iran_token = issue_enrollment(link["uuid"], "iran")
    foreign_token = issue_enrollment(link["uuid"], "foreign")

    iran, iran_agent_token, _ = enroll_node(
        {
            "token": iran_token,
            "name": "IR-1",
            "wg_public_key": wg_key(1),
            "agent_version": "1.0.0",
            "capabilities": {"wireguard": True, "frps": True},
        },
        "198.51.100.10",
    )
    foreign, foreign_agent_token, _ = enroll_node(
        {
            "token": foreign_token,
            "name": "DE-1",
            "wg_public_key": wg_key(2),
            "agent_version": "1.0.0",
            "capabilities": {"wireguard": True, "frpc": True},
        },
        "203.0.113.20",
    )
    assert iran_agent_token and foreign_agent_token

    iran_desired = desired_config(iran)
    foreign_desired = desired_config(foreign)
    assert len(iran_desired["links"]) == 1
    assert len(foreign_desired["links"]) == 1

    iran_link = iran_desired["links"][0]
    foreign_link = foreign_desired["links"][0]
    assert iran_link["ready"] is True
    assert iran_link["peer"]["public_key"] == wg_key(2)
    assert iran_link["direct_endpoint"]["host"] == "203.0.113.20"
    assert iran_link["reverse_endpoint"]["host"] == "127.0.0.1"
    assert iran_link["frp"]["side"] == "server"
    assert iran_link["frp"]["proxy_bind_host"] == "127.0.0.1"
    assert foreign_link["frp"]["side"] == "client"
    assert foreign_link["frp"]["server_host"] == "198.51.100.10"
    assert foreign_link["firewall"]["allow_source"] == "198.51.100.10"

    heartbeat(
        iran,
        {"agent_version": "1.0.0", "state": {"links": [{"uuid": link["uuid"], "transport": "direct", "healthy": True}]}},
        "198.51.100.10",
    )
    assert db.get_tunnel_link(link["uuid"])["active_transport"] == "direct"


def test_enrollment_token_is_one_time():
    link = create_link("one-time")
    token = issue_enrollment(link["uuid"], "iran")
    enroll_node({"token": token, "name": "IR", "wg_public_key": wg_key(3)}, "198.51.100.30")
    with pytest.raises(TunnelError):
        enroll_node({"token": token, "name": "IR2", "wg_public_key": wg_key(4)}, "198.51.100.31")


def test_multiple_links_receive_unique_network_resources():
    first = create_link("A")
    second = create_link("B")
    assert first["subnet_cidr"] != second["subnet_cidr"]
    assert first["foreign_wg_port"] != second["foreign_wg_port"]
    assert first["iran_frp_control_port"] != second["iran_frp_control_port"]
    assert first["iran_frp_proxy_port"] != second["iran_frp_proxy_port"]
