from pathlib import Path

import torpanel.tunnels as tunnels


def test_controller_and_node_agent_versions_match():
    source = (Path(__file__).resolve().parents[1] / "scripts" / "tlm-node-agent.py").read_text(encoding="utf-8")
    assert f'AGENT_VERSION = "{tunnels.AGENT_VERSION}"' in source
    assert tunnels.AGENT_VERSION == "1.3.0"


def test_allocator_skips_existing_location_public_ports(monkeypatch):
    monkeypatch.setattr(tunnels, "tunnel_resource_sets", lambda: {
        "subnets": set(),
        "wg_ports": set(),
        "frp_control_ports": set(),
        "frp_proxy_ports": set(),
    })
    monkeypatch.setattr(tunnels, "list_locations", lambda: [
        {"gateway_port": 22000, "xui_inbound_port": 52000},
        {"gateway_port": 40000, "xui_inbound_port": 0},
    ])
    monkeypatch.setattr(
        tunnels,
        "get_setting",
        lambda key, default="": "10.203.0.0/16" if key == "tunnel_overlay_cidr" else default,
    )

    resource = tunnels._allocate_resources()
    # Slot zero collides with existing location ports in all three tunnel ranges,
    # so allocation must move atomically to the next slot.
    assert resource["foreign_wg_port"] == 52001
    assert resource["iran_frp_control_port"] == 22001
    assert resource["iran_frp_proxy_port"] == 40001
