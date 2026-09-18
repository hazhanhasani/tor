import pytest

import torpanel.panel_tls as panel_tls
from torpanel.helper import _hostname_matches


def test_xui_public_host_requires_https_domain():
    assert panel_tls.xui_public_host("https://panel.example.com:2053/base") == "panel.example.com"
    with pytest.raises(panel_tls.PanelTLSError):
        panel_tls.xui_public_host("http://panel.example.com:2053")
    with pytest.raises(panel_tls.PanelTLSError):
        panel_tls.xui_public_host("https://203.0.113.10:2053")


def test_panel_https_port_rejects_xui_and_managed_cdn_collisions(monkeypatch):
    values = {
        "xui_managed_inbound_mode": "cloudflare",
        "xui_cdn_port": "8443",
    }
    monkeypatch.setattr(panel_tls, "get_setting", lambda key, default="": values.get(key, default))
    monkeypatch.setattr(panel_tls, "list_locations", lambda: [])
    monkeypatch.setattr(panel_tls, "list_tunnel_links", lambda: [])

    assert panel_tls.validate_panel_https_port(2096, xui_base_url="https://panel.example.com:2053") == 2096
    with pytest.raises(panel_tls.PanelTLSError):
        panel_tls.validate_panel_https_port(2053, xui_base_url="https://panel.example.com:2053")
    with pytest.raises(panel_tls.PanelTLSError):
        panel_tls.validate_panel_https_port(8443, xui_base_url="https://panel.example.com:2053")


def test_panel_https_port_rejects_location_and_tunnel_ports(monkeypatch):
    monkeypatch.setattr(panel_tls, "get_setting", lambda key, default="": default)
    monkeypatch.setattr(
        panel_tls,
        "list_locations",
        lambda: [{"name": "Germany", "gateway_port": 2087, "xui_inbound_port": 0}],
    )
    monkeypatch.setattr(
        panel_tls,
        "list_tunnel_links",
        lambda: [{"foreign_wg_port": 2096, "iran_frp_control_port": 0, "iran_frp_proxy_port": 0}],
    )

    with pytest.raises(panel_tls.PanelTLSError):
        panel_tls.validate_panel_https_port(2087, xui_base_url="https://panel.example.com:2053")
    with pytest.raises(panel_tls.PanelTLSError):
        panel_tls.validate_panel_https_port(2096, xui_base_url="https://panel.example.com:2053")


def test_certificate_hostname_matching_supports_single_label_wildcard():
    assert _hostname_matches("panel.example.com", "panel.example.com")
    assert _hostname_matches("*.example.com", "panel.example.com")
    assert not _hostname_matches("*.example.com", "a.b.example.com")
    assert not _hostname_matches("panel.example.com", "other.example.com")
