import pytest

import torpanel.helper as helper_module
import torpanel.panel_tls as panel_tls
from pathlib import Path

from torpanel.helper import _hostname_matches, _is_tls_namespace_process, _map_container_mount_path


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


def test_container_mount_maps_xui_cert_path_to_host_volume():
    mounts = [
        {"Destination": "/etc/x-ui", "Source": "/srv/3x-ui/db"},
        {"Destination": "/root/cert", "Source": "/srv/3x-ui/cert"},
    ]
    mapped = _map_container_mount_path(
        Path("/root/cert/example.com/fullchain.pem"), mounts
    )
    assert mapped == Path("/srv/3x-ui/cert/example.com/fullchain.pem")


def test_container_mount_prefers_most_specific_destination():
    mounts = [
        {"Destination": "/root", "Source": "/srv/root"},
        {"Destination": "/root/cert", "Source": "/srv/certs"},
    ]
    mapped = _map_container_mount_path(
        Path("/root/cert/example.com/privkey.pem"), mounts
    )
    assert mapped == Path("/srv/certs/example.com/privkey.pem")


def test_tls_namespace_process_includes_xray_and_reverse_proxies():
    assert _is_tls_namespace_process("x-ui", "/usr/local/x-ui/x-ui")
    assert _is_tls_namespace_process("xray", "/usr/local/x-ui/bin/xray -config config.json")
    assert _is_tls_namespace_process("nginx", "nginx: worker process")
    assert _is_tls_namespace_process("caddy", "/usr/bin/caddy run")
    assert not _is_tls_namespace_process("sshd", "sshd: root@pts/0")


def test_cloudflare_fallback_certificate_is_generated_and_reused(monkeypatch, tmp_path):
    cert = tmp_path / "fallback.crt"
    key = tmp_path / "fallback.key"
    monkeypatch.setattr(helper_module, "PANEL_TLS_DIR", tmp_path)
    monkeypatch.setattr(helper_module, "PANEL_TLS_FALLBACK_CERT", cert)
    monkeypatch.setattr(helper_module, "PANEL_TLS_FALLBACK_KEY", key)

    cert_path, key_path, source = helper_module._ensure_cloudflare_fallback_cert(
        "panel.example.com"
    )
    assert source == "cloudflare-full-selfsigned"
    assert cert_path == cert
    assert key_path == key
    helper_module._validate_tls_pair(
        cert.read_bytes(), key.read_bytes(), "panel.example.com"
    )

    first_cert = cert.read_bytes()
    helper_module._ensure_cloudflare_fallback_cert("panel.example.com")
    assert cert.read_bytes() == first_cert
