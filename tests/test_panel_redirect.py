import torpanel.panel_redirect as panel_redirect


def test_target_base_url_uses_https_domain_and_nonstandard_port(monkeypatch):
    monkeypatch.setattr(panel_redirect, "PANEL_TLS_ENABLED", True)
    monkeypatch.setattr(panel_redirect, "PANEL_PUBLIC_HOST", "panel.example.com")
    monkeypatch.setattr(panel_redirect, "PANEL_PORT", 2096)
    assert panel_redirect.target_base_url() == "https://panel.example.com:2096"


def test_target_base_url_omits_standard_443(monkeypatch):
    monkeypatch.setattr(panel_redirect, "PANEL_TLS_ENABLED", True)
    monkeypatch.setattr(panel_redirect, "PANEL_PUBLIC_HOST", "panel.example.com")
    monkeypatch.setattr(panel_redirect, "PANEL_PORT", 443)
    assert panel_redirect.target_base_url() == "https://panel.example.com"


def test_target_base_url_disabled_without_tls_or_host(monkeypatch):
    monkeypatch.setattr(panel_redirect, "PANEL_TLS_ENABLED", False)
    monkeypatch.setattr(panel_redirect, "PANEL_PUBLIC_HOST", "panel.example.com")
    assert panel_redirect.target_base_url() == ""

    monkeypatch.setattr(panel_redirect, "PANEL_TLS_ENABLED", True)
    monkeypatch.setattr(panel_redirect, "PANEL_PUBLIC_HOST", "")
    assert panel_redirect.target_base_url() == ""
