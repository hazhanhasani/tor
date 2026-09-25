"""New location creation must use the customer's existing inbound by default."""

import torpanel.app as app_module


def test_create_location_reuses_selected_inbound_without_autoclient(monkeypatch):
    created = []
    monkeypatch.setattr(app_module, "FLASK_SECRET_KEY", "unit-test-secret")
    monkeypatch.setattr(app_module, "ADMIN_PASSWORD_HASH", "unit-test-hash")
    monkeypatch.setattr(app_module, "init_db", lambda: None)
    monkeypatch.setattr(app_module, "validate_csrf", lambda value: None)
    monkeypatch.setattr(app_module, "encrypt_secret", lambda value: value)
    monkeypatch.setattr(app_module, "list_locations", lambda: [])
    monkeypatch.setattr(app_module, "list_tunnel_links", lambda: [])
    monkeypatch.setattr(
        app_module, "get_setting",
        lambda key, default="": (
            "token" if key == "xui_api_token" else
            "legacy" if key == "xui_managed_inbound_mode" else default
        ),
    )
    monkeypatch.setattr(
        app_module, "create_location",
        lambda data: (created.append(data), 123)[1],
    )
    monkeypatch.setattr(app_module, "set_pasarguard_tor_tags", lambda *args: None)
    monkeypatch.setattr(app_module, "apply_runtime", lambda: None)
    monkeypatch.setattr(
        app_module, "sync_all_panels",
        lambda *args: {"xui": {"ok": True, "created": 0}},
    )

    app = app_module.make_app()
    app.testing = True
    client = app.test_client()
    with client.session_transaction() as session:
        session["authenticated"] = True

    response = client.post(
        "/locations/new",
        data={
            "name": "Finland", "country_code": "FI", "enabled": "on",
            "inbound_tags": ["my-paid-inbound"],
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert len(created) == 1
    assert created[0]["inbound_tags"] == ["my-paid-inbound"]
    assert created[0]["xui_auto_client"] is False
    assert created[0]["xui_inbound_port"] == 0


def test_create_location_blocks_unrequested_user_creation(monkeypatch):
    created = []
    monkeypatch.setattr(app_module, "FLASK_SECRET_KEY", "unit-test-secret")
    monkeypatch.setattr(app_module, "ADMIN_PASSWORD_HASH", "unit-test-hash")
    monkeypatch.setattr(app_module, "init_db", lambda: None)
    monkeypatch.setattr(app_module, "validate_csrf", lambda value: None)
    monkeypatch.setattr(app_module, "list_locations", lambda: [])
    monkeypatch.setattr(app_module, "list_tunnel_links", lambda: [])
    monkeypatch.setattr(
        app_module, "get_setting",
        lambda key, default="": (
            "token" if key == "xui_api_token" else
            "legacy" if key == "xui_managed_inbound_mode" else default
        ),
    )
    monkeypatch.setattr(
        app_module, "create_location", lambda data: created.append(data)
    )
    monkeypatch.setattr(app_module, "load_xui_inbounds", lambda: [])
    monkeypatch.setattr(app_module, "load_pasarguard_inbounds", lambda: [])
    monkeypatch.setattr(app_module, "cached_update_available", lambda: False)
    monkeypatch.setattr(app_module, "current_version", lambda: "test")
    app = app_module.make_app()
    app.testing = True
    client = app.test_client()
    with client.session_transaction() as session:
        session["authenticated"] = True
    response = client.post(
        "/locations/new", data={"name": "Finland", "country_code": "FI", "enabled": "on"}
    )
    assert response.status_code == 200
    assert not created
    assert "Inbound" in response.get_data(as_text=True)
