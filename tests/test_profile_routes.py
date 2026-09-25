import torpanel.app as app_module

URI = (
    "vless://11111111-2222-4333-8444-555555555555@203.0.113.5:21001"
    "?security=reality&encryption=none"
    "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "&fp=chrome&spx=%2Ftest&type=tcp&flow=xtls-rprx-vision"
    "&sni=www.example.com&sid=0011223344556677"
)


def _client(monkeypatch):
    monkeypatch.setattr(app_module, "FLASK_SECRET_KEY", "unit-secret")
    monkeypatch.setattr(app_module, "ADMIN_PASSWORD_HASH", "unit-hash")
    monkeypatch.setattr(app_module, "init_db", lambda: None)
    monkeypatch.setattr(app_module, "get_setting", lambda key, default="": default)
    monkeypatch.setattr(app_module, "validate_csrf", lambda value: None)
    monkeypatch.setattr(app_module, "cached_update_available", lambda: False)
    monkeypatch.setattr(app_module, "current_version", lambda: "test")
    app = app_module.make_app()
    app.testing = True
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
    return client


def test_profile_download_is_no_store_json(monkeypatch):
    client = _client(monkeypatch)
    response = client.post("/tools/client-profile", data={"vless_uri": URI})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert "attachment" in response.headers["Content-Disposition"]
    obj = response.json
    assert obj["outbounds"][0]["protocol"] == "vless"
    assert "https://" in obj["dns"]["servers"][0]["address"]


def test_profile_invalid_link_is_not_reflected(monkeypatch):
    client = _client(monkeypatch)
    secret = "s3cr3t"
    response = client.post("/tools/client-profile", data={"vless_uri": secret})
    assert response.status_code == 400
    assert secret not in response.get_data(as_text=True)


def test_diagnostic_route_is_background_and_validates_location(monkeypatch):
    client = _client(monkeypatch)
    monkeypatch.setattr(app_module, "get_location", lambda id: {
        "id": id, "slug": "fi-test", "name": "Finland", "country_code": "FI",
    } if id == 3 else None)
    calls = []
    monkeypatch.setattr(app_module, "launch_diagnostic_job", lambda id: (calls.append(id), True)[1])
    monkeypatch.setattr(app_module, "diagnostic_state", lambda id: {
        "status": "queued", "report": {},
    })
    response = client.post("/locations/3/test", follow_redirects=False)
    assert response.status_code == 302
    assert calls == [3]
    report = client.get("/locations/3/diagnostic")
    assert report.status_code == 200
    assert "data-diagnostic-refresh" in report.get_data(as_text=True)
    assert client.post("/locations/999/test").status_code == 404
