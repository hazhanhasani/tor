from pathlib import Path


def test_wsgi_does_not_double_register_tunnel_blueprint():
    root = Path(__file__).resolve().parents[1]
    wsgi_source = (root / "wsgi.py").read_text(encoding="utf-8")
    app_source = (root / "torpanel" / "app.py").read_text(encoding="utf-8")
    assert "register_blueprint" not in wsgi_source
    assert app_source.count("app.register_blueprint(tunnel_bp)") == 1
    assert wsgi_source.count("register_password_recovery(app)") == 1
