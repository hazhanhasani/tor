"""Regression coverage: existing locations keep legacy behavior, new ones reuse clients."""

import sqlite3

from torpanel import db


def _location(slug="de-existing", **overrides):
    row = {
        "slug": slug, "name": "Germany", "country_code": "DE",
        "socks_port": 19050, "gateway_port": 31001,
        "xui_inbound_port": 0, "ss_method": "vless-reality",
        "ss_password": "encrypted", "inbound_tags": ["already-there"],
        "enabled": True,
    }
    row.update(overrides)
    return row


def test_new_location_defaults_to_reusing_selected_inbounds(monkeypatch, tmp_path):
    path = tmp_path / "panel.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    location_id = db.create_location(_location())
    result = db.get_location(location_id)
    assert result["inbound_tags"] == ["already-there"]
    assert result["xui_auto_client"] is False
    db.update_location(location_id, {**result, "xui_auto_client": True})
    assert db.get_location(location_id)["xui_auto_client"] is True


def test_existing_database_migration_preserves_legacy_opt_in(monkeypatch, tmp_path):
    path = tmp_path / "legacy.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    old_schema = db.SCHEMA.replace(
        "    xui_auto_client INTEGER NOT NULL DEFAULT 1,\n", ""
    )
    with sqlite3.connect(path) as conn:
        conn.executescript(old_schema)
        conn.execute(
            "INSERT INTO locations "
            "(slug,name,country_code,socks_port,gateway_port,xui_inbound_port,"
            "ss_method,ss_password,inbound_tags,enabled,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "fi-legacy", "Finland", "FI", 19051, 31002, 0,
                "vless-reality", "encrypted", "[]", 1,
                "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
            ),
        )
    db.init_db()
    result = db.get_location_by_slug("fi-legacy")
    assert result["xui_auto_client"] is True
