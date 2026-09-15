from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from .config import DB_PATH


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    country_code TEXT NOT NULL,
    socks_port INTEGER NOT NULL UNIQUE,
    gateway_port INTEGER NOT NULL UNIQUE,
    ss_method TEXT NOT NULL DEFAULT '2022-blake3-aes-128-gcm',
    ss_password TEXT NOT NULL,
    inbound_tags TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


@contextmanager
def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        db.executescript(SCHEMA)
        yield db
        db.commit()
    finally:
        db.close()


def init_db() -> None:
    with connect():
        pass


def get_setting(key: str, default: str = "") -> str:
    with connect() as db:
        row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with connect() as db:
        db.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def all_settings() -> dict[str, str]:
    with connect() as db:
        rows = db.execute("SELECT key,value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


def list_locations(enabled_only: bool = False) -> list[dict[str, Any]]:
    sql = "SELECT * FROM locations"
    args: tuple[Any, ...] = ()
    if enabled_only:
        sql += " WHERE enabled=1"
    sql += " ORDER BY id"
    with connect() as db:
        rows = db.execute(sql, args).fetchall()
    return [_row_to_location(r) for r in rows]


def get_location(location_id: int) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM locations WHERE id=?", (location_id,)).fetchone()
    return _row_to_location(row) if row else None


def get_location_by_slug(slug: str) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM locations WHERE slug=?", (slug,)).fetchone()
    return _row_to_location(row) if row else None


def _row_to_location(row: sqlite3.Row) -> dict[str, Any]:
    obj = dict(row)
    try:
        obj["inbound_tags"] = json.loads(obj.get("inbound_tags") or "[]")
    except Exception:
        obj["inbound_tags"] = []
    obj["enabled"] = bool(obj.get("enabled"))
    return obj


def next_socks_port(start: int = 19050) -> int:
    with connect() as db:
        used = {r[0] for r in db.execute("SELECT socks_port FROM locations").fetchall()}
    port = start
    while port in used and port < 65000:
        port += 1
    if port >= 65000:
        raise RuntimeError("No free internal Tor SOCKS port available")
    return port


def create_location(data: dict[str, Any]) -> int:
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        cur = db.execute(
            """INSERT INTO locations
            (slug,name,country_code,socks_port,gateway_port,ss_method,ss_password,inbound_tags,enabled,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data["slug"], data["name"], data["country_code"], int(data["socks_port"]),
                int(data["gateway_port"]), data["ss_method"], data["ss_password"],
                json.dumps(data.get("inbound_tags", []), ensure_ascii=False),
                1 if data.get("enabled", True) else 0, now, now,
            ),
        )
        return int(cur.lastrowid)


def update_location(location_id: int, data: dict[str, Any]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        db.execute(
            """UPDATE locations SET
            name=?, country_code=?, socks_port=?, gateway_port=?, ss_method=?,
            ss_password=?, inbound_tags=?, enabled=?, updated_at=? WHERE id=?""",
            (
                data["name"], data["country_code"], int(data["socks_port"]),
                int(data["gateway_port"]), data["ss_method"], data["ss_password"],
                json.dumps(data.get("inbound_tags", []), ensure_ascii=False),
                1 if data.get("enabled", True) else 0, now, location_id,
            ),
        )


def delete_location(location_id: int) -> None:
    with connect() as db:
        db.execute("DELETE FROM locations WHERE id=?", (location_id,))
