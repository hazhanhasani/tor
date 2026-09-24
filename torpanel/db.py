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
    xui_inbound_port INTEGER NOT NULL DEFAULT 0,
    ss_method TEXT NOT NULL DEFAULT 'vless-reality',
    ss_password TEXT NOT NULL,
    inbound_tags TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tunnel_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('iran','foreign')),
    observed_ip TEXT NOT NULL DEFAULT '',
    advertise_host TEXT NOT NULL DEFAULT '',
    wg_public_key TEXT NOT NULL,
    agent_token_hash TEXT NOT NULL UNIQUE,
    agent_version TEXT NOT NULL DEFAULT '',
    os_info TEXT NOT NULL DEFAULT '',
    capabilities TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_seen TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tunnel_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    iran_node_uuid TEXT,
    foreign_node_uuid TEXT,
    mode TEXT NOT NULL DEFAULT 'auto' CHECK(mode IN ('auto','direct','reverse')),
    active_transport TEXT NOT NULL DEFAULT 'pending',
    subnet_cidr TEXT NOT NULL UNIQUE,
    iran_overlay_ip TEXT NOT NULL UNIQUE,
    foreign_overlay_ip TEXT NOT NULL UNIQUE,
    foreign_wg_port INTEGER NOT NULL UNIQUE,
    iran_frp_control_port INTEGER NOT NULL UNIQUE,
    iran_frp_proxy_port INTEGER NOT NULL UNIQUE,
    wg_psk TEXT NOT NULL,
    frp_token TEXT NOT NULL,
    kill_switch INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    health_timeout INTEGER NOT NULL DEFAULT 45,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tunnel_enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    link_uuid TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('iran','foreign')),
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tunnel_nodes_last_seen ON tunnel_nodes(last_seen);
CREATE INDEX IF NOT EXISTS idx_tunnel_enrollments_link ON tunnel_enrollments(link_uuid, role);
"""


def _migrate(db: sqlite3.Connection) -> None:
    columns = {str(row["name"]) for row in db.execute("PRAGMA table_info(locations)").fetchall()}
    if "xui_inbound_port" not in columns:
        db.execute("ALTER TABLE locations ADD COLUMN xui_inbound_port INTEGER NOT NULL DEFAULT 0")
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_locations_xui_inbound_port "
        "ON locations(xui_inbound_port) WHERE xui_inbound_port > 0"
    )
    # Keep the old ss_* columns for upgrade compatibility. ss_password now
    # stores the encrypted transport seed used to derive VLESS/REALITY keys.
    db.execute("UPDATE locations SET ss_method='vless-reality' WHERE ss_method<>'vless-reality'")


@contextmanager
def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        db.executescript(SCHEMA)
        _migrate(db)
        yield db
        db.commit()
    finally:
        db.close()


def init_db() -> None:
    with connect():
        pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    obj["xui_inbound_port"] = int(obj.get("xui_inbound_port") or 0)
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


def set_location_xui_inbound_port(location_id: int, port: int) -> None:
    now = _now()
    with connect() as db:
        db.execute(
            "UPDATE locations SET xui_inbound_port=?, updated_at=? WHERE id=?",
            (int(port), now, int(location_id)),
        )


def create_location(data: dict[str, Any]) -> int:
    now = _now()
    with connect() as db:
        cur = db.execute(
            """INSERT INTO locations
            (slug,name,country_code,socks_port,gateway_port,xui_inbound_port,ss_method,ss_password,inbound_tags,enabled,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data["slug"], data["name"], data["country_code"], int(data["socks_port"]),
                int(data["gateway_port"]), int(data.get("xui_inbound_port") or 0),
                data["ss_method"], data["ss_password"],
                json.dumps(data.get("inbound_tags", []), ensure_ascii=False),
                1 if data.get("enabled", True) else 0, now, now,
            ),
        )
        return int(cur.lastrowid)


def update_location(location_id: int, data: dict[str, Any]) -> None:
    now = _now()
    with connect() as db:
        db.execute(
            """UPDATE locations SET
            name=?, country_code=?, socks_port=?, gateway_port=?, xui_inbound_port=?, ss_method=?,
            ss_password=?, inbound_tags=?, enabled=?, updated_at=? WHERE id=?""",
            (
                data["name"], data["country_code"], int(data["socks_port"]),
                int(data["gateway_port"]), int(data.get("xui_inbound_port") or 0),
                data["ss_method"], data["ss_password"],
                json.dumps(data.get("inbound_tags", []), ensure_ascii=False),
                1 if data.get("enabled", True) else 0, now, location_id,
            ),
        )


def delete_location(location_id: int) -> None:
    with connect() as db:
        db.execute("DELETE FROM locations WHERE id=?", (location_id,))


# Hybrid tunnel control plane -------------------------------------------------

def _json_obj(value: str, default: Any) -> Any:
    try:
        return json.loads(value or "")
    except Exception:
        return default


def _row_to_node(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    obj = dict(row)
    obj["capabilities"] = _json_obj(obj.get("capabilities") or "{}", {})
    obj["state"] = _json_obj(obj.get("state") or "{}", {})
    obj["enabled"] = bool(obj.get("enabled"))
    return obj


def _row_to_link(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    obj = dict(row)
    obj["kill_switch"] = bool(obj.get("kill_switch"))
    obj["enabled"] = bool(obj.get("enabled"))
    return obj


def list_tunnel_nodes() -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute("SELECT * FROM tunnel_nodes ORDER BY id DESC").fetchall()
    return [_row_to_node(row) for row in rows if row is not None]


def get_tunnel_node(node_uuid: str) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM tunnel_nodes WHERE uuid=?", (node_uuid,)).fetchone()
    return _row_to_node(row)


def get_tunnel_node_by_token_hash(token_hash: str) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM tunnel_nodes WHERE agent_token_hash=?", (token_hash,)).fetchone()
    return _row_to_node(row)


def create_tunnel_node(data: dict[str, Any]) -> dict[str, Any]:
    now = _now()
    with connect() as db:
        db.execute(
            """INSERT INTO tunnel_nodes
            (uuid,name,role,observed_ip,advertise_host,wg_public_key,agent_token_hash,agent_version,os_info,capabilities,state,enabled,last_seen,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data["uuid"], data["name"], data["role"], data.get("observed_ip", ""),
                data.get("advertise_host", ""), data["wg_public_key"], data["agent_token_hash"],
                data.get("agent_version", ""), data.get("os_info", ""),
                json.dumps(data.get("capabilities", {}), ensure_ascii=False),
                json.dumps(data.get("state", {}), ensure_ascii=False), 1, now, now, now,
            ),
        )
    return get_tunnel_node(data["uuid"]) or data


def update_tunnel_node_seen(
    node_uuid: str,
    *,
    observed_ip: str | None = None,
    advertise_host: str | None = None,
    state: dict[str, Any] | None = None,
    agent_version: str | None = None,
    capabilities: dict[str, Any] | None = None,
) -> None:
    node = get_tunnel_node(node_uuid)
    if not node:
        return
    now = _now()
    with connect() as db:
        db.execute(
            """UPDATE tunnel_nodes SET observed_ip=?, advertise_host=?, state=?, agent_version=?, capabilities=?, last_seen=?, updated_at=?
            WHERE uuid=?""",
            (
                observed_ip if observed_ip is not None else node.get("observed_ip", ""),
                advertise_host if advertise_host is not None else node.get("advertise_host", ""),
                json.dumps(state if state is not None else node.get("state", {}), ensure_ascii=False),
                agent_version if agent_version is not None else node.get("agent_version", ""),
                json.dumps(capabilities if capabilities is not None else node.get("capabilities", {}), ensure_ascii=False),
                now, now, node_uuid,
            ),
        )


def list_tunnel_links() -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute("SELECT * FROM tunnel_links ORDER BY id DESC").fetchall()
    return [_row_to_link(row) for row in rows if row is not None]


def get_tunnel_link(link_uuid: str) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM tunnel_links WHERE uuid=?", (link_uuid,)).fetchone()
    return _row_to_link(row)


def create_tunnel_link(data: dict[str, Any]) -> dict[str, Any]:
    now = _now()
    with connect() as db:
        db.execute(
            """INSERT INTO tunnel_links
            (uuid,name,mode,active_transport,subnet_cidr,iran_overlay_ip,foreign_overlay_ip,
             foreign_wg_port,iran_frp_control_port,iran_frp_proxy_port,wg_psk,frp_token,
             kill_switch,enabled,health_timeout,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data["uuid"], data["name"], data.get("mode", "auto"), "pending",
                data["subnet_cidr"], data["iran_overlay_ip"], data["foreign_overlay_ip"],
                int(data["foreign_wg_port"]), int(data["iran_frp_control_port"]),
                int(data["iran_frp_proxy_port"]), data["wg_psk"], data["frp_token"],
                1 if data.get("kill_switch", True) else 0, 1,
                int(data.get("health_timeout", 45)), now, now,
            ),
        )
    return get_tunnel_link(data["uuid"]) or data


def update_tunnel_link(link_uuid: str, **changes: Any) -> None:
    allowed = {"name", "mode", "active_transport", "kill_switch", "enabled", "health_timeout", "iran_node_uuid", "foreign_node_uuid"}
    fields: list[str] = []
    values: list[Any] = []
    for key, value in changes.items():
        if key not in allowed:
            continue
        if key in {"kill_switch", "enabled"}:
            value = 1 if bool(value) else 0
        fields.append(f"{key}=?")
        values.append(value)
    if not fields:
        return
    fields.append("updated_at=?")
    values.append(_now())
    values.append(link_uuid)
    with connect() as db:
        db.execute(f"UPDATE tunnel_links SET {', '.join(fields)} WHERE uuid=?", tuple(values))


def bind_tunnel_link_node(link_uuid: str, role: str, node_uuid: str) -> None:
    if role not in {"iran", "foreign"}:
        raise ValueError("invalid tunnel role")
    update_tunnel_link(link_uuid, **{f"{role}_node_uuid": node_uuid})


def delete_tunnel_link(link_uuid: str) -> None:
    with connect() as db:
        db.execute("DELETE FROM tunnel_enrollments WHERE link_uuid=?", (link_uuid,))
        db.execute("DELETE FROM tunnel_links WHERE uuid=?", (link_uuid,))


def links_for_tunnel_node(node_uuid: str) -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM tunnel_links WHERE enabled=1 AND (iran_node_uuid=? OR foreign_node_uuid=?) ORDER BY id",
            (node_uuid, node_uuid),
        ).fetchall()
    return [_row_to_link(row) for row in rows if row is not None]


def replace_tunnel_enrollment(link_uuid: str, role: str, token_hash: str, expires_at: str) -> None:
    if role not in {"iran", "foreign"}:
        raise ValueError("invalid tunnel role")
    now = _now()
    with connect() as db:
        db.execute("DELETE FROM tunnel_enrollments WHERE link_uuid=? AND role=? AND used_at IS NULL", (link_uuid, role))
        db.execute(
            "INSERT INTO tunnel_enrollments(token_hash,link_uuid,role,expires_at,created_at) VALUES(?,?,?,?,?)",
            (token_hash, link_uuid, role, expires_at, now),
        )


def consume_tunnel_enrollment(token_hash: str) -> dict[str, Any] | None:
    now = _now()
    with connect() as db:
        row = db.execute(
            "SELECT * FROM tunnel_enrollments WHERE token_hash=? AND used_at IS NULL",
            (token_hash,),
        ).fetchone()
        if not row:
            return None
        if str(row["expires_at"]) <= now:
            return None
        changed = db.execute(
            "UPDATE tunnel_enrollments SET used_at=? WHERE id=? AND used_at IS NULL",
            (now, int(row["id"])),
        )
        if changed.rowcount != 1:
            return None
        return dict(row)


def tunnel_resource_sets() -> dict[str, set[Any]]:
    with connect() as db:
        rows = db.execute(
            "SELECT subnet_cidr,foreign_wg_port,iran_frp_control_port,iran_frp_proxy_port FROM tunnel_links"
        ).fetchall()
    return {
        "subnets": {str(r["subnet_cidr"]) for r in rows},
        "wg_ports": {int(r["foreign_wg_port"]) for r in rows},
        "frp_control_ports": {int(r["iran_frp_control_port"]) for r in rows},
        "frp_proxy_ports": {int(r["iran_frp_proxy_port"]) for r in rows},
    }
