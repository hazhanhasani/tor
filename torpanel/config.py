from __future__ import annotations

import os
from pathlib import Path


def load_env_file(path: str | Path) -> None:
    p = Path(path)
    if not p.exists():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        os.environ.setdefault(key, value)


ENV_FILE = os.getenv("TORPANEL_ENV_FILE", "/etc/tor-location-manager/panel.env")
load_env_file(ENV_FILE)

BASE_DIR = Path(os.getenv("TORPANEL_BASE_DIR", "/var/lib/tor-location-manager"))
DB_PATH = Path(os.getenv("TORPANEL_DB_PATH", str(BASE_DIR / "panel.db")))
INSTANCE_DIR = Path(os.getenv("TORPANEL_INSTANCE_DIR", "/etc/tor-location-manager/instances"))
TOR_DATA_DIR = Path(os.getenv("TORPANEL_TOR_DATA_DIR", str(BASE_DIR / "tor")))
GATEWAY_CONFIG = Path(os.getenv("TORPANEL_GATEWAY_CONFIG", "/etc/tor-location-manager/xray-gateway.json"))
XRAY_BIN = os.getenv("TORPANEL_XRAY_BIN", "/usr/local/bin/xray")
HELPER_CMD = os.getenv(
    "TORPANEL_HELPER_CMD",
    "sudo -n /opt/tor-location-manager/venv/bin/python -m torpanel.helper apply",
)

PANEL_BIND = os.getenv("TORPANEL_BIND", "0.0.0.0")
PANEL_PORT = int(os.getenv("TORPANEL_PORT", "8787"))
ADMIN_USERNAME = os.getenv("TORPANEL_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("TORPANEL_ADMIN_PASSWORD_HASH", "")
FLASK_SECRET_KEY = os.getenv("TORPANEL_FLASK_SECRET_KEY", "")
FERNET_KEY = os.getenv("TORPANEL_FERNET_KEY", "")
