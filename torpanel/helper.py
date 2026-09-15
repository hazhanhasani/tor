from __future__ import annotations

import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import GATEWAY_CONFIG, INSTANCE_DIR, TOR_DATA_DIR, XRAY_BIN
from .db import init_db, list_locations
from .security import decrypt_secret


def atomic_write(path: Path, content: str, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def torrc_for(loc: dict) -> str:
    data_dir = TOR_DATA_DIR / loc["slug"]
    return "\n".join([
        "ClientOnly 1", f"DataDirectory {data_dir}",
        f"SocksPort 127.0.0.1:{int(loc['socks_port'])}",
        f"ExitNodes {{{loc['country_code'].lower()}}}", "StrictNodes 1",
        "AvoidDiskWrites 1", "Log notice syslog", "",
    ])


def gateway_config(locations: list[dict]) -> dict:
    inbounds = []
    outbounds = [{"tag": "blocked", "protocol": "blackhole", "settings": {}}]
    rules = []
    for loc in locations:
        slug = loc["slug"]
        inbound_tag = f"gateway-{slug}"
        tor_tag = f"tor-{slug}"
        inbounds.append({
            "tag": inbound_tag, "listen": "0.0.0.0", "port": int(loc["gateway_port"]),
            "protocol": "shadowsocks",
            "settings": {"network": "tcp", "method": loc["ss_method"],
                         "password": decrypt_secret(loc["ss_password"])},
        })
        outbounds.append({
            "tag": tor_tag, "protocol": "socks",
            "settings": {"address": "127.0.0.1", "port": int(loc["socks_port"])},
        })
        rules.append({"type": "field", "inboundTag": [inbound_tag], "network": "udp",
                      "outboundTag": "blocked"})
        rules.append({"type": "field", "inboundTag": [inbound_tag], "network": "tcp",
                      "outboundTag": tor_tag})
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check)


def ensure_owner(path: Path, username: str) -> None:
    try:
        p = pwd.getpwnam(username)
    except KeyError:
        return
    os.chown(path, p.pw_uid, p.pw_gid)


def ensure_group(path: Path, group_name: str) -> None:
    import grp
    try:
        g = grp.getgrnam(group_name)
    except KeyError:
        return
    os.chown(path, 0, g.gr_gid)


def apply() -> None:
    if os.geteuid() != 0:
        raise SystemExit("helper must run as root")
    init_db()
    locations = list_locations(enabled_only=True)
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)
    desired = {loc["slug"] for loc in locations}
    existing = {p.name for p in INSTANCE_DIR.iterdir() if p.is_dir()}

    for slug in sorted(existing - desired):
        run("systemctl", "disable", "--now", f"tor-location@{slug}.service", check=False)
        shutil.rmtree(INSTANCE_DIR / slug, ignore_errors=True)
        shutil.rmtree(TOR_DATA_DIR / slug, ignore_errors=True)

    for loc in locations:
        slug = loc["slug"]
        cfg_dir = INSTANCE_DIR / slug
        cfg_dir.mkdir(parents=True, exist_ok=True)
        data_dir = TOR_DATA_DIR / slug
        data_dir.mkdir(parents=True, exist_ok=True)
        ensure_owner(data_dir, "debian-tor")
        torrc_path = cfg_dir / "torrc"
        atomic_write(torrc_path, torrc_for(loc), 0o640)
        ensure_group(torrc_path, "debian-tor")
        run("systemctl", "enable", f"tor-location@{slug}.service", check=False)

    config = gateway_config(locations)
    encoded = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    temp = GATEWAY_CONFIG.with_suffix(".json.new")
    atomic_write(temp, encoded, 0o640)
    if locations:
        checked = run(XRAY_BIN, "run", "-test", "-config", str(temp), check=False)
        if checked.returncode != 0:
            temp.unlink(missing_ok=True)
            raise RuntimeError(f"Xray config validation failed:\n{checked.stdout}")
    os.replace(temp, GATEWAY_CONFIG)
    ensure_group(GATEWAY_CONFIG, "torpanel")

    run("systemctl", "daemon-reload")
    for loc in locations:
        run("systemctl", "restart", f"tor-location@{loc['slug']}.service")
    if locations:
        run("systemctl", "enable", "--now", "tor-location-gateway.service", check=False)
        run("systemctl", "restart", "tor-location-gateway.service")
    else:
        run("systemctl", "disable", "--now", "tor-location-gateway.service", check=False)


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] != "apply":
        raise SystemExit("usage: python -m torpanel.helper apply")
    apply()


if __name__ == "__main__":
    main()
