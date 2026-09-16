from __future__ import annotations

import ipaddress
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import GATEWAY_CONFIG, INSTANCE_DIR, TOR_DATA_DIR, XRAY_BIN
from .db import get_setting, init_db, list_locations, list_tunnel_links
from .security import decrypt_secret

NODE_AGENT_CONFIG = Path("/etc/tor-location-node/agent.json")


def atomic_write(path: Path, content: str, mode: int = 0o640) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.read_text(encoding="utf-8") == content:
            return False
    except OSError:
        pass
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
        return True
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def _tor_bridge_lines() -> list[str]:
    mode = (get_setting("tor_transport_mode", "direct") or "direct").strip().lower()
    if mode == "direct":
        return []
    if mode != "obfs4":
        raise RuntimeError(f"Unsupported Tor transport mode: {mode}")

    obfs4 = shutil.which("obfs4proxy") or "/usr/bin/obfs4proxy"
    if not Path(obfs4).exists():
        raise RuntimeError(
            "Tor bridge mode is enabled but obfs4proxy is not installed. "
            "Install the obfs4proxy package or switch Tor transport mode to direct."
        )

    raw_lines = get_setting("tor_bridge_lines", "")
    bridges: list[str] = []
    for raw in raw_lines.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("bridge "):
            line = line[7:].strip()
        if not line.lower().startswith("obfs4 "):
            raise RuntimeError("Every configured bridge must be an obfs4 bridge line.")
        bridges.append(line)
    if not bridges:
        raise RuntimeError("Tor bridge mode is enabled but no obfs4 bridge lines were configured.")

    return [
        "UseBridges 1",
        f"ClientTransportPlugin obfs4 exec {obfs4}",
        *[f"Bridge {line}" for line in bridges],
    ]


def _local_agent_node_uuid() -> str:
    try:
        payload = json.loads(NODE_AGENT_CONFIG.read_text(encoding="utf-8"))
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("node_uuid") or "").strip()


def local_tor_tunnel_source_ip() -> str:
    """Return the Iran overlay source for the tunnel agent installed on this host.

    This makes Tor integration automatic only when the local machine is actually
    the Iran node of a ready tunnel link. A controller hosted elsewhere therefore
    remains untouched. If several links ever point at the same local node, an
    explicitly selected `tor_tunnel_link_uuid` wins; otherwise a healthy link is
    preferred deterministically.
    """
    if (get_setting("tor_auto_tunnel_all_locations", "1") or "1").strip() != "1":
        return ""
    node_uuid = _local_agent_node_uuid()
    if not node_uuid:
        return ""
    candidates = [
        link for link in list_tunnel_links()
        if link.get("enabled")
        and str(link.get("iran_node_uuid") or "") == node_uuid
        and str(link.get("foreign_node_uuid") or "")
    ]
    if not candidates:
        return ""
    preferred = (get_setting("tor_tunnel_link_uuid", "") or "").strip()
    if preferred:
        selected = next((link for link in candidates if str(link.get("uuid") or "") == preferred), None)
        if selected is not None:
            candidates = [selected]
    candidates.sort(
        key=lambda link: (
            0 if str(link.get("active_transport") or "") in {"direct", "reverse"} else 1,
            str(link.get("uuid") or ""),
        )
    )
    source = str(candidates[0].get("iran_overlay_ip") or "").strip()
    try:
        ip = ipaddress.ip_address(source)
    except ValueError:
        return ""
    return source if ip.version == 4 else ""


def torrc_for(loc: dict, tunnel_source_ip: str = "") -> str:
    data_dir = TOR_DATA_DIR / loc["slug"]
    lines = [
        "ClientOnly 1",
        f"DataDirectory {data_dir}",
        f"SocksPort 127.0.0.1:{int(loc['socks_port'])}",
    ]
    if tunnel_source_ip:
        lines.append(f"OutboundBindAddress {tunnel_source_ip}")
    lines.extend([
        f"ExitNodes {{{loc['country_code'].lower()}}}",
        "StrictNodes 1",
        "AvoidDiskWrites 1",
        "Log notice syslog",
    ])
    lines.extend(_tor_bridge_lines())
    lines.append("")
    return "\n".join(lines)


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


def service_active(unit: str) -> bool:
    return run("systemctl", "is-active", "--quiet", unit, check=False).returncode == 0


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


def validation_temp_path(path: Path) -> Path:
    """Keep a .json suffix so Xray can auto-detect the config format."""
    return path.with_name(f"{path.stem}.new{path.suffix}")


def apply() -> None:
    if os.geteuid() != 0:
        raise SystemExit("helper must run as root")
    init_db()
    locations = list_locations(enabled_only=True)
    tunnel_source_ip = local_tor_tunnel_source_ip()
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)
    desired = {loc["slug"] for loc in locations}
    existing = {p.name for p in INSTANCE_DIR.iterdir() if p.is_dir()}

    removed_any = False
    for slug in sorted(existing - desired):
        run("systemctl", "disable", "--now", f"tor-location@{slug}.service", check=False)
        shutil.rmtree(INSTANCE_DIR / slug, ignore_errors=True)
        shutil.rmtree(TOR_DATA_DIR / slug, ignore_errors=True)
        removed_any = True

    changed_tor: set[str] = set()
    for loc in locations:
        slug = loc["slug"]
        cfg_dir = INSTANCE_DIR / slug
        cfg_dir.mkdir(parents=True, exist_ok=True)
        data_dir = TOR_DATA_DIR / slug
        data_dir.mkdir(parents=True, exist_ok=True)
        ensure_owner(data_dir, "debian-tor")
        torrc_path = cfg_dir / "torrc"
        if atomic_write(torrc_path, torrc_for(loc, tunnel_source_ip), 0o640):
            changed_tor.add(slug)
        ensure_group(torrc_path, "debian-tor")
        run("systemctl", "enable", f"tor-location@{slug}.service", check=False)

    config = gateway_config(locations)
    encoded = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    try:
        gateway_changed = GATEWAY_CONFIG.read_text(encoding="utf-8") != encoded
    except OSError:
        gateway_changed = True
    if gateway_changed:
        temp = validation_temp_path(GATEWAY_CONFIG)
        atomic_write(temp, encoded, 0o640)
        if locations:
            checked = run(XRAY_BIN, "run", "-test", "-config", str(temp), check=False)
            if checked.returncode != 0:
                temp.unlink(missing_ok=True)
                raise RuntimeError(f"Xray config validation failed:\n{checked.stdout}")
        os.replace(temp, GATEWAY_CONFIG)
        ensure_group(GATEWAY_CONFIG, "torpanel")

    if removed_any:
        run("systemctl", "daemon-reload", check=False)
    for loc in locations:
        unit = f"tor-location@{loc['slug']}.service"
        if loc["slug"] in changed_tor or not service_active(unit):
            run("systemctl", "restart", unit)
    if locations:
        run("systemctl", "enable", "tor-location-gateway.service", check=False)
        if gateway_changed or not service_active("tor-location-gateway.service"):
            run("systemctl", "restart", "tor-location-gateway.service")
    else:
        run("systemctl", "disable", "--now", "tor-location-gateway.service", check=False)

    if tunnel_source_ip:
        print(f"Tor egress for all managed locations is bound to tunnel overlay {tunnel_source_ip}.")
    else:
        print("Tor egress uses the normal host route; no local Iran tunnel agent is attached.")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] != "apply":
        raise SystemExit("usage: python -m torpanel.helper apply")
    apply()


if __name__ == "__main__":
    main()
