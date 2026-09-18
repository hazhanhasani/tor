from __future__ import annotations

import ipaddress
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from .config import ENV_FILE, GATEWAY_CONFIG, INSTANCE_DIR, TOR_DATA_DIR, XRAY_BIN
from .db import get_setting, init_db, list_locations, list_tunnel_links, set_setting
from .security import decrypt_secret

NODE_AGENT_CONFIG = Path("/etc/tor-location-node/agent.json")
PANEL_TLS_DIR = Path("/etc/tor-location-manager/tls")
PANEL_TLS_CERT = PANEL_TLS_DIR / "panel.crt"
PANEL_TLS_KEY = PANEL_TLS_DIR / "panel.key"
PANEL_CREDENTIALS_FILE = Path("/root/tor-location-manager-credentials.txt")


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


def atomic_write_bytes(path: Path, content: bytes, mode: int = 0o640) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.read_bytes() == content:
            os.chmod(path, mode)
            return False
    except OSError:
        pass
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
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


def _panel_env_update(values: dict[str, str]) -> bool:
    path = Path(ENV_FILE)
    rows = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = dict(values)
    output: list[str] = []
    changed = False
    for raw in rows:
        if "=" not in raw or raw.lstrip().startswith("#"):
            output.append(raw)
            continue
        key = raw.split("=", 1)[0].strip()
        if key not in remaining:
            output.append(raw)
            continue
        new_line = f"{key}={remaining.pop(key)}"
        output.append(new_line)
        if raw != new_line:
            changed = True
    for key, value in remaining.items():
        output.append(f"{key}={value}")
        changed = True
    encoded = "\n".join(output).rstrip() + "\n"
    try:
        if path.read_text(encoding="utf-8") == encoded:
            return False
    except OSError:
        pass
    atomic_write(path, encoded, 0o640)
    ensure_group(path, "torpanel")
    return changed


def _hostname_matches(pattern: str, host: str) -> bool:
    pattern = pattern.strip().lower().rstrip(".")
    host = host.strip().lower().rstrip(".")
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        host_labels = host.split(".")
        suffix_labels = suffix.split(".")
        return len(host_labels) == len(suffix_labels) + 1 and host_labels[1:] == suffix_labels
    return False


def _validate_tls_pair(cert_bytes: bytes, key_bytes: bytes, public_host: str) -> None:
    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
        key = serialization.load_pem_private_key(key_bytes, password=None)
    except Exception as exc:
        raise RuntimeError(f"Invalid x-ui TLS certificate/key: {exc}") from exc

    cert_public = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if cert_public != key_public:
        raise RuntimeError("x-ui certificate and private key do not match.")

    now = datetime.now(timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if now < not_before or now >= not_after:
        raise RuntimeError("x-ui certificate is not currently valid.")

    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names.extend(str(value) for value in san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    if not names:
        names.extend(
            attribute.value
            for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if attribute.value
        )
    if not any(_hostname_matches(name, public_host) for name in names):
        raise RuntimeError(
            f"x-ui certificate does not cover panel hostname {public_host}."
        )


def _schedule_panel_restart() -> None:
    unit = f"tor-location-panel-restart-{int(time.time())}"
    result = run(
        "systemd-run",
        f"--unit={unit}",
        "--on-active=2s",
        "--collect",
        "/bin/systemctl",
        "restart",
        "tor-location-panel.service",
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout.strip() or "Could not schedule panel restart.")


def _update_credentials_url(url: str) -> None:
    if not PANEL_CREDENTIALS_FILE.exists():
        return
    try:
        rows = PANEL_CREDENTIALS_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    output: list[str] = []
    replaced = False
    for row in rows:
        if row.startswith("URL:"):
            output.append(f"URL: {url}")
            replaced = True
        else:
            output.append(row)
    if not replaced:
        output.insert(0, f"URL: {url}")
    atomic_write(PANEL_CREDENTIALS_FILE, "\n".join(output).rstrip() + "\n", 0o600)


def _map_container_mount_path(path: Path, mounts: list[dict]) -> Path | None:
    """Map a path reported inside a container to its host bind/volume source."""
    raw = str(path)
    candidates: list[tuple[int, Path]] = []
    for mount in mounts:
        if not isinstance(mount, dict):
            continue
        destination = str(mount.get("Destination") or "").rstrip("/")
        source = str(mount.get("Source") or "").rstrip("/")
        if not destination or destination == "/" or not source:
            continue
        if raw == destination or raw.startswith(destination + "/"):
            suffix = raw[len(destination):].lstrip("/")
            host_path = Path(source) / suffix if suffix else Path(source)
            candidates.append((len(destination), host_path))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _container_tls_pairs(cert_path: Path, key_path: Path) -> list[tuple[Path, Path, str]]:
    pairs: list[tuple[Path, Path, str]] = []
    for runtime in ("docker", "podman"):
        binary = shutil.which(runtime)
        if not binary:
            continue
        ids_result = run(binary, "ps", "-q", check=False)
        ids = [item for item in ids_result.stdout.split() if item]
        if not ids:
            continue
        inspect = run(binary, "inspect", *ids, check=False)
        if inspect.returncode != 0:
            continue
        try:
            containers = json.loads(inspect.stdout)
        except Exception:
            continue
        if not isinstance(containers, list):
            continue
        for item in containers:
            if not isinstance(item, dict):
                continue
            mounts = item.get("Mounts")
            if not isinstance(mounts, list):
                continue
            mapped_cert = _map_container_mount_path(cert_path, mounts)
            mapped_key = _map_container_mount_path(key_path, mounts)
            if mapped_cert is None or mapped_key is None:
                continue
            name = str(item.get("Name") or "").lstrip("/") or str(item.get("Id") or "")[:12]
            pairs.append((mapped_cert, mapped_key, f"{runtime}:{name or 'container'}"))
    return pairs


def _is_tls_namespace_process(comm: str, cmdline: str) -> bool:
    text = f"{comm} {cmdline}".lower()
    # 3x-ui may launch Xray in a different mount namespace from its web process.
    # Reverse proxies can also own the real certificate path while the x-ui API
    # still reports that path. Restrict discovery to relevant TLS-serving
    # processes rather than scanning every process namespace on the host.
    return any(
        token in text
        for token in ("x-ui", "xray", "nginx", "caddy", "apache2", "httpd", "haproxy")
    )


def _proc_namespace_tls_pairs(cert_path: Path, key_path: Path) -> list[tuple[Path, Path, str]]:
    """Resolve x-ui certificate paths through relevant process mount namespaces.

    This covers Docker/LXC/containerd setups where the x-ui API reports a path
    such as /root/cert/... that exists only inside the Xray, x-ui, or reverse
    proxy namespace. The privileged helper reads it via /proc/<pid>/root without
    requiring Docker socket access.
    """
    pairs: list[tuple[Path, Path, str]] = []
    proc = Path("/proc")
    try:
        entries = list(proc.iterdir())
    except OSError:
        return pairs
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8", errors="ignore").strip().lower()
            cmdline = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="ignore").lower()
        except OSError:
            continue
        if not _is_tls_namespace_process(comm, cmdline):
            continue
        root = entry / "root"
        cert_candidate = root / str(cert_path).lstrip("/")
        key_candidate = root / str(key_path).lstrip("/")
        # Only advertise namespaces where at least one reported path exists.
        # This keeps diagnostics concise and avoids misleading proc candidates.
        if not cert_candidate.exists() and not key_candidate.exists():
            continue
        pairs.append((cert_candidate, key_candidate, f"proc:{entry.name}:{comm or 'tls-process'}"))
    return pairs


def _common_tls_pairs(public_host: str) -> list[tuple[Path, Path, str]]:
    host = public_host.strip().lower().rstrip(".")
    return [
        (
            Path("/root/cert") / host / "fullchain.pem",
            Path("/root/cert") / host / "privkey.pem",
            "3x-ui-acme",
        ),
        (
            Path("/root/.acme.sh") / f"{host}_ecc" / "fullchain.cer",
            Path("/root/.acme.sh") / f"{host}_ecc" / f"{host}.key",
            "acme.sh-ecc",
        ),
        (
            Path("/root/.acme.sh") / host / "fullchain.cer",
            Path("/root/.acme.sh") / host / f"{host}.key",
            "acme.sh",
        ),
        (
            Path("/etc/letsencrypt/live") / host / "fullchain.pem",
            Path("/etc/letsencrypt/live") / host / "privkey.pem",
            "letsencrypt",
        ),
    ]


def _resolve_panel_tls_source(
    cert_setting: str, key_setting: str, public_host: str
) -> tuple[Path, Path, str]:
    cert_source = Path(cert_setting)
    key_source = Path(key_setting)
    candidates: list[tuple[Path, Path, str]] = [
        (cert_source, key_source, "x-ui-api"),
        *_container_tls_pairs(cert_source, key_source),
        *_proc_namespace_tls_pairs(cert_source, key_source),
        *_common_tls_pairs(public_host),
    ]

    seen: set[tuple[str, str]] = set()
    checked: list[str] = []
    for cert_candidate, key_candidate, source in candidates:
        pair_key = (str(cert_candidate), str(key_candidate))
        if pair_key in seen:
            continue
        seen.add(pair_key)
        checked.append(f"{source}:{cert_candidate}")
        try:
            cert_path = cert_candidate.resolve(strict=True)
            key_path = key_candidate.resolve(strict=True)
        except OSError:
            continue
        if cert_path.is_file() and key_path.is_file():
            return cert_path, key_path, source

    detail = "; ".join(checked[:6])
    raise RuntimeError(
        "فایل SSL اعلام‌شده توسط 3x-ui روی Host یا namespace پردازش x-ui/Xray/Reverse Proxy پیدا نشد. "
        "اگر دامنه فقط با Cloudflare Edge TLS باز می‌شود، Private Key آن گواهی روی این سرور وجود ندارد و قابل کپی نیست. "
        f"مسیرهای بررسی‌شده: {detail}"
    )


def sync_panel_tls(*, restart: bool = False) -> dict[str, str | bool]:
    if os.geteuid() != 0:
        raise SystemExit("helper must run as root")
    init_db()
    enabled = get_setting("panel_tls_enabled", "0") == "1"
    if not enabled:
        fallback_port = get_setting("panel_http_fallback_port", "8787") or "8787"
        changed = _panel_env_update({
            "TORPANEL_TLS_ENABLED": "0",
            "TORPANEL_PORT": fallback_port,
            "TORPANEL_PUBLIC_HOST": "",
            "TORPANEL_TLS_CERTFILE": str(PANEL_TLS_CERT),
            "TORPANEL_TLS_KEYFILE": str(PANEL_TLS_KEY),
        })
        _update_credentials_url(f"http://SERVER_IP:{fallback_port}")
        if restart and changed:
            _schedule_panel_restart()
        return {"enabled": False, "changed": changed, "url": ""}

    public_host = (get_setting("panel_tls_public_host", "") or "").strip().lower()
    try:
        port = int(get_setting("panel_tls_port", "2096") or 2096)
    except ValueError as exc:
        raise RuntimeError("Panel TLS port is invalid.") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("Panel TLS port is outside the valid range.")
    if not public_host:
        raise RuntimeError("Panel TLS public hostname is missing.")

    cert_setting = (get_setting("panel_tls_source_cert", "") or "").strip()
    key_setting = (get_setting("panel_tls_source_key", "") or "").strip()
    if not cert_setting or not key_setting:
        raise RuntimeError("x-ui certificate source paths are not configured.")
    cert_path, key_path, tls_source = _resolve_panel_tls_source(
        cert_setting, key_setting, public_host
    )

    cert_bytes = cert_path.read_bytes()
    key_bytes = key_path.read_bytes()
    if not cert_bytes or len(cert_bytes) > 2 * 1024 * 1024:
        raise RuntimeError("x-ui certificate file size is invalid.")
    if not key_bytes or len(key_bytes) > 512 * 1024:
        raise RuntimeError("x-ui private-key file size is invalid.")
    _validate_tls_pair(cert_bytes, key_bytes, public_host)

    PANEL_TLS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(PANEL_TLS_DIR, 0o750)
    ensure_group(PANEL_TLS_DIR, "torpanel")
    cert_changed = atomic_write_bytes(PANEL_TLS_CERT, cert_bytes, 0o644)
    key_changed = atomic_write_bytes(PANEL_TLS_KEY, key_bytes, 0o640)
    ensure_group(PANEL_TLS_CERT, "torpanel")
    ensure_group(PANEL_TLS_KEY, "torpanel")

    env_changed = _panel_env_update({
        "TORPANEL_TLS_ENABLED": "1",
        "TORPANEL_PORT": str(port),
        "TORPANEL_PUBLIC_HOST": public_host,
        "TORPANEL_TLS_CERTFILE": str(PANEL_TLS_CERT),
        "TORPANEL_TLS_KEYFILE": str(PANEL_TLS_KEY),
    })
    suffix = "" if port == 443 else f":{port}"
    public_url = f"https://{public_host}{suffix}"
    _update_credentials_url(public_url)
    changed = cert_changed or key_changed or env_changed
    if restart and changed:
        _schedule_panel_restart()
    return {
        "enabled": True,
        "changed": changed,
        "url": public_url,
        "source": tls_source,
    }


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
    if len(sys.argv) >= 2 and sys.argv[1] == "apply":
        if len(sys.argv) != 2:
            raise SystemExit("usage: python -m torpanel.helper apply")
        apply()
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "panel-tls-sync":
        restart = "--restart" in sys.argv[2:]
        try:
            result = sync_panel_tls(restart=restart)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            raise SystemExit(1)
        if result.get("url"):
            source = result.get("source") or "x-ui"
            print(f"Panel HTTPS: {result['url']} (certificate source: {source})")
        else:
            print("Panel HTTPS disabled; HTTP fallback restored.")
        return
    if len(sys.argv) == 2 and sys.argv[1] == "panel-tls-disable":
        if os.geteuid() != 0:
            raise SystemExit("helper must run as root")
        init_db()
        set_setting("panel_tls_enabled", "0")
        try:
            sync_panel_tls(restart=True)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print("Panel HTTPS disabled. HTTP fallback will be restored on port 8787.")
        return
    raise SystemExit(
        "usage: python -m torpanel.helper {apply|panel-tls-sync [--restart]|panel-tls-disable}"
    )


if __name__ == "__main__":
    main()
