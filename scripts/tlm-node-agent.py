#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

AGENT_VERSION = "1.2.0"
CONFIG_DIR = Path("/etc/tor-location-node")
STATE_DIR = Path("/var/lib/tor-location-node")
AGENT_CONFIG = CONFIG_DIR / "agent.json"
PRIVATE_KEY_FILE = CONFIG_DIR / "wg.key"
PUBLIC_KEY_FILE = CONFIG_DIR / "wg.pub"
RUNTIME_STATE = STATE_DIR / "runtime.json"
SELF_PATH = Path("/usr/local/sbin/tlm-node-agent")
AGENT_UNIT = Path("/etc/systemd/system/tor-location-node-agent.service")
WG_DIR = Path("/etc/wireguard")
FRP_DIR = CONFIG_DIR / "frp"
UNIT_DIR = Path("/etc/systemd/system")


class AgentError(RuntimeError):
    pass


def run(*args: str, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        check=check,
    )


def atomic_write(path: Path, content: str, mode: int = 0o600) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    old = None
    try:
        old = path.read_text(encoding="utf-8")
    except OSError:
        pass
    if old == content:
        return False
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


def json_write(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n", mode)


def json_read(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else (default or {})
    except Exception:
        return default or {}


def ssl_context(insecure: bool) -> ssl.SSLContext:
    if insecure:
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def http_json(
    method: str,
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    token: str = "",
    insecure: bool = False,
    timeout: int = 25,
) -> dict[str, Any]:
    body = None
    headers = {"Accept": "application/json", "User-Agent": f"TorLocationNode/{AGENT_VERSION}"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context(insecure)) as resp:
            raw = resp.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as exc:
        detail = exc.read(8192).decode("utf-8", errors="replace")
        raise AgentError(f"Controller HTTP {exc.code}: {detail}") from exc
    except Exception as exc:
        raise AgentError(f"Controller request failed: {exc}") from exc
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise AgentError("Controller returned invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise AgentError("Controller returned invalid JSON object")
    return parsed


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("tlm-node-agent must run as root")


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def ensure_wireguard_keys() -> str:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    if PRIVATE_KEY_FILE.exists() and PUBLIC_KEY_FILE.exists():
        return PUBLIC_KEY_FILE.read_text(encoding="utf-8").strip()
    if not command_exists("wg"):
        raise AgentError("wireguard-tools is required")
    private = run("wg", "genkey").stdout.strip()
    public = run("wg", "pubkey", input_text=private + "\n").stdout.strip()
    atomic_write(PRIVATE_KEY_FILE, private + "\n", 0o600)
    atomic_write(PUBLIC_KEY_FILE, public + "\n", 0o644)
    return public


def platform_asset() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "linux_amd64"
    if machine in {"aarch64", "arm64"}:
        return "linux_arm64"
    raise AgentError(f"Unsupported FRP architecture: {machine}")


def _download_opener(insecure: bool) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [urllib.request.HTTPSHandler(context=ssl_context(insecure))]
    proxy = os.environ.get("TLM_DOWNLOAD_PROXY", "").strip()
    if proxy:
        handlers.insert(0, urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


def _download(
    url: str,
    destination: Path,
    *,
    insecure: bool = False,
    headers: dict[str, str] | None = None,
) -> None:
    request_headers = {"User-Agent": f"TorLocationNode/{AGENT_VERSION}"}
    request_headers.update(headers or {})
    req = urllib.request.Request(url, headers=request_headers)
    opener = _download_opener(insecure)
    with opener.open(req, timeout=180) as resp, destination.open("wb") as out:
        shutil.copyfileobj(resp, out)


def _download_json(url: str, insecure: bool = False) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": f"TorLocationNode/{AGENT_VERSION}"},
    )
    opener = _download_opener(insecure)
    with opener.open(req, timeout=30) as resp:
        data = json.load(resp)
    if not isinstance(data, dict):
        raise AgentError("FRP release metadata is invalid")
    return data


def install_frp(insecure: bool = False) -> None:
    if command_exists("frpc") and command_exists("frps"):
        return
    asset_suffix = platform_asset()
    api = os.environ.get("TLM_FRP_RELEASE_API", "https://api.github.com/repos/fatedier/frp/releases/latest")
    try:
        release = _download_json(api, insecure=insecure)
    except Exception as exc:
        raise AgentError(
            "FRP download metadata is unavailable. Preinstall frpc/frps, set TLM_DOWNLOAD_PROXY, "
            "or set TLM_FRP_RELEASE_API to an accessible mirror."
        ) from exc
    assets = release.get("assets") if isinstance(release, dict) else []
    selected = None
    for item in assets or []:
        name = str(item.get("name") or "")
        if name.endswith(f"_{asset_suffix}.tar.gz"):
            selected = item
            break
    if not selected:
        raise AgentError(f"FRP release asset for {asset_suffix} was not found")
    digest = str(selected.get("digest") or "")
    if not digest.startswith("sha256:"):
        raise AgentError("FRP release does not expose a trusted SHA-256 digest")
    expected = digest.split(":", 1)[1].lower()
    browser_url = str(selected.get("browser_download_url") or "")
    api_asset_url = str(selected.get("url") or "")
    if not browser_url and not api_asset_url:
        raise AgentError("FRP release asset URL is missing")

    with tempfile.TemporaryDirectory(prefix="tlm-frp-") as tmp_name:
        tmp = Path(tmp_name)
        archive = tmp / "frp.tar.gz"
        errors: list[str] = []
        candidates = [
            (browser_url, {}),
            (api_asset_url, {"Accept": "application/octet-stream"}),
        ]
        downloaded = False
        for url, headers in candidates:
            if not url:
                continue
            try:
                _download(url, archive, insecure=insecure, headers=headers)
                downloaded = True
                break
            except Exception as exc:
                errors.append(str(exc))
                archive.unlink(missing_ok=True)
        if not downloaded:
            raise AgentError("FRP download failed through direct Release and GitHub API asset paths: " + " | ".join(errors[-2:]))
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != expected:
            raise AgentError("FRP SHA-256 verification failed")
        extract = tmp / "extract"
        extract.mkdir()
        with tarfile.open(archive, "r:gz") as tf:
            root = extract.resolve()
            for member in tf.getmembers():
                target = (extract / member.name).resolve()
                if target != root and root not in target.parents:
                    raise AgentError("Unsafe FRP archive path")
                if member.issym() or member.islnk():
                    raise AgentError("FRP archive links are not allowed")
            tf.extractall(extract)
        frpc = next(extract.rglob("frpc"), None)
        frps = next(extract.rglob("frps"), None)
        if not frpc or not frps:
            raise AgentError("FRP binaries are missing from the verified archive")
        shutil.copy2(frpc, "/usr/local/bin/frpc")
        shutil.copy2(frps, "/usr/local/bin/frps")
        os.chmod("/usr/local/bin/frpc", 0o755)
        os.chmod("/usr/local/bin/frps", 0o755)


def os_info() -> str:
    try:
        lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
        values = dict(line.split("=", 1) for line in lines if "=" in line)
        return (values.get("PRETTY_NAME") or values.get("NAME") or platform.platform()).strip('"')[:200]
    except Exception:
        return platform.platform()[:200]


def capabilities() -> dict[str, Any]:
    values: dict[str, Any] = {
        "wireguard": command_exists("wg"),
        "wg_quick": command_exists("wg-quick"),
        "frpc": command_exists("frpc"),
        "frps": command_exists("frps"),
        "nft": command_exists("nft"),
        "policy_routing": command_exists("ip"),
        "architecture": platform.machine(),
    }
    for name in ("wg", "frpc", "frps"):
        path = shutil.which(name)
        if not path:
            continue
        try:
            out = run(path, "--version", check=False).stdout.splitlines()
            values[f"{name}_version"] = out[0][:120] if out else "installed"
        except Exception:
            values[f"{name}_version"] = "installed"
    return values


def install_agent(panel: str, token: str, name: str, advertise_host: str, insecure: bool, allow_http: bool) -> None:
    require_root()
    panel = panel.rstrip("/")
    if not panel.startswith(("https://", "http://")):
        raise AgentError("--panel must start with https:// or http://")
    if panel.startswith("http://") and not allow_http:
        raise AgentError("Plain HTTP enrollment is disabled. Use HTTPS or pass --allow-http explicitly.")
    for cmd in ("wg", "wg-quick", "systemctl", "ip", "ping"):
        if not command_exists(cmd):
            raise AgentError(f"Required command is missing: {cmd}")
    public_key = ensure_wireguard_keys()
    install_frp(insecure=insecure)

    payload = {
        "token": token,
        "name": name,
        "advertise_host": advertise_host,
        "wg_public_key": public_key,
        "agent_version": AGENT_VERSION,
        "os_info": os_info(),
        "capabilities": capabilities(),
    }
    enrolled = http_json("POST", panel + "/api/tunnels/enroll", payload=payload, insecure=insecure)
    node_uuid = str(enrolled.get("node_uuid") or "")
    agent_token = str(enrolled.get("agent_token") or "")
    if not node_uuid or not agent_token:
        raise AgentError("Controller enrollment response is incomplete")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    FRP_DIR.mkdir(parents=True, exist_ok=True)
    WG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    os.chmod(STATE_DIR, 0o700)
    json_write(AGENT_CONFIG, {
        "panel": panel,
        "node_uuid": node_uuid,
        "agent_token": agent_token,
        "advertise_host": advertise_host,
        "insecure": bool(insecure),
        "allow_http": bool(allow_http),
    })

    source = Path(__file__).read_bytes()
    SELF_PATH.write_bytes(source)
    os.chmod(SELF_PATH, 0o755)
    unit = """[Unit]\nDescription=Tor Location Hybrid Tunnel Node Agent\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=/usr/local/sbin/tlm-node-agent run\nRestart=always\nRestartSec=5\nNoNewPrivileges=false\nProtectHome=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n"""
    atomic_write(AGENT_UNIT, unit, 0o644)
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", "tor-location-node-agent.service")
    print(f"Node enrolled: {node_uuid}")
    print("Hybrid tunnel agent is running.")


def upgrade_agent(panel: str, insecure: bool, allow_http: bool) -> None:
    require_root()
    config = json_read(AGENT_CONFIG)
    if not config:
        raise AgentError("Node is not enrolled; use the normal install command first")
    panel = (panel or str(config.get("panel") or "")).rstrip("/")
    if not panel.startswith(("https://", "http://")):
        raise AgentError("--panel must start with https:// or http://")
    if panel.startswith("http://") and not (allow_http or bool(config.get("allow_http"))):
        raise AgentError("Plain HTTP controller requires --allow-http")
    config["panel"] = panel
    if insecure:
        config["insecure"] = True
    if allow_http:
        config["allow_http"] = True
    json_write(AGENT_CONFIG, config)
    source = Path(__file__).read_bytes()
    SELF_PATH.write_bytes(source)
    os.chmod(SELF_PATH, 0o755)
    run("systemctl", "daemon-reload", check=False)
    run("systemctl", "restart", "tor-location-node-agent.service", check=False)
    print(f"Node agent upgraded to {AGENT_VERSION}.")


def endpoint_text(host: str, port: int) -> str:
    host = host.strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{int(port)}"


def _wg_config(link: dict[str, Any], private_key: str, endpoint: dict[str, Any] | None) -> str:
    peer = link.get("peer") or {}
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {link['address']}",
        "Table = off",
    ]
    if int(link.get("listen_port") or 0) > 0:
        lines.append(f"ListenPort = {int(link['listen_port'])}")
    lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {peer['public_key']}",
        f"PresharedKey = {link['preshared_key']}",
        f"AllowedIPs = {','.join(link['peer_allowed_ips'])}",
    ])
    if endpoint and endpoint.get("host"):
        lines.append(f"Endpoint = {endpoint_text(str(endpoint['host']), int(endpoint['port']))}")
        lines.append("PersistentKeepalive = 15")
    return "\n".join(lines) + "\n"


def ensure_wg(link: dict[str, Any], endpoint: dict[str, Any] | None) -> None:
    iface = str(link["interface"])
    if not re.fullmatch(r"tlm[a-f0-9]{1,7}", iface):
        raise AgentError("Controller returned an unsafe interface name")
    private_key = PRIVATE_KEY_FILE.read_text(encoding="utf-8").strip()
    content = _wg_config(link, private_key, endpoint)
    cfg = WG_DIR / f"{iface}.conf"
    changed = atomic_write(cfg, content, 0o600)
    active = run("wg", "show", iface, check=False).returncode == 0
    if changed and active:
        run("wg-quick", "down", iface, check=False)
        active = False
    if not active:
        result = run("wg-quick", "up", iface, check=False)
        if result.returncode != 0:
            raise AgentError(f"WireGuard {iface} failed: {result.stdout.strip()}")


def set_wg_endpoint(link: dict[str, Any], endpoint: dict[str, Any]) -> None:
    peer = link.get("peer") or {}
    host = str(endpoint.get("host") or "")
    if not host:
        raise AgentError("Tunnel endpoint host is empty")
    result = run(
        "wg", "set", str(link["interface"]), "peer", str(peer["public_key"]),
        "endpoint", endpoint_text(host, int(endpoint["port"])), check=False,
    )
    if result.returncode != 0:
        raise AgentError(result.stdout.strip() or "wg endpoint update failed")


def _frp_unit_name(side: str, short: str) -> str:
    return f"tlm-frp-{side}-{short}.service"


def ensure_frp(link: dict[str, Any]) -> None:
    frp = link["frp"]
    short = str(link["uuid"]).replace("-", "")[:8]
    side = str(frp.get("side") or "")
    if side == "server":
        cfg = FRP_DIR / f"frps-{short}.toml"
        content = "\n".join([
            f'bindAddr = "{frp["bind_host"]}"',
            f'bindPort = {int(frp["control_port"])}',
            f'proxyBindAddr = "{frp["proxy_bind_host"]}"',
            'auth.method = "token"',
            f'auth.token = "{frp["token"]}"',
            'transport.tls.force = true',
            'log.to = "console"',
            'log.level = "warn"',
            "",
        ])
        binary = "/usr/local/bin/frps"
    elif side == "client":
        server_host = str(frp.get("server_host") or "")
        if not server_host:
            raise AgentError("Iran node endpoint is not available for reverse tunnel")
        cfg = FRP_DIR / f"frpc-{short}.toml"
        content = "\n".join([
            f'serverAddr = "{server_host}"',
            f'serverPort = {int(frp["server_port"])}',
            'loginFailExit = false',
            'auth.method = "token"',
            f'auth.token = "{frp["token"]}"',
            'transport.protocol = "tcp"',
            'transport.tls.enable = true',
            'log.to = "console"',
            'log.level = "warn"',
            '',
            '[[proxies]]',
            f'name = "wg-{short}"',
            'type = "udp"',
            'localIP = "127.0.0.1"',
            f'localPort = {int(frp["local_wg_port"])}',
            f'remotePort = {int(frp["remote_udp_port"])}',
            'transport.useEncryption = true',
            'transport.useCompression = false',
            "",
        ])
        binary = "/usr/local/bin/frpc"
    else:
        return
    changed = atomic_write(cfg, content, 0o600)
    unit_name = _frp_unit_name(side, short)
    unit_path = UNIT_DIR / unit_name
    unit = "\n".join([
        "[Unit]",
        f"Description=TLM hybrid reverse tunnel {side} {short}",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"ExecStart={binary} -c {cfg}",
        "Restart=always",
        "RestartSec=3",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectHome=true",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ])
    unit_changed = atomic_write(unit_path, unit, 0o644)
    if unit_changed:
        run("systemctl", "daemon-reload")
    run("systemctl", "enable", unit_name, check=False)
    if changed or unit_changed:
        run("systemctl", "restart", unit_name, check=False)
    elif run("systemctl", "is-active", "--quiet", unit_name, check=False).returncode != 0:
        run("systemctl", "start", unit_name, check=False)


def stop_frp(link: dict[str, Any]) -> None:
    short = str(link["uuid"]).replace("-", "")[:8]
    for side in ("server", "client"):
        name = _frp_unit_name(side, short)
        run("systemctl", "disable", "--now", name, check=False)


def peer_ping(ip: str) -> tuple[bool, float | None]:
    started = time.monotonic()
    result = run("ping", "-c", "1", "-W", "2", ip, check=False)
    elapsed = (time.monotonic() - started) * 1000
    return result.returncode == 0, round(elapsed, 1) if result.returncode == 0 else None


def load_runtime() -> dict[str, Any]:
    return json_read(RUNTIME_STATE, {"links": {}, "egress": {}})


def save_runtime(value: dict[str, Any]) -> None:
    json_write(RUNTIME_STATE, value)


def choose_path(link: dict[str, Any], runtime: dict[str, Any]) -> tuple[str, float | None, str]:
    if link["role"] != "iran":
        ok, rtt = peer_ping(str(link["peer_ip"]))
        return ("passive" if ok else "pending"), rtt, "foreign-passive"

    mode = str(link.get("mode") or "auto")
    direct = link.get("direct_endpoint")
    reverse = link.get("reverse_endpoint")
    if mode == "direct":
        set_wg_endpoint(link, direct)
        time.sleep(0.6)
        ok, rtt = peer_ping(str(link["peer_ip"]))
        return ("direct" if ok else "down"), rtt, "forced-direct"
    if mode == "reverse":
        set_wg_endpoint(link, reverse)
        time.sleep(0.8)
        ok, rtt = peer_ping(str(link["peer_ip"]))
        return ("reverse" if ok else "down"), rtt, "forced-reverse"

    links_state = runtime.setdefault("links", {})
    item = links_state.setdefault(link["uuid"], {})
    current = str(item.get("transport") or "direct")
    last_probe = float(item.get("last_direct_probe") or 0)
    now = time.time()

    if current == "reverse":
        set_wg_endpoint(link, reverse)
        ok, rtt = peer_ping(str(link["peer_ip"]))
        if ok and now - last_probe < 180:
            return "reverse", rtt, "reverse-healthy"
        item["last_direct_probe"] = now
        set_wg_endpoint(link, direct)
        time.sleep(1.0)
        direct_ok, direct_rtt = peer_ping(str(link["peer_ip"]))
        if direct_ok:
            item["transport"] = "direct"
            return "direct", direct_rtt, "direct-recovered"
        set_wg_endpoint(link, reverse)
        time.sleep(0.5)
        reverse_ok, reverse_rtt = peer_ping(str(link["peer_ip"]))
        item["transport"] = "reverse" if reverse_ok else "down"
        return ("reverse" if reverse_ok else "down"), reverse_rtt, "direct-probe-failed"

    set_wg_endpoint(link, direct)
    ok, rtt = peer_ping(str(link["peer_ip"]))
    if ok:
        item["transport"] = "direct"
        return "direct", rtt, "direct-healthy"
    set_wg_endpoint(link, reverse)
    time.sleep(0.8)
    ok, rtt = peer_ping(str(link["peer_ip"]))
    item["transport"] = "reverse" if ok else "down"
    return ("reverse" if ok else "down"), rtt, "direct-failed"


def _validate_egress(link: dict[str, Any]) -> tuple[str, int, int]:
    egress = link.get("egress") or {}
    source = str(egress.get("source_ip") or "")
    try:
        ip = ipaddress.ip_address(source)
    except ValueError as exc:
        raise AgentError("Invalid egress source IP") from exc
    if ip.version != 4:
        raise AgentError("Only IPv4 egress is currently supported")
    table = int(egress.get("route_table") or 0)
    priority = int(egress.get("rule_priority") or 0)
    if not 10000 <= table <= 29999 or not 10000 <= priority <= 29999:
        raise AgentError("Invalid policy-routing table or priority")
    return source, table, priority


def ensure_egress(link: dict[str, Any]) -> dict[str, Any]:
    source, table, priority = _validate_egress(link)
    if link["role"] == "iran":
        iface = str(link["interface"])
        run("ip", "-4", "route", "replace", "blackhole", "default", "table", str(table), "metric", "32767", check=False)
        route = run(
            "ip", "-4", "route", "replace", "default", "dev", iface, "table", str(table), "metric", "10",
            check=False,
        )
        if route.returncode != 0:
            raise AgentError(route.stdout.strip() or "failed to install tunnel egress route")
        run(
            "ip", "-4", "rule", "del", "pref", str(priority), "from", f"{source}/32", "lookup", str(table),
            check=False,
        )
        rule = run(
            "ip", "-4", "rule", "add", "pref", str(priority), "from", f"{source}/32", "lookup", str(table),
            check=False,
        )
        if rule.returncode != 0 and "File exists" not in rule.stdout:
            raise AgentError(rule.stdout.strip() or "failed to install tunnel policy rule")
    else:
        try:
            Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n", encoding="ascii")
        except OSError as exc:
            raise AgentError(f"failed to enable IPv4 forwarding: {exc}") from exc
    return {
        "role": link["role"],
        "source_ip": source,
        "route_table": table,
        "rule_priority": priority,
        "interface": str(link["interface"]),
    }


def cleanup_stale_egress(runtime: dict[str, Any], desired: dict[str, dict[str, Any]]) -> None:
    previous = runtime.get("egress") if isinstance(runtime.get("egress"), dict) else {}
    for link_uuid, item in previous.items():
        if link_uuid in desired or not isinstance(item, dict) or item.get("role") != "iran":
            continue
        source = str(item.get("source_ip") or "")
        table = int(item.get("route_table") or 0)
        priority = int(item.get("rule_priority") or 0)
        if source and table and priority:
            run(
                "ip", "-4", "rule", "del", "pref", str(priority), "from", f"{source}/32", "lookup", str(table),
                check=False,
            )
            run("ip", "-4", "route", "flush", "table", str(table), check=False)
    runtime["egress"] = desired


def apply_firewall(links: list[dict[str, Any]]) -> dict[str, Any]:
    if not command_exists("nft"):
        return {"enabled": False, "reason": "nft-not-installed"}
    ready = [link for link in links if link.get("ready")]
    guarded = [link for link in ready if link.get("kill_switch")]
    foreign = [link for link in ready if link.get("role") == "foreign"]
    run("nft", "delete", "table", "inet", "tlm_tunnel", check=False)
    run("nft", "delete", "table", "ip", "tlm_tunnel_nat", check=False)

    errors: list[str] = []
    if guarded:
        commands = [
            "add table inet tlm_tunnel",
            "add chain inet tlm_tunnel input { type filter hook input priority -40; policy accept; }",
        ]
        for link in guarded:
            if link["role"] == "foreign":
                fw = link.get("firewall") or {}
                port = int(fw.get("wg_port") or 0)
                source = str(fw.get("allow_source") or "")
                if port:
                    commands.append(f'add rule inet tlm_tunnel input iifname "lo" udp dport {port} accept')
                    try:
                        ip = ipaddress.ip_address(source)
                        family = "ip6" if ip.version == 6 else "ip"
                        commands.append(f"add rule inet tlm_tunnel input {family} saddr {source} udp dport {port} accept")
                    except ValueError:
                        pass
                    commands.append(f"add rule inet tlm_tunnel input udp dport {port} drop")
            elif link["role"] == "iran":
                frp = link.get("frp") or {}
                port = int(frp.get("control_port") or 0)
                source = str(frp.get("allow_source") or "")
                if port and source:
                    try:
                        ip = ipaddress.ip_address(source)
                        family = "ip6" if ip.version == 6 else "ip"
                        commands.append(f"add rule inet tlm_tunnel input {family} saddr {source} tcp dport {port} accept")
                        commands.append(f"add rule inet tlm_tunnel input tcp dport {port} drop")
                    except ValueError:
                        pass
        result = run("nft", "-f", "-", check=False, input_text="\n".join(commands) + "\n")
        if result.returncode != 0:
            errors.append(result.stdout.strip()[:500])

    if foreign:
        nat = [
            "add table ip tlm_tunnel_nat",
            "add chain ip tlm_tunnel_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }",
        ]
        for link in foreign:
            egress = link.get("egress") or {}
            source = str(egress.get("source_ip") or "")
            iface = str(link.get("interface") or "")
            try:
                ipaddress.IPv4Address(source)
            except ValueError:
                continue
            if not re.fullmatch(r"tlm[a-f0-9]{1,7}", iface):
                continue
            nat.append(
                f'add rule ip tlm_tunnel_nat postrouting ip saddr {source}/32 oifname != "{iface}" masquerade'
            )
        result = run("nft", "-f", "-", check=False, input_text="\n".join(nat) + "\n")
        if result.returncode != 0:
            errors.append(result.stdout.strip()[:500])

    return {"enabled": not errors, "errors": errors}


def cleanup_stale(desired_ifaces: set[str], desired_frp_units: set[str]) -> None:
    for cfg in WG_DIR.glob("tlm*.conf"):
        iface = cfg.stem
        if iface not in desired_ifaces:
            run("wg-quick", "down", iface, check=False)
            cfg.unlink(missing_ok=True)
    for unit in UNIT_DIR.glob("tlm-frp-*.service"):
        if unit.name not in desired_frp_units:
            run("systemctl", "disable", "--now", unit.name, check=False)
            unit.unlink(missing_ok=True)
    run("systemctl", "daemon-reload", check=False)


def apply_desired(desired: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    link_states: list[dict[str, Any]] = []
    desired_ifaces: set[str] = set()
    desired_frp_units: set[str] = set()
    ready_links: list[dict[str, Any]] = []
    desired_egress: dict[str, dict[str, Any]] = {}

    for link in desired.get("links", []):
        if not isinstance(link, dict):
            continue
        if not link.get("ready") or not link.get("peer"):
            link_states.append({"uuid": link.get("uuid"), "transport": "pending", "healthy": False, "detail": "waiting-for-peer"})
            continue
        desired_ifaces.add(str(link["interface"]))
        ready_links.append(link)
        try:
            source, table, priority = _validate_egress(link)
            desired_egress[str(link["uuid"])] = {
                "role": str(link["role"]),
                "source_ip": source,
                "route_table": table,
                "rule_priority": priority,
                "interface": str(link["interface"]),
            }
            mode = str(link.get("mode") or "auto")
            if mode in {"auto", "reverse"}:
                ensure_frp(link)
                side = str((link.get("frp") or {}).get("side") or "")
                if side:
                    desired_frp_units.add(_frp_unit_name(side, str(link["uuid"]).replace("-", "")[:8]))
            else:
                stop_frp(link)

            initial_endpoint = None
            if link["role"] == "iran":
                initial_endpoint = link.get("reverse_endpoint") if mode == "reverse" else link.get("direct_endpoint")
            ensure_wg(link, initial_endpoint)
            ensure_egress(link)
            transport, rtt, detail = choose_path(link, runtime)
            healthy = transport in {"direct", "reverse", "passive"}
            link_states.append({
                "uuid": link["uuid"], "transport": transport, "healthy": healthy,
                "rtt_ms": rtt, "detail": detail, "peer_ip": link.get("peer_ip"),
            })
        except Exception as exc:
            link_states.append({"uuid": link.get("uuid"), "transport": "down", "healthy": False, "detail": str(exc)[:500]})

    firewall = apply_firewall(ready_links)
    cleanup_stale_egress(runtime, desired_egress)
    cleanup_stale(desired_ifaces, desired_frp_units)
    save_runtime(runtime)
    return {"links": link_states, "firewall": firewall, "updated_at": time.time()}


def run_agent() -> None:
    require_root()
    config = json_read(AGENT_CONFIG)
    if not config:
        raise SystemExit("Node is not enrolled. Run: tlm-node-agent install ...")
    panel = str(config["panel"]).rstrip("/")
    node_uuid = str(config["node_uuid"])
    token = str(config["agent_token"])
    insecure = bool(config.get("insecure"))
    advertise_host = str(config.get("advertise_host") or "")
    runtime = load_runtime()
    failures = 0
    while True:
        poll_interval = 15
        try:
            desired = http_json(
                "GET", panel + f"/api/tunnels/nodes/{node_uuid}/desired",
                token=token, insecure=insecure,
            )
            poll_interval = max(5, min(int(desired.get("poll_interval") or 15), 120))
            state = apply_desired(desired, runtime)
            http_json(
                "POST", panel + f"/api/tunnels/nodes/{node_uuid}/heartbeat",
                token=token, insecure=insecure,
                payload={
                    "agent_version": AGENT_VERSION,
                    "advertise_host": advertise_host,
                    "capabilities": capabilities(),
                    "state": state,
                },
            )
            failures = 0
        except Exception as exc:
            failures += 1
            print(f"agent cycle failed: {exc}", file=sys.stderr, flush=True)
            poll_interval = min(60, 5 * failures)
        time.sleep(poll_interval)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tor Location hybrid tunnel node agent")
    sub = parser.add_subparsers(dest="command", required=True)
    install = sub.add_parser("install")
    install.add_argument("--panel", required=True)
    install.add_argument("--token", required=True)
    install.add_argument("--name", required=True)
    install.add_argument("--advertise-host", default="")
    install.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    install.add_argument("--allow-http", action="store_true", help="Allow unencrypted controller HTTP")
    upgrade = sub.add_parser("upgrade")
    upgrade.add_argument("--panel", required=True)
    upgrade.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    upgrade.add_argument("--allow-http", action="store_true", help="Allow unencrypted controller HTTP")
    sub.add_parser("run")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        if args.command == "install":
            install_agent(args.panel, args.token, args.name, args.advertise_host, args.insecure, args.allow_http)
        elif args.command == "upgrade":
            upgrade_agent(args.panel, args.insecure, args.allow_http)
        else:
            run_agent()
    except AgentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
