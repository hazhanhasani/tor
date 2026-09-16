#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

AGENT_CONFIG = Path("/etc/tor-location-node/agent.json")
TLM_PYTHON = Path("/opt/tor-location-manager/venv/bin/python")
TLM_APP = Path("/opt/tor-location-manager")


def run(*args: str, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        check=check,
    )


def json_read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


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
    headers = {"Accept": "application/json", "User-Agent": "TorLocationPortFabric/1.0"}
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
        raise RuntimeError(f"Controller HTTP {exc.code}: {detail}") from exc
    except Exception as exc:
        raise RuntimeError(f"Controller request failed: {exc}") from exc
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError("Controller returned invalid JSON")
    return parsed


def local_inventory() -> dict[str, Any]:
    if not (TLM_PYTHON.exists() and TLM_APP.exists()):
        return {"installed": False, "locations": [], "ports": [], "location_count": 0, "port_count": 0}
    result = subprocess.run(
        [str(TLM_PYTHON), "-m", "torpanel.fabric", "inventory"],
        cwd=str(TLM_APP), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=60, check=False,
    )
    if result.returncode != 0:
        return {
            "installed": True,
            "locations": [],
            "ports": [],
            "location_count": 0,
            "port_count": 0,
            "errors": [result.stdout.strip()[:1000] or "inventory-command-failed"],
        }
    try:
        value = json.loads(result.stdout)
    except Exception:
        return {
            "installed": True,
            "locations": [],
            "ports": [],
            "location_count": 0,
            "port_count": 0,
            "errors": ["inventory-invalid-json"],
        }
    return value if isinstance(value, dict) else {"installed": True, "locations": [], "ports": []}


def _valid_iface(value: str) -> bool:
    return bool(re.fullmatch(r"tlm[a-f0-9]{1,7}", value or ""))


def _valid_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def build_nft_script(links: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]], list[str]]:
    """Build deterministic all-port DNAT/SNAT rules for Tor locations.

    A public port can only point at one foreign peer on one Iran node. If two
    linked foreign panels advertise the same port, the first link wins and the
    duplicate is reported as a conflict instead of silently changing target.
    """
    mappings: list[dict[str, Any]] = []
    conflicts: list[str] = []
    owners: dict[int, tuple[str, str]] = {}

    for link in sorted(links, key=lambda row: str(row.get("uuid") or "")):
        if not link.get("ready"):
            continue
        iface = str(link.get("interface") or "")
        foreign_ip = str(link.get("foreign_ip") or "")
        iran_ip = str(link.get("iran_ip") or "")
        if not (_valid_iface(iface) and _valid_ipv4(foreign_ip) and _valid_ipv4(iran_ip)):
            continue
        for raw in link.get("ports") or []:
            try:
                port = int(raw)
            except (TypeError, ValueError):
                continue
            if not 1 <= port <= 65535:
                continue
            owner = owners.get(port)
            target = (str(link.get("uuid") or ""), foreign_ip)
            if owner and owner != target:
                conflicts.append(f"port {port} is advertised by multiple foreign links")
                continue
            if owner:
                continue
            owners[port] = target
            mappings.append({
                "uuid": target[0], "port": port, "iface": iface,
                "foreign_ip": foreign_ip, "iran_ip": iran_ip,
            })

    lines = [
        "delete table ip tlm_port_fabric",
        "delete table inet tlm_port_fabric_filter",
    ]
    if not mappings:
        return "\n".join(lines) + "\n", mappings, conflicts

    lines.extend([
        "add table ip tlm_port_fabric",
        "add chain ip tlm_port_fabric prerouting { type nat hook prerouting priority dstnat; policy accept; }",
        "add chain ip tlm_port_fabric postrouting { type nat hook postrouting priority srcnat; policy accept; }",
        "add table inet tlm_port_fabric_filter",
        "add chain inet tlm_port_fabric_filter forward { type filter hook forward priority -40; policy accept; }",
    ])
    seen_return_ifaces: set[str] = set()
    for item in mappings:
        port = item["port"]
        iface = item["iface"]
        foreign_ip = item["foreign_ip"]
        iran_ip = item["iran_ip"]
        for proto in ("tcp", "udp"):
            lines.append(
                f'add rule ip tlm_port_fabric prerouting iifname != "{iface}" {proto} dport {port} dnat to {foreign_ip}:{port}'
            )
            lines.append(
                f'add rule ip tlm_port_fabric postrouting oifname "{iface}" ip daddr {foreign_ip} {proto} dport {port} snat to {iran_ip}'
            )
            lines.append(
                f'add rule inet tlm_port_fabric_filter forward oifname "{iface}" ip daddr {foreign_ip} {proto} dport {port} accept'
            )
        if iface not in seen_return_ifaces:
            lines.append(
                f'add rule inet tlm_port_fabric_filter forward iifname "{iface}" ct state established,related accept'
            )
            seen_return_ifaces.add(iface)
    return "\n".join(lines) + "\n", mappings, conflicts


def apply_port_fabric(links: list[dict[str, Any]]) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise RuntimeError("port fabric must run as root")
    if not shutil_which("nft"):
        return {"enabled": False, "reason": "nft-not-installed", "mappings": 0, "conflicts": []}
    script, mappings, conflicts = build_nft_script(links)
    if mappings:
        try:
            Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n", encoding="ascii")
        except OSError as exc:
            raise RuntimeError(f"failed to enable IPv4 forwarding: {exc}") from exc
    # Deleting a missing table is expected to fail, so perform deletes separately.
    run("nft", "delete", "table", "ip", "tlm_port_fabric", check=False)
    run("nft", "delete", "table", "inet", "tlm_port_fabric_filter", check=False)
    if not mappings:
        return {"enabled": True, "mappings": 0, "conflicts": conflicts}
    filtered = "\n".join(
        line for line in script.splitlines() if not line.startswith("delete table ")
    ) + "\n"
    result = run("nft", "-f", "-", check=False, input_text=filtered)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.strip() or "nft port-fabric apply failed")
    return {"enabled": True, "mappings": len(mappings), "conflicts": conflicts}


def shutil_which(name: str) -> str | None:
    import shutil
    return shutil.which(name)


def cycle(config: dict[str, Any], *, post_inventory: bool = True) -> dict[str, Any]:
    panel = str(config.get("panel") or "").rstrip("/")
    node_uuid = str(config.get("node_uuid") or "")
    token = str(config.get("agent_token") or "")
    insecure = bool(config.get("insecure"))
    if not panel or not node_uuid or not token:
        raise RuntimeError("Node agent configuration is incomplete")

    desired = http_json(
        "GET", panel + f"/api/tunnels/nodes/{node_uuid}/port-fabric",
        token=token, insecure=insecure,
    )
    role = str((desired.get("node") or {}).get("role") or "")
    result: dict[str, Any] = {"role": role}
    if role == "foreign" and post_inventory:
        inventory = local_inventory()
        http_json(
            "POST", panel + f"/api/tunnels/nodes/{node_uuid}/port-fabric/inventory",
            token=token, insecure=insecure, payload={"inventory": inventory},
        )
        result["inventory"] = inventory
    elif role == "iran":
        result["fabric"] = apply_port_fabric(desired.get("links") if isinstance(desired.get("links"), list) else [])
    return result


def run_loop() -> None:
    failures = 0
    last_inventory = 0.0
    while True:
        config = json_read(AGENT_CONFIG)
        if not config:
            print("port-fabric waiting for node enrollment", file=sys.stderr, flush=True)
            time.sleep(5)
            continue
        try:
            now = time.time()
            result = cycle(config, post_inventory=(now - last_inventory >= 60))
            if result.get("inventory") is not None:
                last_inventory = now
            failures = 0
            delay = 15
        except Exception as exc:
            failures += 1
            print(f"port-fabric cycle failed: {exc}", file=sys.stderr, flush=True)
            delay = min(60, max(5, failures * 5))
        time.sleep(delay)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Automatic Tor Location port fabric")
    parser.add_argument("command", choices=["run", "once"])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "run":
        run_loop()
        return
    config = json_read(AGENT_CONFIG)
    if not config:
        raise SystemExit("Node is not enrolled")
    print(json.dumps(cycle(config), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
