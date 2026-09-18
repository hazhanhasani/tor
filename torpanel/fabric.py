from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import PANEL_PORT
from .db import get_setting, list_locations, list_tunnel_links
from .panel_sync import pasarguard_inbounds, xui_inbounds
from .routing_state import pasarguard_tor_tags

ROOT = Path(__file__).resolve().parent.parent


def _port(value: Any) -> int:
    try:
        port = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return port if 1 <= port <= 65535 else 0


def tunnel_infrastructure_ports() -> set[int]:
    reserved = {_port(PANEL_PORT)}
    for link in list_tunnel_links():
        for key in ("foreign_wg_port", "iran_frp_control_port", "iran_frp_proxy_port"):
            port = _port(link.get(key))
            if port:
                reserved.add(port)
    return {port for port in reserved if port}


def build_location_port_inventory(
    locations: list[dict[str, Any]],
    *,
    xui_rows: list[dict[str, Any]] | None = None,
    pasarguard_rows: list[dict[str, Any]] | None = None,
    pasarguard_tags_by_slug: dict[str, list[str]] | None = None,
    reserved_ports: set[int] | None = None,
) -> dict[str, Any]:
    """Return every externally reachable port owned by enabled Tor locations.

    Internal Tor SOCKS ports are intentionally excluded because they are bound to
    loopback and must never be exposed by the Iran↔foreign port fabric. Tunnel
    control/WireGuard ports and the panel port are also excluded so a Location can
    never steal the management path through an nftables DNAT rule.
    """
    xui_rows = xui_rows or []
    pasarguard_rows = pasarguard_rows or []
    pasarguard_tags_by_slug = pasarguard_tags_by_slug or {}
    reserved_ports = {_port(value) for value in (reserved_ports or set()) if _port(value)}

    xui_port_by_tag = {
        str(row.get("tag") or ""): _port(row.get("port"))
        for row in xui_rows
        if str(row.get("tag") or "") and _port(row.get("port"))
    }
    pg_port_by_tag = {
        str(row.get("tag") or ""): _port(row.get("port"))
        for row in pasarguard_rows
        if str(row.get("tag") or "") and _port(row.get("port"))
    }

    all_ports: set[int] = set()
    blocked_ports: set[int] = set()
    result_locations: list[dict[str, Any]] = []
    for location in locations:
        if not location.get("enabled"):
            continue
        slug = str(location.get("slug") or "").strip()
        if not slug:
            continue

        ports: set[int] = set()
        sources: dict[int, set[str]] = {}
        blocked_sources: dict[int, set[str]] = {}

        def add(value: Any, source: str) -> None:
            port = _port(value)
            if not port:
                return
            if port in reserved_ports:
                blocked_ports.add(port)
                blocked_sources.setdefault(port, set()).add(source)
                return
            ports.add(port)
            all_ports.add(port)
            sources.setdefault(port, set()).add(source)

        # Every Tor location has a public gateway and, when 3x-ui is configured,
        # a managed inbound. Those are always part of the automatic tunnel fabric
        # unless their port collides with tunnel/control infrastructure.
        add(location.get("gateway_port"), "tor-gateway")
        add(location.get("xui_inbound_port"), "managed-3x-ui")

        # Include manually assigned 3x-ui/PasarGuard inbounds that belong to the
        # same Tor location. This makes "all ports" follow the location model,
        # not just the automatically generated inbound.
        for tag in location.get("inbound_tags") or []:
            tag = str(tag or "")
            add(xui_port_by_tag.get(tag), f"3x-ui:{tag}")
        for tag in pasarguard_tags_by_slug.get(slug, []):
            tag = str(tag or "")
            add(pg_port_by_tag.get(tag), f"pasarguard:{tag}")

        result_locations.append({
            "slug": slug,
            "name": str(location.get("name") or slug),
            "country_code": str(location.get("country_code") or "").upper(),
            "ports": sorted(ports),
            "port_sources": {
                str(port): sorted(values) for port, values in sorted(sources.items())
            },
            "blocked_ports": sorted(blocked_sources),
        })

    return {
        "locations": result_locations,
        "ports": sorted(all_ports),
        "blocked_ports": sorted(blocked_ports),
        "location_count": len(result_locations),
        "port_count": len(all_ports),
    }


def location_port_inventory() -> dict[str, Any]:
    locations = list_locations(enabled_only=True)
    errors: list[str] = []

    try:
        xui_rows = xui_inbounds()
    except Exception as exc:
        xui_rows = []
        errors.append(f"3x-ui: {exc}")

    try:
        pg_rows = pasarguard_inbounds()
    except Exception as exc:
        pg_rows = []
        errors.append(f"PasarGuard: {exc}")

    pg_tags = {str(loc.get("slug") or ""): pasarguard_tor_tags(str(loc.get("slug") or "")) for loc in locations}
    reserved_ports = tunnel_infrastructure_ports()
    inventory = build_location_port_inventory(
        locations,
        xui_rows=xui_rows,
        pasarguard_rows=pg_rows,
        pasarguard_tags_by_slug=pg_tags,
        reserved_ports=reserved_ports,
    )

    # Cloudflare mode uses one shared public VLESS/WS/TLS inbound for every
    # Location. When this manager runs on the foreign node, the automatic port
    # fabric must mirror that single CDN origin port through the Iran edge too.
    if get_setting("xui_managed_inbound_mode", "legacy") == "cloudflare":
        cdn_port = _port(get_setting("xui_cdn_port", "8443"))
        if cdn_port and cdn_port not in reserved_ports:
            merged = set(inventory.get("ports") or [])
            merged.add(cdn_port)
            inventory["ports"] = sorted(merged)
            inventory["port_count"] = len(merged)
            for item in inventory.get("locations") or []:
                loc_ports = set(item.get("ports") or [])
                loc_ports.add(cdn_port)
                item["ports"] = sorted(loc_ports)
        elif cdn_port:
            blocked = set(inventory.get("blocked_ports") or [])
            blocked.add(cdn_port)
            inventory["blocked_ports"] = sorted(blocked)

    if inventory.get("blocked_ports"):
        errors.append(
            "Port Fabric skipped ports reserved by the panel/tunnel infrastructure: "
            + ", ".join(str(port) for port in inventory["blocked_ports"])
        )
    version = "unknown"
    try:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        pass
    return {
        "installed": True,
        "version": version,
        **inventory,
        "errors": errors,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Tor Location Manager port-fabric inventory")
    parser.add_argument("command", choices=["inventory"])
    args = parser.parse_args()
    if args.command == "inventory":
        print(json.dumps(location_port_inventory(), ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
