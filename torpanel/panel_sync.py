from __future__ import annotations

import copy
from typing import Any

from .db import get_setting, list_tunnel_links
from .pasarguard import PasarGuardClient, configured as pasarguard_configured, current_settings as pasarguard_settings, sync_pasarguard
from .routing_state import tunnel_panel_tags
from .xui import XUIClient, current_settings as xui_settings, sync_locations

XUI_TUNNEL_PREFIX = "tlm-tunnel-"


def xui_configured() -> bool:
    cfg = xui_settings()
    return bool(cfg.base_url.strip("/") and cfg.api_token)


def _hybrid_freedom_outbound(tag: str, source_ip: str) -> dict[str, Any]:
    """Build a current Xray freedom outbound bound to the tunnel source IP.

    Xray 26.x expects Freedom DNS strategy in streamSettings.sockopt, not in
    the freedom protocol settings object. Keeping this in one builder prevents
    3x-ui and PasarGuard from drifting to different schemas.
    """
    return {
        "tag": tag,
        "protocol": "freedom",
        "settings": {},
        "sendThrough": source_ip,
        "streamSettings": {
            "sockopt": {
                "domainStrategy": "UseIPv4",
            }
        },
    }


def build_xui_hybrid_config(original: dict[str, Any], tunnel_links: list[dict[str, Any]]) -> dict[str, Any]:
    config = copy.deepcopy(original)
    outbounds = config.setdefault("outbounds", [])
    if not isinstance(outbounds, list):
        outbounds = []
        config["outbounds"] = outbounds
    routing = config.setdefault("routing", {})
    if not isinstance(routing, dict):
        routing = {}
        config["routing"] = routing
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        rules = []

    outbounds[:] = [
        item for item in outbounds
        if not (isinstance(item, dict) and str(item.get("tag") or "").startswith(XUI_TUNNEL_PREFIX))
    ]
    rules = [
        rule for rule in rules
        if not (isinstance(rule, dict) and str(rule.get("outboundTag") or "").startswith(XUI_TUNNEL_PREFIX))
    ]

    managed_rules: list[dict[str, Any]] = []
    for link in tunnel_links:
        link_uuid = str(link.get("uuid") or "")
        tags = tunnel_panel_tags(link_uuid, "xui")
        if not tags or not link.get("enabled"):
            continue
        source_ip = str(link.get("iran_overlay_ip") or "")
        if not source_ip:
            continue
        tag = XUI_TUNNEL_PREFIX + link_uuid.replace("-", "")[:12]
        outbounds.append(_hybrid_freedom_outbound(tag, source_ip))
        managed_rules.append({"type": "field", "inboundTag": tags, "outboundTag": tag})

    api_rules: list[dict[str, Any]] = []
    rest: list[dict[str, Any]] = []
    for rule in rules:
        if isinstance(rule, dict) and rule.get("outboundTag") == "api" and "api" in (rule.get("inboundTag") or []):
            api_rules.append(rule)
        else:
            rest.append(rule)
    routing["rules"] = api_rules + managed_rules + rest
    return config


def sync_xui_hybrid() -> dict[str, int]:
    settings = xui_settings()
    client = XUIClient(settings)
    links = list_tunnel_links()
    original = client.get_xray_config()
    config = build_xui_hybrid_config(original, links)
    changed = config != original
    if changed:
        client.update_xray_config(config)
    return {
        "tunnel_routes": sum(1 for link in links if tunnel_panel_tags(str(link.get("uuid") or ""), "xui")),
        "tunnel_xray_updated": 1 if changed else 0,
    }


def sync_all_panels(locations: list[dict[str, Any]], decrypt_password) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if xui_configured():
        try:
            tor_stats = sync_locations(locations, decrypt_password)
            tunnel_stats = sync_xui_hybrid()
            result["xui"] = {"ok": True, **tor_stats, **tunnel_stats}
        except Exception as exc:
            result["xui"] = {"ok": False, "error": str(exc)}
    else:
        result["xui"] = {"ok": None, "skipped": True}

    if pasarguard_configured():
        try:
            result["pasarguard"] = {"ok": True, **sync_pasarguard(locations, decrypt_password)}
        except Exception as exc:
            result["pasarguard"] = {"ok": False, "error": str(exc)}
    else:
        result["pasarguard"] = {"ok": None, "skipped": True}
    return result


def xui_inbounds() -> list[dict[str, Any]]:
    if not xui_configured():
        return []
    rows = XUIClient(xui_settings()).list_inbounds()
    return [
        row for row in rows
        if not str(row.get("tag") or "").startswith("torloc-in-")
        and str(row.get("tag") or "") != "torloc-cdn"
    ]


def pasarguard_inbounds() -> list[dict[str, Any]]:
    if not pasarguard_configured():
        return []
    return PasarGuardClient(pasarguard_settings()).list_inbounds()


def provider_summary() -> dict[str, bool]:
    return {
        "xui": xui_configured(),
        "pasarguard": pasarguard_configured(),
        "has_gateway": bool(get_setting("gateway_host") or get_setting("pasarguard_gateway_host")),
    }
