from __future__ import annotations

import json
from typing import Any

from .db import get_setting, set_setting

TOR_PG_ROUTES_KEY = "pasarguard_tor_routes"
TUNNEL_ROUTES_KEY = "hybrid_tunnel_panel_routes"


def _load(key: str) -> dict[str, Any]:
    raw = get_setting(key, "{}")
    try:
        value = json.loads(raw or "{}")
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _save(key: str, value: dict[str, Any]) -> None:
    set_setting(key, json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def _normalize_tags(tags: list[str] | tuple[str, ...] | set[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in tags:
        tag = str(item or "").strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        result.append(tag)
    return result


def pasarguard_tor_tags(location_slug: str) -> list[str]:
    value = _load(TOR_PG_ROUTES_KEY).get(str(location_slug), [])
    return _normalize_tags(value if isinstance(value, list) else [])


def set_pasarguard_tor_tags(location_slug: str, tags: list[str]) -> None:
    data = _load(TOR_PG_ROUTES_KEY)
    normalized = _normalize_tags(tags)
    if normalized:
        data[str(location_slug)] = normalized
    else:
        data.pop(str(location_slug), None)
    _save(TOR_PG_ROUTES_KEY, data)


def delete_pasarguard_tor_tags(location_slug: str) -> None:
    set_pasarguard_tor_tags(location_slug, [])


def tunnel_panel_tags(link_uuid: str, provider: str) -> list[str]:
    provider = str(provider).strip().lower()
    if provider not in {"xui", "pasarguard"}:
        return []
    row = _load(TUNNEL_ROUTES_KEY).get(str(link_uuid), {})
    if not isinstance(row, dict):
        return []
    value = row.get(provider, [])
    return _normalize_tags(value if isinstance(value, list) else [])


def set_tunnel_panel_tags(link_uuid: str, provider: str, tags: list[str]) -> None:
    provider = str(provider).strip().lower()
    if provider not in {"xui", "pasarguard"}:
        raise ValueError("provider must be xui or pasarguard")
    data = _load(TUNNEL_ROUTES_KEY)
    row = data.get(str(link_uuid), {})
    if not isinstance(row, dict):
        row = {}
    normalized = _normalize_tags(tags)
    if normalized:
        row[provider] = normalized
    else:
        row.pop(provider, None)
    if row:
        data[str(link_uuid)] = row
    else:
        data.pop(str(link_uuid), None)
    _save(TUNNEL_ROUTES_KEY, data)


def delete_tunnel_panel_tags(link_uuid: str) -> None:
    data = _load(TUNNEL_ROUTES_KEY)
    data.pop(str(link_uuid), None)
    _save(TUNNEL_ROUTES_KEY, data)


def explicit_route_conflicts(
    provider: str,
    tags: list[str],
    *,
    locations: list[dict[str, Any]],
    tunnel_links: list[dict[str, Any]],
    exclude_location_slug: str | None = None,
    exclude_link_uuid: str | None = None,
) -> dict[str, list[str]]:
    wanted = set(_normalize_tags(tags))
    if not wanted:
        return {}
    conflicts: dict[str, list[str]] = {}
    provider = provider.lower().strip()
    if provider == "xui":
        for loc in locations:
            slug = str(loc.get("slug") or "")
            if slug == exclude_location_slug:
                continue
            overlap = wanted.intersection(str(x) for x in (loc.get("inbound_tags") or []))
            if overlap:
                conflicts[f"Tor {loc.get('name') or slug}"] = sorted(overlap)
    elif provider == "pasarguard":
        for loc in locations:
            slug = str(loc.get("slug") or "")
            if slug == exclude_location_slug:
                continue
            overlap = wanted.intersection(pasarguard_tor_tags(slug))
            if overlap:
                conflicts[f"Tor {loc.get('name') or slug}"] = sorted(overlap)
    for link in tunnel_links:
        uuid = str(link.get("uuid") or "")
        if uuid == exclude_link_uuid:
            continue
        overlap = wanted.intersection(tunnel_panel_tags(uuid, provider))
        if overlap:
            conflicts[f"Tunnel {link.get('name') or uuid}"] = sorted(overlap)
    return conflicts
