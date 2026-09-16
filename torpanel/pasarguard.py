from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3

from .db import get_setting, list_tunnel_links
from .routing_state import pasarguard_tor_tags, tunnel_panel_tags
from .security import decrypt_secret

TOR_OUTBOUND_PREFIX = "tlm-pg-tor-"
TUNNEL_OUTBOUND_PREFIX = "tlm-pg-tunnel-"
MANAGED_PREFIXES = (TOR_OUTBOUND_PREFIX, TUNNEL_OUTBOUND_PREFIX)


class PasarGuardError(RuntimeError):
    pass


def normalize_api_key(value: str) -> str:
    key = (value or "").strip()
    if key.lower().startswith("apikey "):
        key = key[7:].strip()
    return key


@dataclass
class PasarGuardSettings:
    base_url: str
    api_key: str
    core_id: int
    verify_tls: bool
    restart_nodes: bool
    gateway_host: str


def current_settings() -> PasarGuardSettings:
    key_enc = get_setting("pasarguard_api_key")
    core_raw = get_setting("pasarguard_core_id", "0")
    try:
        core_id = int(core_raw or 0)
    except ValueError:
        core_id = 0
    return PasarGuardSettings(
        base_url=get_setting("pasarguard_base_url").rstrip("/") + "/",
        api_key=normalize_api_key(decrypt_secret(key_enc) if key_enc else ""),
        core_id=core_id,
        verify_tls=get_setting("pasarguard_verify_tls", "1") == "1",
        restart_nodes=get_setting("pasarguard_restart_nodes", "1") == "1",
        gateway_host=get_setting("pasarguard_gateway_host") or get_setting("gateway_host"),
    )


def configured() -> bool:
    cfg = current_settings()
    return bool(cfg.base_url.strip("/") and cfg.api_key and cfg.core_id > 0)


class PasarGuardClient:
    def __init__(self, settings: PasarGuardSettings):
        self.settings = settings
        if not settings.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "X-Api-Key": settings.api_key,
            "User-Agent": "TorLocationManager/1.6",
        })

    def _url(self, path: str) -> str:
        return urljoin(self.settings.base_url, path.lstrip("/"))

    def _request(self, method: str, path: str, **kwargs) -> Any:
        url = self._url(path)
        try:
            response = self.session.request(
                method,
                url,
                timeout=25,
                verify=self.settings.verify_tls,
                allow_redirects=False,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise PasarGuardError(f"اتصال به PasarGuard برقرار نشد: {exc}") from exc

        if response.is_redirect or response.is_permanent_redirect:
            raise PasarGuardError(
                f"PasarGuard Redirect برگرداند (HTTP {response.status_code}). Base URL را بررسی کنید."
            )
        if response.status_code == 401:
            raise PasarGuardError("PasarGuard API Key را نپذیرفت (HTTP 401). کلید را بررسی یا دوباره صادر کنید.")
        if response.status_code == 403:
            raise PasarGuardError(
                "API Key معتبر است اما دسترسی کافی ندارد (HTTP 403). دسترسی cores.read و cores.update لازم است."
            )
        if response.status_code == 404:
            raise PasarGuardError(
                "PasarGuard endpoint پیدا نشد (HTTP 404). URL پنل، نسخه API یا Core ID را بررسی کنید. "
                f"مسیر: {urlparse(url).path}"
            )
        if not response.ok:
            raise PasarGuardError(f"PasarGuard پاسخ HTTP {response.status_code} داد: {response.text[:400]}")
        if response.status_code == 204 or not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise PasarGuardError("PasarGuard پاسخ JSON معتبر برنگرداند.") from exc

    def list_cores(self) -> list[dict[str, Any]]:
        payload = self._request("GET", "/api/cores", params={"limit": 200})
        if isinstance(payload, dict):
            rows = payload.get("cores")
            if isinstance(rows, list):
                return [x for x in rows if isinstance(x, dict)]
        if isinstance(payload, list):
            return [x for x in payload if isinstance(x, dict)]
        raise PasarGuardError("ساختار پاسخ لیست Coreهای PasarGuard شناخته نشد.")

    def get_core(self, core_id: int | None = None) -> dict[str, Any]:
        target = int(core_id or self.settings.core_id)
        if target <= 0:
            raise PasarGuardError("Core ID پاسارگارد تنظیم نشده است.")
        payload = self._request("GET", f"/api/core/{target}")
        if not isinstance(payload, dict) or not isinstance(payload.get("config"), dict):
            raise PasarGuardError("Core پاسخ معتبر یا config قابل ویرایش ندارد.")
        return payload

    def update_core(self, core: dict[str, Any], config: dict[str, Any]) -> None:
        payload = {
            "name": core.get("name"),
            "config": config,
            "type": core.get("type"),
            "exclude_inbound_tags": core.get("exclude_inbound_tags") or [],
            "fallbacks_inbound_tags": core.get("fallbacks_inbound_tags") or [],
        }
        self._request(
            "PUT",
            f"/api/core/{int(core['id'])}",
            params={"restart_nodes": "true" if self.settings.restart_nodes else "false"},
            json=payload,
        )

    def test_connection(self) -> dict[str, Any]:
        cores = self.list_cores()
        selected = None
        if self.settings.core_id:
            selected = next((x for x in cores if int(x.get("id") or 0) == self.settings.core_id), None)
            if selected is None:
                selected = self.get_core(self.settings.core_id)
        return {"core_count": len(cores), "selected_core": selected}

    def list_inbounds(self) -> list[dict[str, Any]]:
        core = self.get_core()
        config = core.get("config") or {}
        rows = config.get("inbounds") or []
        result: list[dict[str, Any]] = []
        for item in rows:
            if not isinstance(item, dict):
                continue
            tag = str(item.get("tag") or "").strip()
            if not tag:
                continue
            result.append({
                "tag": tag,
                "protocol": str(item.get("protocol") or ""),
                "listen": str(item.get("listen") or ""),
                "port": item.get("port"),
            })
        return result


def _managed_tag(value: Any) -> bool:
    tag = str(value or "")
    return any(tag.startswith(prefix) for prefix in MANAGED_PREFIXES)


def _insert_managed_rules(routing: dict[str, Any], managed_rules: list[dict[str, Any]]) -> None:
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        rules = []
    rules = [
        rule for rule in rules
        if not (isinstance(rule, dict) and _managed_tag(rule.get("outboundTag")))
    ]
    api_rules: list[dict[str, Any]] = []
    rest: list[dict[str, Any]] = []
    for rule in rules:
        if isinstance(rule, dict) and rule.get("outboundTag") == "api" and "api" in (rule.get("inboundTag") or []):
            api_rules.append(rule)
        else:
            rest.append(rule)
    routing["rules"] = api_rules + managed_rules + rest


def _hybrid_freedom_outbound(tag: str, source_ip: str) -> dict[str, Any]:
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


def build_synced_core_config(
    original: dict[str, Any],
    locations: list[dict[str, Any]],
    *,
    gateway_host: str,
    decrypt_password,
    tunnel_links: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    config = copy.deepcopy(original)
    outbounds = config.setdefault("outbounds", [])
    if not isinstance(outbounds, list):
        outbounds = []
        config["outbounds"] = outbounds
    outbounds[:] = [
        outbound for outbound in outbounds
        if not (isinstance(outbound, dict) and _managed_tag(outbound.get("tag")))
    ]
    routing = config.setdefault("routing", {})
    if not isinstance(routing, dict):
        routing = {}
        config["routing"] = routing

    managed_rules: list[dict[str, Any]] = []
    for loc in locations:
        if not loc.get("enabled"):
            continue
        tags = pasarguard_tor_tags(str(loc.get("slug") or ""))
        if not tags:
            continue
        if not gateway_host:
            raise PasarGuardError("Gateway host برای Tor روی PasarGuard تنظیم نشده است.")
        tag = TOR_OUTBOUND_PREFIX + str(loc["slug"])
        outbounds.append({
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "address": gateway_host,
                "port": int(loc["gateway_port"]),
                "method": loc["ss_method"],
                "password": decrypt_password(loc["ss_password"]),
            },
        })
        managed_rules.append({"type": "field", "inboundTag": tags, "outboundTag": tag})

    for link in tunnel_links if tunnel_links is not None else list_tunnel_links():
        link_uuid = str(link.get("uuid") or "")
        tags = tunnel_panel_tags(link_uuid, "pasarguard")
        if not tags or not link.get("enabled"):
            continue
        source_ip = str(link.get("iran_overlay_ip") or "")
        if not source_ip:
            continue
        tag = TUNNEL_OUTBOUND_PREFIX + link_uuid.replace("-", "")[:12]
        outbounds.append(_hybrid_freedom_outbound(tag, source_ip))
        managed_rules.append({"type": "field", "inboundTag": tags, "outboundTag": tag})

    _insert_managed_rules(routing, managed_rules)
    return config


def sync_pasarguard(locations: list[dict[str, Any]], decrypt_password) -> dict[str, Any]:
    settings = current_settings()
    if not settings.base_url.strip("/") or not settings.api_key or settings.core_id <= 0:
        raise PasarGuardError("PasarGuard URL/API Key/Core ID تنظیم نشده است.")
    client = PasarGuardClient(settings)
    core = client.get_core()
    updated = build_synced_core_config(
        core["config"],
        locations,
        gateway_host=settings.gateway_host,
        decrypt_password=decrypt_password,
    )
    client.update_core(core, updated)
    return {
        "core_id": int(core["id"]),
        "tor_routes": sum(1 for loc in locations if pasarguard_tor_tags(str(loc.get("slug") or ""))),
        "tunnel_routes": sum(1 for link in list_tunnel_links() if tunnel_panel_tags(str(link.get("uuid") or ""), "pasarguard")),
    }
