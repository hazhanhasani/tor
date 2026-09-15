from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests
import urllib3

from .db import get_setting
from .security import decrypt_secret

MANAGED_PREFIX = "torloc-"


class XUIError(RuntimeError):
    pass


@dataclass
class XUISettings:
    base_url: str
    api_token: str
    gateway_host: str
    verify_tls: bool
    outbound_test_url: str = "https://www.google.com/generate_204"


def current_settings() -> XUISettings:
    token_enc = get_setting("xui_api_token")
    return XUISettings(
        base_url=get_setting("xui_base_url").rstrip("/") + "/",
        api_token=decrypt_secret(token_enc) if token_enc else "",
        gateway_host=get_setting("gateway_host"),
        verify_tls=get_setting("xui_verify_tls", "1") == "1",
        outbound_test_url=get_setting("xui_outbound_test_url", "https://www.google.com/generate_204"),
    )


class XUIClient:
    def __init__(self, settings: XUISettings):
        self.settings = settings
        if not settings.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Authorization": f"Bearer {settings.api_token}",
            "User-Agent": "TorLocationManager/1.0",
        })

    def _url(self, path: str) -> str:
        return urljoin(self.settings.base_url, path.lstrip("/"))

    def _request(self, method: str, path: str, **kwargs) -> Any:
        try:
            response = self.session.request(method, self._url(path), timeout=20,
                                            verify=self.settings.verify_tls, **kwargs)
        except requests.RequestException as exc:
            raise XUIError(f"3x-ui connection failed: {exc}") from exc
        if response.status_code in (401, 403):
            raise XUIError("3x-ui authentication failed. Check the API token.")
        if not response.ok:
            raise XUIError(f"3x-ui returned HTTP {response.status_code}: {response.text[:300]}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise XUIError("3x-ui returned a non-JSON response") from exc
        if isinstance(payload, dict) and payload.get("success") is False:
            raise XUIError(str(payload.get("msg") or "3x-ui request failed"))
        return payload

    @staticmethod
    def _unwrap(payload: Any) -> Any:
        obj = payload.get("obj", payload) if isinstance(payload, dict) else payload
        for _ in range(3):
            if isinstance(obj, str):
                text = obj.strip()
                if not text:
                    return obj
                try:
                    obj = json.loads(text)
                    continue
                except json.JSONDecodeError:
                    return obj
            break
        return obj

    def list_inbounds(self) -> list[dict[str, Any]]:
        payload = self._request("GET", "/panel/api/inbounds/options")
        obj = self._unwrap(payload)
        if isinstance(obj, dict):
            for key in ("inbounds", "data", "items"):
                if isinstance(obj.get(key), list):
                    obj = obj[key]
                    break
        if not isinstance(obj, list):
            raise XUIError("Unexpected response from /panel/api/inbounds/options")
        result = []
        for item in obj:
            if not isinstance(item, dict) or not item.get("tag"):
                continue
            result.append({
                "id": item.get("id"), "tag": str(item["tag"]),
                "remark": str(item.get("remark") or ""),
                "protocol": str(item.get("protocol") or ""), "port": item.get("port"),
            })
        return result

    def get_xray_config(self) -> dict[str, Any]:
        payload = self._request("POST", "/panel/api/xray/")
        obj = self._unwrap(payload)
        if isinstance(obj, dict) and "xraySetting" in obj:
            obj = obj["xraySetting"]
            if isinstance(obj, str):
                obj = json.loads(obj)
        if isinstance(obj, dict) and "outbounds" in obj and "routing" in obj:
            return obj
        if isinstance(payload, dict):
            for candidate in payload.values():
                if isinstance(candidate, str):
                    try:
                        parsed = json.loads(candidate)
                    except Exception:
                        continue
                    if isinstance(parsed, dict) and "xraySetting" in parsed:
                        config = parsed["xraySetting"]
                        if isinstance(config, str):
                            config = json.loads(config)
                        if isinstance(config, dict):
                            return config
        raise XUIError("Could not read the Xray configuration from 3x-ui")

    def update_xray_config(self, config: dict[str, Any]) -> None:
        self._request("POST", "/panel/api/xray/update", data={
            "xraySetting": json.dumps(config, separators=(",", ":"), ensure_ascii=False),
            "outboundTestUrl": self.settings.outbound_test_url,
        })

    def test_connection(self) -> dict[str, Any]:
        inbounds = self.list_inbounds()
        return {"inbound_count": len(inbounds), "inbounds": inbounds}


def build_synced_config(original: dict[str, Any], locations: list[dict[str, Any]],
                        gateway_host: str, decrypt_password) -> dict[str, Any]:
    if not gateway_host:
        raise XUIError("Gateway host/IP is not configured")
    config = copy.deepcopy(original)
    outbounds = config.setdefault("outbounds", [])
    routing = config.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    outbounds[:] = [o for o in outbounds if not (
        isinstance(o, dict) and str(o.get("tag", "")).startswith(MANAGED_PREFIX))]
    rules[:] = [r for r in rules if not (
        isinstance(r, dict) and str(r.get("outboundTag", "")).startswith(MANAGED_PREFIX))]

    managed_rules: list[dict[str, Any]] = []
    for loc in locations:
        if not loc.get("enabled") or not loc.get("inbound_tags"):
            continue
        tag = MANAGED_PREFIX + loc["slug"]
        outbounds.append({
            "tag": tag, "protocol": "shadowsocks",
            "settings": {
                "address": gateway_host, "port": int(loc["gateway_port"]),
                "method": loc["ss_method"], "password": decrypt_password(loc["ss_password"]),
            },
        })
        managed_rules.append({"type": "field", "inboundTag": list(loc["inbound_tags"]),
                              "outboundTag": tag})

    api_rules, rest = [], []
    for rule in rules:
        if isinstance(rule, dict) and rule.get("outboundTag") == "api" and \
                "api" in (rule.get("inboundTag") or []):
            api_rules.append(rule)
        else:
            rest.append(rule)
    routing["rules"] = api_rules + managed_rules + rest
    return config


def sync_locations(locations: list[dict[str, Any]], decrypt_password) -> None:
    settings = current_settings()
    if not settings.base_url.strip("/") or not settings.api_token:
        raise XUIError("3x-ui URL/API token is not configured")
    client = XUIClient(settings)
    updated = build_synced_config(client.get_xray_config(), locations,
                                  settings.gateway_host, decrypt_password)
    client.update_xray_config(updated)
