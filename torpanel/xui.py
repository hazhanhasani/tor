from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3

from .db import get_setting, set_location_xui_inbound_port
from .security import decrypt_secret

MANAGED_PREFIX = "torloc-"
MANAGED_INBOUND_PREFIX = "torloc-in-"
MANAGED_INBOUND_METHOD = "2022-blake3-aes-256-gcm"


class XUIError(RuntimeError):
    pass


def normalize_api_token(value: str) -> str:
    """Accept either the raw token or a pasted `Bearer <token>` value."""
    token = (value or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


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
        api_token=normalize_api_token(decrypt_secret(token_enc) if token_enc else ""),
        gateway_host=get_setting("gateway_host"),
        verify_tls=get_setting("xui_verify_tls", "1") == "1",
        outbound_test_url=get_setting("xui_outbound_test_url", "https://www.google.com/generate_204"),
    )


class XUIClient:
    def __init__(self, settings: XUISettings):
        self.settings = settings
        self.settings.api_token = normalize_api_token(self.settings.api_token)
        if not settings.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Authorization": f"Bearer {self.settings.api_token}",
            "User-Agent": "TorLocationManager/1.2",
        })

    def _url(self, path: str) -> str:
        return urljoin(self.settings.base_url, path.lstrip("/"))

    def _request(self, method: str, path: str, **kwargs) -> Any:
        url = self._url(path)
        try:
            response = self.session.request(
                method,
                url,
                timeout=20,
                verify=self.settings.verify_tls,
                allow_redirects=False,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise XUIError(f"اتصال به 3x-ui برقرار نشد: {exc}") from exc

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location", "")
            raise XUIError(
                f"3x-ui برای endpoint موردنظر Redirect برگرداند (HTTP {response.status_code}). "
                f"آدرس کامل پنل و base path را بررسی کنید. مقصد: {location or 'نامشخص'}"
            )
        if response.status_code == 401:
            raise XUIError(
                "3x-ui توکن را نپذیرفت (HTTP 401). توکن ممکن است اشتباه، حذف‌شده، "
                "غیرفعال یا منقضی باشد. در Settings → Security یک API Token جدید بسازید، "
                "آن را فعال نگه دارید و فقط مقدار خود توکن را وارد کنید."
            )
        if response.status_code == 403:
            detail = ""
            try:
                payload = response.json()
                detail = str(payload.get("msg") or "") if isinstance(payload, dict) else ""
            except ValueError:
                pass
            msg = (
                "توکن معتبر است اما اجازه این عملیات را ندارد (HTTP 403). "
                "برای Tor Location Manager باید API Token با scope=admin استفاده شود."
            )
            if detail:
                msg += f" پیام 3x-ui: {detail}"
            raise XUIError(msg)
        if response.status_code == 404:
            raise XUIError(
                "Endpoint API پیدا نشد (HTTP 404). آدرس 3x-ui یا base path اشتباه است. "
                f"مسیر بررسی‌شده: {urlparse(url).path}"
            )
        if not response.ok:
            raise XUIError(f"3x-ui پاسخ HTTP {response.status_code} داد: {response.text[:300]}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise XUIError("3x-ui پاسخ غیر JSON برگرداند؛ URL/base path پنل را بررسی کنید.") from exc
        if isinstance(payload, dict) and payload.get("success") is False:
            raise XUIError(str(payload.get("msg") or "درخواست 3x-ui ناموفق بود"))
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
            raise XUIError("پاسخ /panel/api/inbounds/options ساختار مورد انتظار را ندارد.")
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

    def get_inbound(self, inbound_id: int) -> dict[str, Any]:
        obj = self._unwrap(self._request("GET", f"/panel/api/inbounds/get/{int(inbound_id)}"))
        if not isinstance(obj, dict):
            raise XUIError("جزئیات Inbound از 3x-ui قابل خواندن نیست.")
        return obj

    def add_inbound(self, payload: dict[str, Any]) -> dict[str, Any]:
        obj = self._unwrap(self._request("POST", "/panel/api/inbounds/add", json=payload))
        return obj if isinstance(obj, dict) else {}

    def update_inbound(self, inbound_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        obj = self._unwrap(self._request("POST", f"/panel/api/inbounds/update/{int(inbound_id)}", json=payload))
        return obj if isinstance(obj, dict) else {}

    def delete_inbound(self, inbound_id: int) -> None:
        self._request("POST", f"/panel/api/inbounds/del/{int(inbound_id)}")

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
        raise XUIError("خواندن تنظیمات Xray از 3x-ui ممکن نشد.")

    def update_xray_config(self, config: dict[str, Any]) -> None:
        self._request("POST", "/panel/api/xray/update", data={
            "xraySetting": json.dumps(config, separators=(",", ":"), ensure_ascii=False),
            "outboundTestUrl": self.settings.outbound_test_url,
        })

    def test_connection(self) -> dict[str, Any]:
        if not self.settings.api_token:
            raise XUIError("API Token خالی است.")
        inbounds = self.list_inbounds()
        return {"inbound_count": len(inbounds), "inbounds": inbounds}


def managed_inbound_tag(location: dict[str, Any]) -> str:
    return MANAGED_INBOUND_PREFIX + str(location["slug"])


def managed_outbound_tag(location: dict[str, Any]) -> str:
    return MANAGED_PREFIX + str(location["slug"])


def derive_managed_inbound_password(location: dict[str, Any], decrypt_password) -> str:
    gateway_secret = decrypt_password(location["ss_password"]).encode("utf-8")
    material = b"tor-location-manager:3x-ui-inbound:v1\x00" + str(location["slug"]).encode("utf-8") + b"\x00" + gateway_secret
    return base64.b64encode(hashlib.sha256(material).digest()).decode("ascii")


def _json_obj(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}


def managed_inbound_payload(location: dict[str, Any], decrypt_password) -> dict[str, Any]:
    port = int(location.get("xui_inbound_port") or 0)
    if not port:
        raise XUIError("پورت Inbound مدیریت‌شده هنوز تعیین نشده است.")
    return {
        "remark": f"Tor {str(location['country_code']).upper()} · {location['name']}",
        "enable": True,
        "expiryTime": 0,
        "total": 0,
        "trafficReset": "never",
        "listen": "",
        "port": port,
        "protocol": "shadowsocks",
        "settings": {
            "method": MANAGED_INBOUND_METHOD,
            "password": derive_managed_inbound_password(location, decrypt_password),
            "network": "tcp",
            "clients": [],
            "ivCheck": False,
        },
        "streamSettings": {"network": "tcp", "security": "none"},
        "tag": managed_inbound_tag(location),
        "sniffing": {
            "enabled": False,
            "destOverride": ["http", "tls", "quic", "fakedns"],
            "metadataOnly": False,
            "routeOnly": False,
        },
    }


def _inbound_matches(current: dict[str, Any], expected: dict[str, Any]) -> bool:
    if int(current.get("port") or 0) != int(expected["port"]):
        return False
    for key in ("tag", "remark", "protocol"):
        if str(current.get(key) or "") != str(expected.get(key) or ""):
            return False
    if bool(current.get("enable")) is not True:
        return False
    current_settings = _json_obj(current.get("settings"))
    expected_settings = expected["settings"]
    for key in ("method", "password", "network"):
        if current_settings.get(key) != expected_settings.get(key):
            return False
    return True


def _choose_inbound_port(location: dict[str, Any], options: list[dict[str, Any]], locations: list[dict[str, Any]]) -> int:
    desired_tag = managed_inbound_tag(location)
    existing = next((row for row in options if row.get("tag") == desired_tag), None)
    configured = int(location.get("xui_inbound_port") or 0)
    used_by_other = {
        int(row.get("port") or 0)
        for row in options
        if row.get("tag") != desired_tag and int(row.get("port") or 0) > 0
    }
    reserved_local = {
        int(loc.get("gateway_port") or 0) for loc in locations
    } | {
        int(loc.get("socks_port") or 0) for loc in locations
    } | {8787}

    if configured:
        if configured in used_by_other:
            raise XUIError(f"پورت {configured} در 3x-ui توسط Inbound دیگری استفاده می‌شود.")
        if configured in reserved_local:
            raise XUIError(
                f"پورت {configured} با یکی از پورت‌های داخلی Tor/Gateway تداخل دارد. "
                "برای Inbound 3x-ui یک پورت جدا انتخاب کنید."
            )
        return configured

    if existing and int(existing.get("port") or 0) > 0:
        port = int(existing["port"])
        set_location_xui_inbound_port(int(location["id"]), port)
        location["xui_inbound_port"] = port
        return port

    unavailable = used_by_other | reserved_local | {
        int(loc.get("xui_inbound_port") or 0) for loc in locations if int(loc.get("xui_inbound_port") or 0) > 0
    }
    for port in range(21000, 60000):
        if port not in unavailable:
            set_location_xui_inbound_port(int(location["id"]), port)
            location["xui_inbound_port"] = port
            return port
    raise XUIError("هیچ پورت آزاد مناسبی برای Inbound مدیریت‌شده پیدا نشد.")


def reconcile_managed_inbounds(client: XUIClient, locations: list[dict[str, Any]], decrypt_password) -> dict[str, int]:
    options = client.list_inbounds()
    desired_tags = {managed_inbound_tag(loc) for loc in locations if loc.get("enabled")}

    removed = 0
    for row in list(options):
        tag = str(row.get("tag") or "")
        if tag.startswith(MANAGED_INBOUND_PREFIX) and tag not in desired_tags:
            if row.get("id") is not None:
                client.delete_inbound(int(row["id"]))
                removed += 1

    if removed:
        options = client.list_inbounds()

    created = updated = 0
    for location in locations:
        if not location.get("enabled"):
            continue
        _choose_inbound_port(location, options, locations)
        tag = managed_inbound_tag(location)
        expected = managed_inbound_payload(location, decrypt_password)
        existing = next((row for row in options if row.get("tag") == tag), None)
        if existing is None:
            client.add_inbound(expected)
            created += 1
            options.append({
                "id": None,
                "tag": tag,
                "remark": expected["remark"],
                "protocol": expected["protocol"],
                "port": expected["port"],
            })
            continue
        if existing.get("id") is None:
            continue
        current = client.get_inbound(int(existing["id"]))
        if not _inbound_matches(current, expected):
            client.update_inbound(int(existing["id"]), expected)
            updated += 1
    return {"created": created, "updated": updated, "removed": removed}


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
        if not loc.get("enabled"):
            continue
        tag = managed_outbound_tag(loc)
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
        route_tags = [managed_inbound_tag(loc), *list(loc.get("inbound_tags") or [])]
        route_tags = list(dict.fromkeys(str(x) for x in route_tags if x))
        if route_tags:
            managed_rules.append({
                "type": "field",
                "inboundTag": route_tags,
                "outboundTag": tag,
            })

    api_rules, rest = [], []
    for rule in rules:
        if isinstance(rule, dict) and rule.get("outboundTag") == "api" and \
                "api" in (rule.get("inboundTag") or []):
            api_rules.append(rule)
        else:
            rest.append(rule)
    routing["rules"] = api_rules + managed_rules + rest
    return config


def sync_locations(locations: list[dict[str, Any]], decrypt_password) -> dict[str, int]:
    settings = current_settings()
    if not settings.base_url.strip("/") or not settings.api_token:
        raise XUIError("3x-ui URL/API token is not configured")
    client = XUIClient(settings)
    inbound_stats = reconcile_managed_inbounds(client, locations, decrypt_password)
    updated = build_synced_config(client.get_xray_config(), locations,
                                  settings.gateway_host, decrypt_password)
    client.update_xray_config(updated)
    return inbound_stats
