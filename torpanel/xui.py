from __future__ import annotations

import base64
import copy
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .db import get_setting, set_location_xui_inbound_port, set_setting
from .security import decrypt_secret
from .vless import REALITY_FLOW, build_gateway_vless_outbound, build_managed_vless_inbound
from .warp import xray_domain_rules
from .xui_cdn import (
    CDN_MANAGED_TAG,
    reconcile_cdn_inbound,
    managed_client_email,
)

MANAGED_PREFIX = "torloc-"
MANAGED_INBOUND_PREFIX = "torloc-in-"


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
    managed_inbound_mode: str = "legacy"
    cdn_domain: str = ""
    cdn_port: int = 8443
    cdn_ws_path: str = "/edge"
    cdn_reject_unknown_sni: bool = True


def current_settings() -> XUISettings:
    token_enc = get_setting("xui_api_token")
    return XUISettings(
        base_url=get_setting("xui_base_url").rstrip("/") + "/",
        api_token=normalize_api_token(decrypt_secret(token_enc) if token_enc else ""),
        gateway_host=get_setting("gateway_host"),
        verify_tls=get_setting("xui_verify_tls", "1") == "1",
        outbound_test_url=get_setting("xui_outbound_test_url", "https://www.google.com/generate_204"),
        managed_inbound_mode=get_setting("xui_managed_inbound_mode", "legacy") or "legacy",
        cdn_domain=get_setting("xui_cdn_domain", ""),
        cdn_port=int(get_setting("xui_cdn_port", "8443") or 8443),
        cdn_ws_path=get_setting("xui_cdn_ws_path", "/edge") or "/edge",
        cdn_reject_unknown_sni=get_setting("xui_cdn_reject_unknown_sni", "1") == "1",
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
            "User-Agent": "TorLocationManager/1.11",
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

    def warp_data(self) -> dict[str, Any] | None:
        obj = self._unwrap(self._request("POST", "/panel/api/xray/warp/data"))
        return obj if isinstance(obj, dict) and obj else None

    def warp_config(self) -> dict[str, Any] | None:
        obj = self._unwrap(self._request("POST", "/panel/api/xray/warp/config"))
        return obj if isinstance(obj, dict) and obj else None

    @staticmethod
    def _wireguard_keypair() -> tuple[str, str]:
        private = x25519.X25519PrivateKey.generate()
        private_raw = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_raw = private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return (
            base64.b64encode(private_raw).decode("ascii"),
            base64.b64encode(public_raw).decode("ascii"),
        )

    def warp_register(self) -> tuple[dict[str, Any], dict[str, Any]]:
        private_key, public_key = self._wireguard_keypair()
        obj = self._unwrap(self._request(
            "POST",
            "/panel/api/xray/warp/reg",
            data={"privateKey": private_key, "publicKey": public_key},
        ))
        if not isinstance(obj, dict):
            raise XUIError("3x-ui پاسخ ثبت WARP نامعتبر برگرداند.")
        data = obj.get("data")
        config = obj.get("config")
        if not isinstance(data, dict) or not isinstance(config, dict):
            raise XUIError("3x-ui WARP ثبت شد اما data/config کامل برنگشت.")
        return data, config

    @staticmethod
    def build_warp_outbound(data: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        cfg = config.get("config") if isinstance(config, dict) else None
        if not isinstance(cfg, dict):
            raise XUIError("پیکربندی WARP از 3x-ui ناقص است.")
        peers = cfg.get("peers")
        if not isinstance(peers, list) or not peers or not isinstance(peers[0], dict):
            raise XUIError("Peer مربوط به WARP در پاسخ 3x-ui وجود ندارد.")
        peer = peers[0]
        interface = cfg.get("interface") if isinstance(cfg.get("interface"), dict) else {}
        addresses = interface.get("addresses") if isinstance(interface.get("addresses"), dict) else {}
        address: list[str] = []
        if addresses.get("v4"):
            address.append(f"{addresses['v4']}/32")
        if addresses.get("v6"):
            address.append(f"{addresses['v6']}/128")
        client_id = str(cfg.get("client_id") or data.get("client_id") or "")
        reserved: list[int] = []
        if client_id:
            try:
                reserved = list(base64.b64decode(client_id))
            except Exception:
                reserved = []
        endpoint = peer.get("endpoint")
        if isinstance(endpoint, dict):
            endpoint = endpoint.get("host")
        endpoint = str(endpoint or "")
        public_key = str(peer.get("public_key") or "")
        secret_key = str(data.get("private_key") or "")
        if not address or not endpoint or not public_key or not secret_key:
            raise XUIError("اطلاعات WireGuard مربوط به WARP کامل نیست.")
        return {
            "tag": "warp",
            "protocol": "wireguard",
            "settings": {
                "mtu": 1420,
                "secretKey": secret_key,
                "address": address,
                "reserved": reserved,
                "domainStrategy": "ForceIPv4v6",
                "peers": [{"publicKey": public_key, "endpoint": endpoint}],
                "noKernelTun": True,
            },
        }

    @staticmethod
    def _merge_warp_outbound(existing: dict[str, Any], refreshed: dict[str, Any]) -> dict[str, Any]:
        """Refresh native WARP credentials while preserving unrelated user settings."""
        merged = copy.deepcopy(existing) if isinstance(existing, dict) else {}
        merged["tag"] = "warp"
        merged["protocol"] = "wireguard"
        previous_settings = merged.get("settings")
        settings = copy.deepcopy(previous_settings) if isinstance(previous_settings, dict) else {}
        fresh_settings = refreshed.get("settings")
        if isinstance(fresh_settings, dict):
            settings.update(copy.deepcopy(fresh_settings))
        merged["settings"] = settings
        return merged

    def ensure_warp_outbound(self, config: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        updated = copy.deepcopy(config)
        outbounds = updated.setdefault("outbounds", [])
        existing_index = next(
            (i for i, row in enumerate(outbounds)
             if isinstance(row, dict) and str(row.get("tag") or "") == "warp"),
            -1,
        )

        data = self.warp_data()
        if data:
            warp_cfg = self.warp_config()
            if not warp_cfg:
                raise XUIError("WARP در 3x-ui ثبت شده اما Config آن قابل دریافت نیست.")
        else:
            data, warp_cfg = self.warp_register()

        refreshed = self.build_warp_outbound(data, warp_cfg)
        if existing_index >= 0:
            existing = outbounds[existing_index]
            merged = self._merge_warp_outbound(existing, refreshed)
            changed = merged != existing
            outbounds[existing_index] = merged
            return updated, changed

        outbounds.append(refreshed)
        return updated, True

    def test_outbound(self, outbound: dict[str, Any], all_outbounds: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        obj = self._unwrap(self._request(
            "POST",
            "/panel/api/xray/testOutbound",
            data={
                "outbound": json.dumps(outbound, separators=(",", ":")),
                "allOutbounds": json.dumps(all_outbounds or [], separators=(",", ":")),
                "mode": "http",
            },
        ))
        return obj if isinstance(obj, dict) else {}

    def get_web_cert_files(self) -> dict[str, str]:
        obj = self._unwrap(self._request("GET", "/panel/api/server/getWebCertFiles"))
        if not isinstance(obj, dict):
            raise XUIError("مسیر Certificate پنل از 3x-ui قابل خواندن نیست.")
        cert_file = str(obj.get("webCertFile") or "").strip()
        key_file = str(obj.get("webKeyFile") or "").strip()
        if not cert_file or not key_file:
            raise XUIError(
                "3x-ui برای پنل Certificate/Key ثبت‌شده ندارد. "
                "ابتدا SSL پنل را تنظیم کنید تا همان Certificate برای Inbound CDN استفاده شود."
            )
        return {"webCertFile": cert_file, "webKeyFile": key_file}

    def get_server_status(self) -> dict[str, Any]:
        """Read the official 3x-ui status endpoint (v3.8.5 compatible)."""
        status = self._unwrap(self._request("GET", "/panel/api/server/status"))
        if not isinstance(status, dict):
            raise XUIError("پاسخ وضعیت 3x-ui ساختار مورد انتظار را ندارد.")
        return status

    def test_connection(self) -> dict[str, Any]:
        if not self.settings.api_token:
            raise XUIError("API Token خالی است.")
        inbounds = self.list_inbounds()
        # Status is supplementary: older panels may lack this endpoint, but a
        # working inbound API must still pass the connection check.
        try:
            status = self.get_server_status()
        except XUIError:
            status = {}
        xray = status.get("xray") if isinstance(status.get("xray"), dict) else {}
        return {
            "inbound_count": len(inbounds),
            "inbounds": inbounds,
            "panel_version": str(status.get("panelVersion") or ""),
            "xray_version": str(xray.get("version") or ""),
            "xray_state": xray.get("state"),
        }


def managed_inbound_tag(location: dict[str, Any]) -> str:
    return MANAGED_INBOUND_PREFIX + str(location["slug"])


def managed_outbound_tag(location: dict[str, Any]) -> str:
    return MANAGED_PREFIX + str(location["slug"])


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
    return build_managed_vless_inbound(
        location, decrypt_password, tag=managed_inbound_tag(location), port=port
    )


def _is_tlm_generated_client(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    email = str(row.get("email") or "").strip().lower()
    return email.startswith("torloc.") and email.endswith("@managed.invalid")


def _repair_existing_managed_payload(
    current: dict[str, Any],
    expected: dict[str, Any],
) -> dict[str, Any]:
    """Patch transport/security without replacing real 3x-ui clients.

    Sanaei 3x-ui SyncInbound treats settings.clients as the complete desired
    client set. Sending the generated one-client payload therefore detaches
    every user that is not present in it. Keep user-managed clients, repair
    their Reality/Vision flow, and remove only our synthetic bootstrap client
    once real clients exist.
    """
    repaired = copy.deepcopy(current)
    for key, value in expected.items():
        if key != "settings":
            repaired[key] = copy.deepcopy(value)
    current_settings = _json_obj(current.get("settings"))
    if not isinstance(current_settings.get("clients"), list):
        raise XUIError(
            "3x-ui فهرست کاربران این Inbound را کامل برنگرداند؛ "
            "برای جلوگیری از حذف کاربران، Sync متوقف شد."
        )
    current_clients = [
        copy.deepcopy(row)
        for row in current_settings["clients"]
        if isinstance(row, dict)
    ]
    if len(current_clients) != len(current_settings["clients"]):
        raise XUIError("فهرست کاربران Inbound معتبر نیست؛ Sync بدون تغییر متوقف شد.")
    # Existing clients belong to the operator; their flow, UUID, quota,
    # subscription ID and enabled state must never be rewritten by Sync.
    repaired["settings"] = copy.deepcopy(current_settings)
    repaired["settings"]["decryption"] = "none"
    repaired["settings"]["encryption"] = "none"
    # Never remove even a generated client: an existing subscription may use it.
    repaired["settings"]["clients"] = (
        current_clients if current_clients else copy.deepcopy(expected["settings"]["clients"])
    )

    # These are panel/subscription presentation fields, not Tor transport
    # ownership. Preserve them when 3x-ui returns them so Sync does not reset
    # an operator's sharing preferences.
    for key in ("shareAddrStrategy", "shareAddr", "subSortIndex"):
        if key in current:
            repaired[key] = copy.deepcopy(current[key])
    return repaired


def _vless_client_projection(row: Any) -> tuple[str, str, str, bool]:
    if not isinstance(row, dict):
        return ("", "", "", False)
    return (
        str(row.get("email") or ""),
        str(row.get("id") or ""),
        str(row.get("flow") or ""),
        bool(row.get("enable", True)),
    )


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
    if str(current_settings.get("decryption") or "") != "none":
        return False
    if str(current_settings.get("encryption") or "none") != "none":
        return False
    current_clients = sorted(
        _vless_client_projection(row)
        for row in (current_settings.get("clients") or [])
        if isinstance(row, dict)
    )
    expected_clients = sorted(
        _vless_client_projection(row)
        for row in (expected_settings.get("clients") or [])
        if isinstance(row, dict)
    )
    if current_clients != expected_clients:
        return False
    if bool(current.get("disableFlow", False)) is not False:
        return False

    current_stream = _json_obj(current.get("streamSettings"))
    expected_stream = expected["streamSettings"]
    if str(current_stream.get("network") or "") != "tcp":
        return False
    if str(current_stream.get("security") or "") != "reality":
        return False
    current_reality = _json_obj(current_stream.get("realitySettings"))
    expected_reality = expected_stream["realitySettings"]
    current_target = str(current_reality.get("target") or current_reality.get("dest") or "")
    expected_target = str(expected_reality.get("target") or expected_reality.get("dest") or "")
    if current_target != expected_target:
        return False
    if str(current_reality.get("privateKey") or "") != str(expected_reality.get("privateKey") or ""):
        return False
    if list(current_reality.get("serverNames") or []) != list(expected_reality["serverNames"]):
        return False
    if list(current_reality.get("shortIds") or []) != list(expected_reality["shortIds"]):
        return False
    current_client_reality = _json_obj(current_reality.get("settings"))
    expected_client_reality = expected_reality.get("settings") or {}
    for key in ("publicKey", "fingerprint", "serverName", "spiderX"):
        if str(current_client_reality.get(key) or "") != str(expected_client_reality.get(key) or ""):
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


def reconcile_managed_inbounds(
    client: XUIClient, locations: list[dict[str, Any]], decrypt_password
) -> dict[str, Any]:
    if client.settings.managed_inbound_mode == "cloudflare":
        return reconcile_cdn_inbound(client, locations, decrypt_password)

    options = client.list_inbounds()
    existing_tags = {
        str(row.get("tag") or "") for row in options
        if str(row.get("tag") or "")
    }
    # Reject stale selections before adding or updating anything. Otherwise
    # replacing the routing rules can silently detach every user on that tag.
    requested_manual_tags = {
        str(tag)
        for loc in locations if loc.get("enabled")
        for tag in (loc.get("inbound_tags") or [])
        if tag
    }
    missing_tags = sorted(requested_manual_tags - existing_tags)
    if missing_tags:
        raise XUIError(
            "Inboundهای انتخاب‌شده در 3x-ui پیدا نشدند؛ Sync بدون تغییر متوقف شد: "
            + ", ".join(missing_tags)
        )

    created = updated = preserved = 0
    warnings: list[str] = []
    managed_tags: list[str] = []
    for location in locations:
        if not location.get("enabled"):
            continue
        tag = managed_inbound_tag(location)
        existing = next((row for row in options if row.get("tag") == tag), None)
        manual_tags = [str(x) for x in (location.get("inbound_tags") or []) if x]

        if manual_tags or not location.get("xui_auto_client", True):
            # New locations explicitly reuse the selected live inbounds; no
            # synthetic user is ever created unless the opt-in was checked.
            # Keep any older generated inbound routed for live subscriptions.
            if existing is not None:
                managed_tags.append(tag)
            preserved += len(manual_tags) + int(existing is not None)
            continue

        if existing is None:
            _choose_inbound_port(location, options, locations)
            expected = managed_inbound_payload(location, decrypt_password)
            client.add_inbound(expected)
            created += 1
            managed_tags.append(tag)
            options.append({
                "id": None, "tag": tag, "remark": expected["remark"],
                "protocol": expected["protocol"], "port": expected["port"],
            })
            continue

        managed_tags.append(tag)
        if existing.get("id") is None:
            raise XUIError("Inbound موجود شناسه معتبر ندارد؛ از تغییر آن صرف‌نظر شد.")
        _choose_inbound_port(location, options, locations)
        current = client.get_inbound(int(existing["id"]))
        expected = _repair_existing_managed_payload(
            current, managed_inbound_payload(location, decrypt_password)
        )
        if _inbound_matches(current, expected):
            continue

        current_clients = _json_obj(current.get("settings")).get("clients") or []
        if any(
            not _is_tlm_generated_client(row) for row in current_clients
        ):
            # 3x-ui's update API treats settings.clients as replacement data.
            # Never risk removing paid users to repair transport defaults.
            preserved += 1
            warnings.append(
                f"{tag}: تنظیمات اینباند با کاربران موجود دست‌نخورده حفظ شد؛ "
                "برای تغییر Transport، ابتدا پشتیبان بگیرید."
            )
            continue

        client.update_inbound(int(existing["id"]), expected)
        updated += 1

    return {
        "created": created, "updated": updated, "removed": 0,
        "preserved": preserved, "warnings": warnings,
        "managed_tags": managed_tags,
    }

def build_synced_config(original: dict[str, Any], locations: list[dict[str, Any]],
                        gateway_host: str, decrypt_password,
                        xui_settings: XUISettings | None = None,
                        warp_enabled: bool = False,
                        warp_mode: str = "domains",
                        warp_domains: list[str] | None = None,
                        warp_inbound_tags: list[str] | None = None,
                        managed_cdn_tag: str = CDN_MANAGED_TAG,
                        managed_inbound_tags: set[str] | None = None,
                        preserved_legacy_tags: set[str] | None = None,
                        cdn_managed_emails: set[str] | None = None) -> dict[str, Any]:
    if not gateway_host:
        raise XUIError("Gateway host/IP is not configured")
    config = copy.deepcopy(original)
    outbounds = config.setdefault("outbounds", [])
    routing = config.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    outbounds[:] = [o for o in outbounds if not (
        isinstance(o, dict) and str(o.get("tag", "")).startswith(MANAGED_PREFIX))]
    rules[:] = [r for r in rules if not (
        isinstance(r, dict)
        and (
            str(r.get("outboundTag", "")).startswith(MANAGED_PREFIX)
            or str(r.get("ruleTag") or "") == "torloc-warp"
        )
    )]

    managed_rules: list[dict[str, Any]] = []
    warp_tags = list(dict.fromkeys(str(x) for x in (warp_inbound_tags or []) if x))
    if warp_enabled and not warp_tags and xui_settings and xui_settings.managed_inbound_mode == "cloudflare":
        warp_tags = [managed_cdn_tag]
    if warp_enabled and warp_tags:
        warp_rule: dict[str, Any] = {
            "type": "field",
            "ruleTag": "torloc-warp",
            "inboundTag": warp_tags,
            "outboundTag": "warp",
        }
        if warp_mode != "all":
            domain_tokens = xray_domain_rules(warp_domains or [])
            if domain_tokens:
                warp_rule["domain"] = domain_tokens
            else:
                warp_rule = {}
        if warp_rule:
            managed_rules.append(warp_rule)

    for loc in locations:
        if not loc.get("enabled"):
            continue
        tag = managed_outbound_tag(loc)
        outbounds.append(
            build_gateway_vless_outbound(loc, gateway_host, decrypt_password, tag)
        )
        manual_tags = list(dict.fromkeys(str(x) for x in (loc.get("inbound_tags") or []) if x))
        if xui_settings and xui_settings.managed_inbound_mode == "cloudflare":
            # Only route a synthetic CDN client if it was explicitly requested
            # or existed already. Reusing a manually selected inbound must
            # never create a replacement client per new location.
            email = managed_client_email(loc)
            has_cdn_client = (
                (cdn_managed_emails is None and loc.get("xui_auto_client", True))
                or (cdn_managed_emails is not None and email in cdn_managed_emails)
            )
            if has_cdn_client and managed_cdn_tag:
                managed_rules.append({
                    "type": "field",
                    "inboundTag": [managed_cdn_tag],
                    "user": [email],
                    "outboundTag": tag,
                })
            legacy_tag = managed_inbound_tag(loc)
            legacy_tags = (
                [legacy_tag] if preserved_legacy_tags and legacy_tag in preserved_legacy_tags else []
            )
            existing_tags = list(dict.fromkeys([*manual_tags, *legacy_tags]))
            if existing_tags:
                managed_rules.append({
                    "type": "field",
                    "inboundTag": existing_tags,
                    "outboundTag": tag,
                })
        else:
            auto_tag = managed_inbound_tag(loc)
            use_auto = managed_inbound_tags is None or auto_tag in managed_inbound_tags
            route_tags = [*([auto_tag] if use_auto else []), *manual_tags]
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


def sync_locations(
    locations: list[dict[str, Any]],
    decrypt_password,
    *,
    tunnel_links: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    settings = current_settings()
    if not settings.base_url.strip("/") or not settings.api_token:
        raise XUIError("3x-ui URL/API token is not configured")
    client = XUIClient(settings)
    previous_cdn_tag = get_setting("xui_cdn_runtime_tag", "") or ""
    # Validate the operator's exact manual selection before altering inbounds
    # or Xray. A stale tag must never silently fall back to a new user.
    requested_manual_tags = {
        str(tag)
        for loc in locations if loc.get("enabled")
        for tag in (loc.get("inbound_tags") or []) if tag
    }
    if requested_manual_tags:
        available = {
            str(row.get("tag") or "")
            for row in client.list_inbounds()
        }
        missing = sorted(requested_manual_tags - available)
        if missing:
            raise XUIError(
                "Inboundهای انتخاب‌شده موجود نیستند؛ Sync بدون تغییر متوقف شد: "
                + ", ".join(missing)
            )
    inbound_stats = reconcile_managed_inbounds(client, locations, decrypt_password)
    managed_cdn_tag = str(inbound_stats.get("cdn_inbound_tag") or CDN_MANAGED_TAG)
    if settings.managed_inbound_mode == "cloudflare":
        set_setting("xui_cdn_runtime_tag", managed_cdn_tag)
        cdn_port = int(inbound_stats.get("cdn_port") or settings.cdn_port)
        settings.cdn_port = cdn_port
        set_setting("xui_cdn_port", str(cdn_port))
    server_config = client.get_xray_config()
    original = server_config
    warp_enabled = get_setting("xui_warp_enabled", "0") == "1"
    warp_mode = get_setting("xui_warp_mode", "domains") or "domains"
    try:
        warp_domains = json.loads(get_setting("xui_warp_domains_json", "[]") or "[]")
        if not isinstance(warp_domains, list):
            warp_domains = []
    except Exception:
        warp_domains = []
    try:
        warp_inbound_tags = json.loads(get_setting("xui_warp_inbound_tags", "[]") or "[]")
        if not isinstance(warp_inbound_tags, list):
            warp_inbound_tags = []
    except Exception:
        warp_inbound_tags = []

    if settings.managed_inbound_mode == "cloudflare":
        replaceable = {CDN_MANAGED_TAG}
        if previous_cdn_tag:
            replaceable.add(previous_cdn_tag)
        normalized_tags: list[str] = []
        for tag in warp_inbound_tags:
            value = str(tag or "")
            if value in replaceable:
                value = managed_cdn_tag
            if value and value not in normalized_tags:
                normalized_tags.append(value)
        if warp_enabled and not normalized_tags:
            normalized_tags = [managed_cdn_tag]
        warp_inbound_tags = normalized_tags
        set_setting(
            "xui_warp_inbound_tags",
            json.dumps(warp_inbound_tags, ensure_ascii=False),
        )

    warp_created = False
    if warp_enabled:
        original, warp_created = client.ensure_warp_outbound(original)

    updated = build_synced_config(
        original, locations,
        settings.gateway_host, decrypt_password, settings,
        warp_enabled=warp_enabled,
        warp_mode=warp_mode,
        warp_domains=[str(x) for x in warp_domains],
        warp_inbound_tags=[str(x) for x in warp_inbound_tags],
        managed_cdn_tag=managed_cdn_tag,
        managed_inbound_tags=set(inbound_stats.get("managed_tags") or []),
        preserved_legacy_tags=set(inbound_stats.get("preserved_legacy_tags") or []),
        cdn_managed_emails=set(inbound_stats.get("cdn_managed_emails") or []),
    )
    # One Xray settings update for Tor, WARP and tunnel routes combined.
    if tunnel_links is not None:
        from .panel_sync import build_xui_hybrid_config
        updated = build_xui_hybrid_config(updated, tunnel_links)
    xray_updated = updated != server_config
    if xray_updated:
        client.update_xray_config(updated)
    inbound_stats["xray_updated"] = 1 if xray_updated else 0
    inbound_stats["warp_created"] = 1 if warp_created else 0
    inbound_stats["warp_enabled"] = 1 if warp_enabled else 0
    return inbound_stats
