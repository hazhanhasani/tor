from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import uuid
from typing import Any
from urllib.parse import quote, urlencode, urlparse

from .db import set_setting

CDN_MANAGED_TAG = "torloc-cdn"
CDN_MANAGED_REMARK = "Tor CDN Gateway · Cloudflare"
LEGACY_MANAGED_PREFIX = "torloc-in-"
CLOUDFLARE_HTTPS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


class CDNProfileError(RuntimeError):
    pass


def normalize_cdn_domain(value: str, base_url: str = "") -> str:
    domain = (value or "").strip().lower().rstrip(".")
    if not domain and base_url:
        domain = (urlparse(base_url).hostname or "").strip().lower().rstrip(".")
    if not domain:
        raise CDNProfileError("دامنه CDN مشخص نشده است.")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise CDNProfileError("برای Cloudflare CDN باید دامنه استفاده شود، نه IP مستقیم.")
    if not DOMAIN_RE.fullmatch(domain):
        raise CDNProfileError("دامنه CDN معتبر نیست.")
    return domain


def normalize_cdn_port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise CDNProfileError("پورت CDN معتبر نیست.") from exc
    if port not in CLOUDFLARE_HTTPS_PORTS:
        ports = ", ".join(str(x) for x in sorted(CLOUDFLARE_HTTPS_PORTS))
        raise CDNProfileError(f"پورت CDN باید یکی از پورت‌های HTTPS قابل Proxy در Cloudflare باشد: {ports}")
    return port


def normalize_ws_path(value: str) -> str:
    path = (value or "").strip()
    if not path:
        raise CDNProfileError("WebSocket path خالی است.")
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 180 or any(ch in path for ch in ("?", "#", "\r", "\n", " ")):
        raise CDNProfileError("WebSocket path معتبر نیست.")
    if not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+", path):
        raise CDNProfileError("WebSocket path فقط باید شامل کاراکترهای امن URL باشد.")
    return path


def managed_client_email(location: dict[str, Any]) -> str:
    slug = str(location.get("slug") or "").strip()
    return f"torloc.{slug}@managed.invalid"


def derive_vless_id(location: dict[str, Any], decrypt_password) -> str:
    # The UUID is an authentication secret. Derive it from the encrypted gateway
    # secret so it is stable across reconciles but cannot be guessed from a slug.
    gateway_secret = decrypt_password(location["ss_password"]).encode("utf-8")
    material = (
        b"tor-location-manager:cloudflare-vless:v1\x00"
        + str(location["slug"]).encode("utf-8")
        + b"\x00"
        + gateway_secret
    )
    raw = bytearray(hashlib.sha256(material).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def _derive_sub_id(location: dict[str, Any], decrypt_password) -> str:
    gateway_secret = decrypt_password(location["ss_password"]).encode("utf-8")
    material = (
        b"tor-location-manager:cloudflare-subid:v1\x00"
        + str(location["slug"]).encode("utf-8")
        + b"\x00"
        + gateway_secret
    )
    raw = bytearray(hashlib.sha256(material).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def _client(location: dict[str, Any], decrypt_password) -> dict[str, Any]:
    return {
        "id": derive_vless_id(location, decrypt_password),
        "email": managed_client_email(location),
        "flow": "",
        "limitIp": 0,
        "totalGB": 0,
        "expiryTime": 0,
        "enable": True,
        "tgId": 0,
        "subId": _derive_sub_id(location, decrypt_password),
        "comment": f"Tor {str(location.get('country_code') or '').upper()} · {location.get('name') or location.get('slug')}",
        "reset": 0,
    }


def build_cdn_inbound_payload(
    locations: list[dict[str, Any]],
    settings: Any,
    cert_files: dict[str, str],
    decrypt_password,
) -> dict[str, Any]:
    domain = normalize_cdn_domain(settings.cdn_domain, settings.base_url)
    port = normalize_cdn_port(settings.cdn_port)
    path = normalize_ws_path(settings.cdn_ws_path)
    cert_file = str(cert_files.get("webCertFile") or "").strip()
    key_file = str(cert_files.get("webKeyFile") or "").strip()
    if not cert_file or not key_file:
        raise CDNProfileError(
            "3x-ui برای پنل Certificate/Key ثبت‌شده ندارد. ابتدا webCertFile و webKeyFile پنل را تنظیم کنید."
        )
    if not cert_file.startswith("/") or not key_file.startswith("/"):
        raise CDNProfileError("مسیر Certificate/Key پنل در 3x-ui معتبر نیست.")

    clients = [
        _client(loc, decrypt_password)
        for loc in locations
        if loc.get("enabled")
    ]
    return {
        "remark": CDN_MANAGED_REMARK,
        "enable": True,
        "expiryTime": 0,
        "total": 0,
        "trafficReset": "never",
        "listen": "",
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": clients,
            "decryption": "none",
            "encryption": "none",
        },
        "streamSettings": {
            "network": "ws",
            "wsSettings": {
                "acceptProxyProtocol": False,
                "path": path,
                "host": domain,
                "headers": {
                    "Host": domain,
                },
                "heartbeatPeriod": 30,
            },
            "security": "tls",
            "tlsSettings": {
                "serverName": domain,
                # Keep TLS 1.2 as the minimum even though 3x-ui allows 1.0.
                # It matches modern Cloudflare origins while avoiding legacy TLS.
                "minVersion": "1.2",
                "maxVersion": "1.3",
                "cipherSuites": "",
                "rejectUnknownSni": bool(settings.cdn_reject_unknown_sni),
                "disableSystemRoot": False,
                "enableSessionResumption": False,
                "certificates": [{
                    "ocspStapling": 0,
                    "oneTimeLoading": False,
                    "usage": "encipherment",
                    "buildChain": False,
                    "certificateFile": cert_file,
                    "keyFile": key_file,
                    "useFile": True,
                }],
                "alpn": ["h3", "h2", "http/1.1"],
                "echServerKeys": "",
                "settings": {
                    "fingerprint": "randomized",
                    "echConfigList": "",
                    "pinnedPeerCertSha256": [],
                    "verifyPeerCertByName": "",
                },
            },
        },
        "tag": CDN_MANAGED_TAG,
        "sniffing": {
            # routeOnly lets Xray use HTTP Host / TLS SNI for routing without
            # rewriting the destination. This makes selective WARP routing work
            # even when the client resolved the website to an IP locally.
            "enabled": True,
            "destOverride": ["http", "tls"],
            "metadataOnly": False,
            "routeOnly": True,
        },
    }


def _obj(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError):
            return {}
    return {}


def _is_managed_location_client(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    email = str(row.get("email") or "").strip().lower()
    return email.startswith("torloc.") and email.endswith("@managed.invalid")


def merge_preserved_cdn_clients(
    current: dict[str, Any],
    expected: dict[str, Any],
) -> dict[str, Any]:
    """Keep operator-created clients while reconciling only TLM clients."""
    merged = copy.deepcopy(expected)
    current_settings = _obj(current.get("settings"))
    if not isinstance(current_settings.get("clients"), list):
        raise CDNProfileError(
            "3x-ui فهرست کاربران CDN را برنگرداند؛ Sync بدون حذف کاربران متوقف شد."
        )
    current_clients = current_settings["clients"]
    if not all(isinstance(row, dict) for row in current_clients):
        raise CDNProfileError("فهرست کاربران CDN ناقص است؛ Sync متوقف شد.")
    existing_by_email = {
        str(row.get("email") or "").strip().lower(): row
        for row in current_clients if _is_managed_location_client(row)
    }
    managed_clients = []
    desired_emails = set()
    for generated in (expected.get("settings", {}).get("clients") or []):
        email = str(generated.get("email") or "").strip().lower()
        desired_emails.add(email)
        # Retain the exact live UUID, subscription ID and user limits.
        managed_clients.append(copy.deepcopy(existing_by_email.get(email, generated)))
    # Orphaned managed users are disabled, not deleted; they can be recovered.
    stale = [
        {**copy.deepcopy(row), "enable": False}
        for row in current_clients
        if _is_managed_location_client(row)
        and str(row.get("email") or "").strip().lower() not in desired_emails
    ]
    foreign_clients = [
        copy.deepcopy(row) for row in current_clients
        if not _is_managed_location_client(row)
    ]
    merged["settings"] = copy.deepcopy(current_settings)
    merged["settings"]["decryption"] = "none"
    merged["settings"]["encryption"] = "none"
    merged["settings"]["clients"] = foreign_clients + managed_clients + stale
    for key in ("shareAddrStrategy", "shareAddr", "subSortIndex"):
        if key in current:
            merged[key] = copy.deepcopy(current[key])
    return merged


def _client_projection(row: Any) -> tuple[str, str, bool, str, int, str]:
    if not isinstance(row, dict):
        return ("", "", False, "", 0, "")
    raw_tg_id = row.get("tgId", 0)
    # 3x-ui's Go model requires tgId to be JSON integer (int64), never an
    # empty string. Treat legacy empty-string data as a mismatch so the next
    # reconciliation rewrites the managed inbound with the typed value 0.
    try:
        tg_id = int(raw_tg_id or 0)
    except (TypeError, ValueError):
        tg_id = -1
    return (
        str(row.get("email") or ""),
        str(row.get("id") or ""),
        bool(row.get("enable", True)),
        str(row.get("flow") or ""),
        tg_id,
        str(row.get("subId") or ""),
    )


def cdn_inbound_matches(current: dict[str, Any], expected: dict[str, Any]) -> bool:
    for key in ("tag", "remark", "protocol"):
        if str(current.get(key) or "") != str(expected.get(key) or ""):
            return False
    if int(current.get("port") or 0) != int(expected["port"]):
        return False
    if not bool(current.get("enable")):
        return False

    current_settings = _obj(current.get("settings"))
    expected_settings = expected["settings"]
    if str(current_settings.get("decryption") or "") != "none":
        return False
    if str(current_settings.get("encryption") or "") != "none":
        return False
    current_clients = sorted(_client_projection(x) for x in (current_settings.get("clients") or []))
    expected_clients = sorted(_client_projection(x) for x in expected_settings["clients"])
    if current_clients != expected_clients:
        return False

    current_stream = _obj(current.get("streamSettings"))
    expected_stream = expected["streamSettings"]
    if current_stream.get("network") != "ws" or current_stream.get("security") != "tls":
        return False

    current_ws = _obj(current_stream.get("wsSettings"))
    expected_ws = expected_stream["wsSettings"]
    for key in ("path", "host"):
        if str(current_ws.get(key) or "") != str(expected_ws[key]):
            return False
    current_headers = _obj(current_ws.get("headers"))
    expected_headers = expected_ws["headers"]
    if str(current_headers.get("Host") or "") != str(expected_headers["Host"]):
        return False
    if int(current_ws.get("heartbeatPeriod") or 0) != int(expected_ws["heartbeatPeriod"]):
        return False

    current_sniffing = _obj(current.get("sniffing"))
    expected_sniffing = expected["sniffing"]
    if bool(current_sniffing.get("enabled")) != bool(expected_sniffing["enabled"]):
        return False
    if list(current_sniffing.get("destOverride") or []) != list(expected_sniffing["destOverride"]):
        return False
    if bool(current_sniffing.get("routeOnly")) != bool(expected_sniffing["routeOnly"]):
        return False

    current_tls = _obj(current_stream.get("tlsSettings"))
    expected_tls = expected_stream["tlsSettings"]
    for key in ("serverName", "minVersion", "maxVersion"):
        if str(current_tls.get(key) or "") != str(expected_tls.get(key) or ""):
            return False
    if bool(current_tls.get("rejectUnknownSni")) != bool(expected_tls["rejectUnknownSni"]):
        return False
    if list(current_tls.get("alpn") or []) != list(expected_tls["alpn"]):
        return False
    for key in ("disableSystemRoot", "enableSessionResumption"):
        if bool(current_tls.get(key)) != bool(expected_tls[key]):
            return False
    current_certs = current_tls.get("certificates") or []
    expected_certs = expected_tls["certificates"]
    if not current_certs or not isinstance(current_certs[0], dict):
        return False
    for key in ("certificateFile", "keyFile", "usage"):
        if str(current_certs[0].get(key) or "") != str(expected_certs[0].get(key) or ""):
            return False
    if bool(current_certs[0].get("useFile", False)) is not True:
        return False
    return True


def _is_managed_cdn_row(row: dict[str, Any]) -> bool:
    return (
        str(row.get("tag") or "") == CDN_MANAGED_TAG
        or str(row.get("remark") or "") == CDN_MANAGED_REMARK
    )


def _xui_web_port(settings: Any) -> int:
    try:
        parsed = urlparse(str(getattr(settings, "base_url", "") or ""))
        if parsed.port:
            return int(parsed.port)
        return 443 if parsed.scheme == "https" else 80
    except Exception:
        return 0


def _row_id(row: dict[str, Any]) -> int | None:
    try:
        return int(row.get("id")) if row.get("id") is not None else None
    except (TypeError, ValueError):
        return None


def _pick_free_cdn_port(
    options: list[dict[str, Any]],
    settings: Any,
    preferred: int,
    ignore_ids: set[int] | None = None,
    blocked_ports: set[int] | None = None,
) -> int:
    ignored = ignore_ids or set()
    used: set[int] = set(blocked_ports or ())
    for row in options:
        if _row_id(row) in ignored:
            continue
        try:
            port = int(row.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if port > 0:
            used.add(port)
    panel_port = _xui_web_port(settings)
    if panel_port:
        used.add(panel_port)
    order = [preferred, 443, 8443, 2053, 2083, 2087, 2096]
    for port in order:
        if port in CLOUDFLARE_HTTPS_PORTS and port not in used:
            return port
    raise CDNProfileError(
        "هیچ پورت HTTPS آزاد سازگار با Cloudflare برای Inbound مدیریت‌شده پیدا نشد."
    )


def _is_port_conflict_error(exc: Exception) -> bool:
    message = str(exc or "").lower()
    has_port = "port" in message or "پورت" in message
    conflict_words = (
        "already", "exists", "exist", "used", "in use", "occupied",
        "duplicate", "استفاده", "موجود", "اشغال",
    )
    return has_port and any(word in message for word in conflict_words)


def reconcile_cdn_inbound(client: Any, locations: list[dict[str, Any]], decrypt_password) -> dict[str, Any]:
    """Reconcile CDN safely with 3x-ui 3.8.5 port/relay conflict validation.

    Do not remove working legacy inbounds until the shared CDN inbound exists.
    Port conflicts can come from AWG relays or forwarded peers that the inbound
    options API cannot list, so retry every eligible Cloudflare port.
    """
    options = client.list_inbounds()
    enabled = [loc for loc in locations if loc.get("enabled")]
    desired_port = normalize_cdn_port(client.settings.cdn_port)
    managed_rows = [row for row in options if _is_managed_cdn_row(row)]
    existing = next(
        (row for row in managed_rows if int(row.get("port") or 0) == desired_port),
        None,
    )
    if existing is None and managed_rows:
        existing = next(
            (row for row in managed_rows if str(row.get("tag") or "") == CDN_MANAGED_TAG),
            managed_rows[0],
        )
        existing_port = int(existing.get("port") or 0)
        if existing_port in CLOUDFLARE_HTTPS_PORTS:
            desired_port = existing_port

    if not enabled:
        # Never delete the shared inbound: it may also contain real operator
        # clients. Disable only synthetic clients for inactive locations.
        if existing is not None and _row_id(existing) is not None:
            inbound_id = _row_id(existing)
            current = client.get_inbound(inbound_id)
            settings_obj = _obj(current.get("settings"))
            clients = settings_obj.get("clients")
            if not isinstance(clients, list) or not all(isinstance(row, dict) for row in clients):
                raise CDNProfileError("فهرست کاربران CDN ناقص است؛ Sync متوقف شد.")
            if any(_is_managed_location_client(row) and row.get("enable", True) for row in clients):
                updated_payload = copy.deepcopy(current)
                settings_obj["clients"] = [
                    {**row, "enable": False} if _is_managed_location_client(row) else row
                    for row in clients
                ]
                updated_payload["settings"] = settings_obj
                client.update_inbound(inbound_id, updated_payload)
                changed = 1
            else:
                changed = 0
            return {
                "created": 0, "updated": changed, "removed": 0,
                "cdn_clients": 0, "cdn_inbound_tag": str(existing.get("tag") or ""),
                "cdn_port": desired_port, "preserved_legacy_tags": [],
            }
        return {
            "created": 0, "updated": 0, "removed": 0,
            "cdn_clients": 0, "cdn_inbound_tag": "",
            "cdn_port": desired_port, "preserved_legacy_tags": [],
        }

    existing_id = _row_id(existing) if existing else None
    if existing is not None and existing_id is None:
        raise CDNProfileError("Inbound مدیریت‌شده CDN شناسه معتبر ندارد؛ حذف خودکار انجام نشد.")
    existing_tag = str((existing or {}).get("tag") or CDN_MANAGED_TAG)
    original_port = client.settings.cdn_port
    cert_files = client.get_web_cert_files()
    blocked_ports: set[int] = set()
    ignored_ids = {existing_id} if existing_id is not None else set()
    current = client.get_inbound(existing_id) if existing_id is not None else None

    try:
        while True:
            candidate = _pick_free_cdn_port(
                options, client.settings, desired_port,
                ignore_ids=ignored_ids, blocked_ports=blocked_ports,
            )
            client.settings.cdn_port = candidate
            expected = build_cdn_inbound_payload(
                enabled, client.settings, cert_files, decrypt_password
            )
            if existing is not None:
                expected["tag"] = existing_tag
            if current is not None:
                expected = merge_preserved_cdn_clients(current, expected)

            if current is not None and cdn_inbound_matches(current, expected):
                created = updated = 0
                actual_tag = existing_tag
                break

            try:
                if existing_id is None:
                    client.add_inbound(expected)
                else:
                    client.update_inbound(existing_id, expected)
            except Exception as exc:
                if not _is_port_conflict_error(exc):
                    raise
                # Current 3x-ui also reserves ports forwarded by AmneziaWG
                # peers. Those are not represented by /inbounds/options.
                blocked_ports.add(candidate)
                options = client.list_inbounds()
                continue

            created = 1 if existing_id is None else 0
            updated = 0 if existing_id is None else 1
            if created:
                refreshed = client.list_inbounds()
                created_row = next(
                    (row for row in refreshed if _is_managed_cdn_row(row)
                     and int(row.get("port") or 0) == candidate),
                    None,
                )
                if created_row is None:
                    raise CDNProfileError(
                        "3x-ui ایجاد Inbound CDN را پذیرفت اما ورودی جدید در فهرست یافت نشد؛ "
                        "ورودی‌های قدیمی برای جلوگیری از قطعی حفظ شدند."
                    )
                actual_tag = str(created_row.get("tag") or CDN_MANAGED_TAG)
                existing_id = _row_id(created_row)
            else:
                actual_tag = existing_tag
            break
    except Exception:
        client.settings.cdn_port = original_port
        raise

    # Persist the selected port only after a successful add/update. If creation
    # failed, older per-location routes and stored settings are untouched.
    if client.settings.cdn_port != original_port:
        set_setting("xui_cdn_port", str(client.settings.cdn_port))

    # Legacy inbounds may still have paying users. Keep them and preserve
    # their routes during the CDN migration. Cleanup must be explicit.
    retained_legacy_tags = [
        str(row.get("tag"))
        for row in client.list_inbounds()
        if str(row.get("tag") or "").startswith(LEGACY_MANAGED_PREFIX)
    ]
    return {
        "created": created, "updated": updated, "removed": 0,
        "cdn_clients": len(enabled), "cdn_inbound_tag": actual_tag,
        "cdn_port": client.settings.cdn_port,
        "preserved_legacy_tags": retained_legacy_tags,
    }


def managed_cdn_client_uri(location: dict[str, Any], settings: Any, decrypt_password) -> str:
    if getattr(settings, "managed_inbound_mode", "legacy") != "cloudflare":
        return ""
    domain = normalize_cdn_domain(settings.cdn_domain, settings.base_url)
    port = normalize_cdn_port(settings.cdn_port)
    path = normalize_ws_path(settings.cdn_ws_path)
    client_id = derive_vless_id(location, decrypt_password)
    query = urlencode({
        "encryption": "none",
        "security": "tls",
        "sni": domain,
        "fp": "chrome",
        "type": "ws",
        "host": domain,
        "path": path,
        "alpn": "h3,h2,http/1.1",
    })
    label = quote(f"Tor {str(location.get('country_code') or '').upper()} · {location.get('name') or location.get('slug')}")
    return f"vless://{client_id}@{domain}:{port}?{query}#{label}"
