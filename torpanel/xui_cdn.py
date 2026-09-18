from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from typing import Any
from urllib.parse import quote, urlencode, urlparse

CDN_MANAGED_TAG = "torloc-cdn"
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
        "remark": "Tor CDN Gateway · Cloudflare",
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


def reconcile_cdn_inbound(client: Any, locations: list[dict[str, Any]], decrypt_password) -> dict[str, int]:
    options = client.list_inbounds()
    enabled = [loc for loc in locations if loc.get("enabled")]
    removed = 0

    desired_port = normalize_cdn_port(client.settings.cdn_port)
    conflicts = [
        row for row in options
        if str(row.get("tag") or "") != CDN_MANAGED_TAG
        and int(row.get("port") or 0) == desired_port
    ]
    if conflicts:
        names = ", ".join(
            str(row.get("remark") or row.get("tag") or row.get("id") or "Inbound")
            for row in conflicts[:5]
        )
        alternatives = sorted(CLOUDFLARE_HTTPS_PORTS - {desired_port})
        raise CDNProfileError(
            f"پورت {desired_port} قبلاً در 3x-ui استفاده می‌شود ({names}). "
            f"یکی از پورت‌های آزاد سازگار با Cloudflare را انتخاب کنید: "
            + ", ".join(str(port) for port in alternatives)
        )

    # Cloudflare mode replaces the old per-location SS2022 public inbounds.
    for row in list(options):
        tag = str(row.get("tag") or "")
        if tag.startswith(LEGACY_MANAGED_PREFIX) or (tag == CDN_MANAGED_TAG and not enabled):
            if row.get("id") is not None:
                client.delete_inbound(int(row["id"]))
                removed += 1

    if not enabled:
        return {"created": 0, "updated": 0, "removed": removed, "cdn_clients": 0}

    if removed:
        options = client.list_inbounds()

    cert_files = client.get_web_cert_files()
    expected = build_cdn_inbound_payload(enabled, client.settings, cert_files, decrypt_password)
    existing = next((row for row in options if str(row.get("tag") or "") == CDN_MANAGED_TAG), None)
    if existing is None:
        client.add_inbound(expected)
        return {"created": 1, "updated": 0, "removed": removed, "cdn_clients": len(enabled)}

    if existing.get("id") is None:
        return {"created": 0, "updated": 0, "removed": removed, "cdn_clients": len(enabled)}

    current = client.get_inbound(int(existing["id"]))
    if not cdn_inbound_matches(current, expected):
        client.update_inbound(int(existing["id"]), expected)
        return {"created": 0, "updated": 1, "removed": removed, "cdn_clients": len(enabled)}
    return {"created": 0, "updated": 0, "removed": removed, "cdn_clients": len(enabled)}


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
