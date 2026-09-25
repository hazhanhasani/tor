"""Build a conservative TCP/DoH Xray client for a supplied VLESS REALITY URI.

The URI is supplied by an authenticated administrator over POST and must never
be stored or logged. The resulting profile keeps DNS on the proxy path and
blocks unsupported arbitrary UDP rather than leaking it as direct traffic.
"""
from __future__ import annotations

import ipaddress
import json
import re
import uuid
from urllib.parse import parse_qs, unquote, urlsplit


class ClientProfileError(ValueError):
    pass


def _host(value: str) -> str:
    host = (value or "").strip()
    if not host or len(host) > 253 or any(c.isspace() for c in host):
        raise ClientProfileError("آدرس سرور VLESS معتبر نیست.")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not re.fullmatch(
        r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host
    ):
        raise ClientProfileError("Hostname کانفیگ VLESS معتبر نیست.")
    if any(not label or len(label) > 63 or label.startswith("-")
           or label.endswith("-") for label in host.split(".")):
        raise ClientProfileError("Hostname کانفیگ VLESS معتبر نیست.")
    return host


def parse_reality_uri(uri: str) -> dict:
    if not isinstance(uri, str) or len(uri) > 4096:
        raise ClientProfileError("لینک VLESS معتبر نیست.")
    try:
        link = urlsplit(uri.strip())
        if link.scheme.lower() != "vless" or not link.hostname or not link.port:
            raise ValueError("missing uri fields")
        user_id = str(uuid.UUID(unquote(link.username or "")))
        query = parse_qs(link.query, keep_blank_values=True)
    except (ValueError, TypeError) as exc:
        raise ClientProfileError("لینک معتبر VLESS با UUID و پورت لازم است.") from exc

    def field(name: str, default: str = "") -> str:
        values = query.get(name, [])
        if len(values) > 1:
            raise ClientProfileError(f"پارامتر تکراری: {name}")
        return values[0] if values else default

    if field("security").lower() != "reality":
        raise ClientProfileError("این سازنده فقط VLESS + REALITY را پشتیبانی می‌کند.")
    if field("type", "tcp").lower() not in {"tcp", "raw"}:
        raise ClientProfileError("این پروفایل مخصوص حمل‌ونقل TCP/REALITY است.")
    flow = field("flow")
    if flow not in {"", "xtls-rprx-vision"}:
        raise ClientProfileError("Flow ناشناخته است؛ تنظیمات کاربر را دستی بررسی کنید.")
    pbk, sid, sni = field("pbk"), field("sid"), field("sni")
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,50}", pbk):
        raise ClientProfileError("کلید عمومی REALITY معتبر نیست.")
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", sid):
        raise ClientProfileError("Short ID معتبر نیست.")
    server_name = _host(sni)
    fingerprint = field("fp", "chrome")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,30}", fingerprint):
        raise ClientProfileError("Fingerprint معتبر نیست.")
    spider = field("spx", "/")
    if not spider.startswith("/") or len(spider) > 256 or any(
        ord(char) < 32 for char in spider
    ):
        raise ClientProfileError("spiderX معتبر نیست.")
    if field("encryption", "none") != "none":
        raise ClientProfileError("VLESS باید encryption=none داشته باشد.")
    return {
        "address": _host(link.hostname),
        "port": link.port,
        "id": user_id,
        "flow": flow,
        "publicKey": pbk,
        "shortId": sid.lower(),
        "serverName": server_name,
        "fingerprint": fingerprint,
        "spiderX": spider,
        "label": unquote(link.fragment or "Tor VLESS")[:80],
    }


def build_client_profile(uri: str) -> dict:
    """Return a JSON-serializable stock Xray client profile, not 3x-ui API data."""
    server = parse_reality_uri(uri)
    return {
        "remarks": server["label"],
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                {"address": "https://1.1.1.1/dns-query", "queryStrategy": "UseIPv4"},
                {"address": "https://8.8.8.8/dns-query", "queryStrategy": "UseIPv4"},
            ],
            "queryStrategy": "UseIPv4",
            "tag": "dns-module",
        },
        "inbounds": [
            {
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "enabled": True, "destOverride": ["http", "tls"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "http",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
            },
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": server["address"],
                        "port": server["port"],
                        "users": [{
                            "id": server["id"],
                            "encryption": "none",
                            "flow": server["flow"],
                        }],
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "fingerprint": server["fingerprint"],
                        "serverName": server["serverName"],
                        "publicKey": server["publicKey"],
                        "shortId": server["shortId"],
                        "spiderX": server["spiderX"],
                    },
                },
                "mux": {"enabled": False},
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
            {"tag": "dns-out", "protocol": "dns"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field", "inboundTag": ["socks", "http"],
                    "port": "53", "outboundTag": "dns-out",
                },
                {
                    "type": "field", "network": "udp",
                    "outboundTag": "block",
                },
                {
                    "type": "field", "ip": ["geoip:private"],
                    "outboundTag": "direct",
                },
                {
                    "type": "field", "domain": ["geosite:private"],
                    "outboundTag": "direct",
                },
                {
                    "type": "field", "inboundTag": ["dns-module"],
                    "outboundTag": "proxy",
                },
            ],
        },
    }


def profile_json(uri: str) -> str:
    return json.dumps(build_client_profile(uri), ensure_ascii=False, indent=2) + "\n"
