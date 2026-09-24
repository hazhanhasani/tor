from __future__ import annotations

import base64
import hashlib
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

REALITY_DEST = "www.cloudflare.com:443"
REALITY_SERVER_NAME = "www.cloudflare.com"
REALITY_FLOW = "xtls-rprx-vision"


@dataclass(frozen=True)
class RealityIdentity:
    client_id: str
    private_key: str
    public_key: str
    short_id: str


def _secret(location: dict[str, Any], decrypt_password: Callable[[str], str]) -> bytes:
    return decrypt_password(str(location["ss_password"])).encode("utf-8")


def _material(location: dict[str, Any], decrypt_password, purpose: str, label: str) -> bytes:
    return (
        b"tor-location-manager:vless-reality:v1\x00"
        + purpose.encode("utf-8")
        + b"\x00"
        + label.encode("utf-8")
        + b"\x00"
        + str(location["slug"]).encode("utf-8")
        + b"\x00"
        + _secret(location, decrypt_password)
    )


def _stable_uuid(location: dict[str, Any], decrypt_password, purpose: str, label: str) -> str:
    raw = bytearray(hashlib.sha256(_material(location, decrypt_password, purpose, label)).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def derive_reality_identity(
    location: dict[str, Any],
    decrypt_password,
    purpose: str,
) -> RealityIdentity:
    private_seed = hashlib.sha256(
        _material(location, decrypt_password, purpose, "x25519")
    ).digest()
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_seed)
    private_raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    short_id = hashlib.sha256(
        _material(location, decrypt_password, purpose, "short-id")
    ).hexdigest()[:16]
    return RealityIdentity(
        client_id=_stable_uuid(location, decrypt_password, purpose, "client-id"),
        private_key=_b64url(private_raw),
        public_key=_b64url(public_raw),
        short_id=short_id,
    )


def gateway_reality_identity(location: dict[str, Any], decrypt_password) -> RealityIdentity:
    return derive_reality_identity(location, decrypt_password, "gateway")


def managed_inbound_reality_identity(location: dict[str, Any], decrypt_password) -> RealityIdentity:
    return derive_reality_identity(location, decrypt_password, "managed-inbound")


def managed_subscription_id(location: dict[str, Any], decrypt_password) -> str:
    return _stable_uuid(location, decrypt_password, "managed-inbound", "subscription-id")


def _server_reality_settings(identity: RealityIdentity) -> dict[str, Any]:
    return {
        "show": False,
        "dest": REALITY_DEST,
        "xver": 0,
        "serverNames": [REALITY_SERVER_NAME],
        "privateKey": identity.private_key,
        "shortIds": [identity.short_id],
    }


def _client_reality_settings(identity: RealityIdentity) -> dict[str, Any]:
    return {
        "show": False,
        "fingerprint": "chrome",
        "serverName": REALITY_SERVER_NAME,
        "publicKey": identity.public_key,
        "shortId": identity.short_id,
        "spiderX": "/",
    }


def build_gateway_vless_inbound(
    location: dict[str, Any],
    decrypt_password,
    tag: str,
) -> dict[str, Any]:
    identity = gateway_reality_identity(location, decrypt_password)
    return {
        "tag": tag,
        "listen": "0.0.0.0",
        "port": int(location["gateway_port"]),
        "protocol": "vless",
        "settings": {
            "clients": [{
                "id": identity.client_id,
                "flow": REALITY_FLOW,
                "email": f"tor-gateway.{location['slug']}@managed.invalid",
            }],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": _server_reality_settings(identity),
        },
        "sniffing": {"enabled": False},
    }


def build_gateway_vless_outbound(
    location: dict[str, Any],
    gateway_host: str,
    decrypt_password,
    tag: str,
) -> dict[str, Any]:
    identity = gateway_reality_identity(location, decrypt_password)
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "address": str(gateway_host),
            "port": int(location["gateway_port"]),
            "id": identity.client_id,
            "flow": REALITY_FLOW,
            "encryption": "none",
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": _client_reality_settings(identity),
        },
    }


def build_managed_vless_inbound(
    location: dict[str, Any],
    decrypt_password,
    *,
    tag: str,
    port: int,
) -> dict[str, Any]:
    identity = managed_inbound_reality_identity(location, decrypt_password)
    return {
        "remark": f"Tor {str(location['country_code']).upper()} · {location['name']}",
        "enable": True,
        "expiryTime": 0,
        "total": 0,
        "trafficReset": "never",
        "listen": "",
        "port": int(port),
        "protocol": "vless",
        "settings": {
            "clients": [{
                "id": identity.client_id,
                "email": f"torloc.{location['slug']}@managed.invalid",
                "flow": REALITY_FLOW,
                "limitIp": 0,
                "totalGB": 0,
                "expiryTime": 0,
                "enable": True,
                "tgId": 0,
                "subId": managed_subscription_id(location, decrypt_password),
                "comment": f"Tor {str(location['country_code']).upper()} · {location['name']}",
                "reset": 0,
            }],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": _server_reality_settings(identity),
        },
        "tag": tag,
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls"],
            "metadataOnly": False,
            "routeOnly": True,
        },
    }
