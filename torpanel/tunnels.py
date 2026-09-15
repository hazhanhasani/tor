from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import (
    bind_tunnel_link_node,
    consume_tunnel_enrollment,
    create_tunnel_link as db_create_tunnel_link,
    create_tunnel_node,
    delete_tunnel_link as db_delete_tunnel_link,
    get_setting,
    get_tunnel_link,
    get_tunnel_node,
    get_tunnel_node_by_token_hash,
    links_for_tunnel_node,
    list_tunnel_links,
    list_tunnel_nodes,
    replace_tunnel_enrollment,
    tunnel_resource_sets,
    update_tunnel_link,
    update_tunnel_node_seen,
)
from .security import decrypt_secret, encrypt_secret

AGENT_VERSION = "1.0.0"
WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)$")


class TunnelError(RuntimeError):
    pass


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_name(value: str, fallback: str) -> str:
    value = (value or "").strip()
    if not value:
        return fallback
    if len(value) > 80:
        raise TunnelError("نام نود یا لینک حداکثر ۸۰ کاراکتر است.")
    return value


def _validate_host(value: str) -> str:
    value = (value or "").strip().strip("[]")
    if not value:
        return ""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not HOST_RE.fullmatch(value) or ".." in value:
        raise TunnelError("Advertise host معتبر نیست.")
    return value.lower()


def _validate_wg_public_key(value: str) -> str:
    value = (value or "").strip()
    if not WG_KEY_RE.fullmatch(value):
        raise TunnelError("WireGuard public key معتبر نیست.")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise TunnelError("WireGuard public key معتبر نیست.") from exc
    if len(raw) != 32:
        raise TunnelError("WireGuard public key معتبر نیست.")
    return value


def _allocate_resources() -> dict[str, Any]:
    used = tunnel_resource_sets()
    overlay_cidr = get_setting("tunnel_overlay_cidr", "10.203.0.0/16") or "10.203.0.0/16"
    try:
        network = ipaddress.ip_network(overlay_cidr, strict=True)
    except ValueError as exc:
        raise TunnelError("CIDR شبکه Overlay معتبر نیست.") from exc
    if network.version != 4 or network.prefixlen > 28:
        raise TunnelError("Overlay CIDR باید IPv4 و حداقل دارای فضای /28 باشد.")

    # Up to 8000 simultaneously configured links with the default port plan.
    for slot, subnet in enumerate(network.subnets(new_prefix=30), start=0):
        if slot >= 8000:
            break
        subnet_text = str(subnet)
        wg_port = 52000 + slot
        frp_control = 22000 + slot
        frp_proxy = 40000 + slot
        if wg_port > 59999 or frp_control > 29999 or frp_proxy > 47999:
            break
        if subnet_text in used["subnets"]:
            continue
        if wg_port in used["wg_ports"] or frp_control in used["frp_control_ports"] or frp_proxy in used["frp_proxy_ports"]:
            continue
        hosts = list(subnet.hosts())
        if len(hosts) < 2:
            continue
        return {
            "subnet_cidr": subnet_text,
            "iran_overlay_ip": str(hosts[0]),
            "foreign_overlay_ip": str(hosts[1]),
            "foreign_wg_port": wg_port,
            "iran_frp_control_port": frp_control,
            "iran_frp_proxy_port": frp_proxy,
        }
    raise TunnelError("فضای خودکار Tunnel تمام شده است؛ CIDR یا محدوده پورت‌ها باید توسعه یابد.")


def create_link(name: str, mode: str = "auto", kill_switch: bool = True, health_timeout: int = 45) -> dict[str, Any]:
    name = _validate_name(name, "Hybrid Tunnel")
    mode = (mode or "auto").strip().lower()
    if mode not in {"auto", "direct", "reverse"}:
        raise TunnelError("حالت Tunnel معتبر نیست.")
    try:
        health_timeout = int(health_timeout)
    except (TypeError, ValueError) as exc:
        raise TunnelError("Health timeout معتبر نیست.") from exc
    if not 15 <= health_timeout <= 300:
        raise TunnelError("Health timeout باید بین ۱۵ تا ۳۰۰ ثانیه باشد.")

    resources = _allocate_resources()
    wg_psk = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    frp_token = secrets.token_urlsafe(36)
    link_uuid = str(uuid.uuid4())
    return db_create_tunnel_link({
        "uuid": link_uuid,
        "name": name,
        "mode": mode,
        "kill_switch": kill_switch,
        "health_timeout": health_timeout,
        "wg_psk": encrypt_secret(wg_psk),
        "frp_token": encrypt_secret(frp_token),
        **resources,
    })


def delete_link(link_uuid: str) -> None:
    if not get_tunnel_link(link_uuid):
        raise TunnelError("Tunnel پیدا نشد.")
    db_delete_tunnel_link(link_uuid)


def issue_enrollment(link_uuid: str, role: str, ttl_minutes: int = 30) -> str:
    link = get_tunnel_link(link_uuid)
    if not link:
        raise TunnelError("Tunnel پیدا نشد.")
    if role not in {"iran", "foreign"}:
        raise TunnelError("Role معتبر نیست.")
    token = secrets.token_urlsafe(32)
    expires_at = (_now() + timedelta(minutes=max(5, min(int(ttl_minutes), 1440)))).isoformat()
    replace_tunnel_enrollment(link_uuid, role, token_hash(token), expires_at)
    return token


def enroll_node(payload: dict[str, Any], observed_ip: str) -> tuple[dict[str, Any], str, dict[str, Any]]:
    raw_token = str(payload.get("token") or "").strip()
    if not raw_token:
        raise TunnelError("Enrollment token ارسال نشده است.")
    enrollment = consume_tunnel_enrollment(token_hash(raw_token))
    if not enrollment:
        raise TunnelError("Enrollment token نامعتبر، مصرف‌شده یا منقضی است.")

    link = get_tunnel_link(str(enrollment["link_uuid"]))
    if not link:
        raise TunnelError("Tunnel مرتبط با token وجود ندارد.")
    role = str(enrollment["role"])
    current_uuid = link.get(f"{role}_node_uuid")
    if current_uuid:
        # Explicitly rotating an enrollment token is allowed to replace a node on the link.
        existing = get_tunnel_node(str(current_uuid))
        if existing and existing.get("enabled"):
            raise TunnelError("این سمت Tunnel قبلاً Node فعال دارد؛ ابتدا Node قبلی را غیرفعال یا Link را دوباره بسازید.")

    wg_public_key = _validate_wg_public_key(str(payload.get("wg_public_key") or ""))
    node_uuid = str(uuid.uuid4())
    agent_token = secrets.token_urlsafe(40)
    node = create_tunnel_node({
        "uuid": node_uuid,
        "name": _validate_name(str(payload.get("name") or ""), "Iran Node" if role == "iran" else "Foreign Node"),
        "role": role,
        "observed_ip": observed_ip or "",
        "advertise_host": _validate_host(str(payload.get("advertise_host") or "")),
        "wg_public_key": wg_public_key,
        "agent_token_hash": token_hash(agent_token),
        "agent_version": str(payload.get("agent_version") or "")[:32],
        "os_info": str(payload.get("os_info") or "")[:200],
        "capabilities": payload.get("capabilities") if isinstance(payload.get("capabilities"), dict) else {},
    })
    bind_tunnel_link_node(link["uuid"], role, node_uuid)
    return node, agent_token, get_tunnel_link(link["uuid"]) or link


def authenticate_node(node_uuid: str, bearer_token: str) -> dict[str, Any]:
    if not bearer_token:
        raise TunnelError("Node authentication required.")
    node = get_tunnel_node_by_token_hash(token_hash(bearer_token))
    if not node or node.get("uuid") != node_uuid or not node.get("enabled"):
        raise TunnelError("Node authentication failed.")
    return node


def _node_endpoint(node: dict[str, Any]) -> str:
    return str(node.get("advertise_host") or node.get("observed_ip") or "").strip()


def _link_payload(link: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    role = node["role"]
    if node["uuid"] not in {link.get("iran_node_uuid"), link.get("foreign_node_uuid")}:
        raise TunnelError("Node به این Tunnel تعلق ندارد.")
    peer_uuid = link.get("foreign_node_uuid") if role == "iran" else link.get("iran_node_uuid")
    peer = get_tunnel_node(str(peer_uuid)) if peer_uuid else None
    ready = bool(peer and peer.get("enabled"))
    short = link["uuid"].replace("-", "")[:8]
    iface = f"tlm{short[:7]}"  # <= 10 chars; Linux IFNAMSIZ-safe.
    self_ip = link["iran_overlay_ip"] if role == "iran" else link["foreign_overlay_ip"]
    peer_ip = link["foreign_overlay_ip"] if role == "iran" else link["iran_overlay_ip"]

    result: dict[str, Any] = {
        "uuid": link["uuid"],
        "name": link["name"],
        "role": role,
        "ready": ready,
        "mode": link["mode"],
        "kill_switch": bool(link["kill_switch"]),
        "health_timeout": int(link["health_timeout"]),
        "interface": iface,
        "address": f"{self_ip}/30",
        "self_ip": self_ip,
        "peer_ip": peer_ip,
        "peer_allowed_ips": [f"{peer_ip}/32"],
        "preshared_key": decrypt_secret(link["wg_psk"]),
        "listen_port": int(link["foreign_wg_port"]) if role == "foreign" else 0,
        "frp": {
            "control_port": int(link["iran_frp_control_port"]),
            "proxy_port": int(link["iran_frp_proxy_port"]),
            "token": decrypt_secret(link["frp_token"]),
        },
    }
    if not ready or not peer:
        result["peer"] = None
        return result

    peer_endpoint = _node_endpoint(peer)
    self_endpoint = _node_endpoint(node)
    result["peer"] = {
        "uuid": peer["uuid"],
        "name": peer["name"],
        "public_key": peer["wg_public_key"],
        "endpoint_host": peer_endpoint,
    }
    if role == "iran":
        result["direct_endpoint"] = {
            "host": peer_endpoint,
            "port": int(link["foreign_wg_port"]),
        }
        result["reverse_endpoint"] = {"host": "127.0.0.1", "port": int(link["iran_frp_proxy_port"])}
        result["frp"].update({
            "side": "server",
            "bind_host": "0.0.0.0",
            "proxy_bind_host": "127.0.0.1",
            "allow_source": peer.get("observed_ip") or "",
        })
    else:
        result["direct_endpoint"] = None
        result["reverse_endpoint"] = None
        result["frp"].update({
            "side": "client",
            "server_host": _node_endpoint(peer),
            "server_port": int(link["iran_frp_control_port"]),
            "local_wg_port": int(link["foreign_wg_port"]),
            "remote_udp_port": int(link["iran_frp_proxy_port"]),
        })
        result["firewall"] = {
            "wg_port": int(link["foreign_wg_port"]),
            "allow_source": peer.get("observed_ip") or "",
            "allow_loopback": True,
        }
    result["self_endpoint"] = self_endpoint
    return result


def desired_config(node: dict[str, Any]) -> dict[str, Any]:
    links = links_for_tunnel_node(node["uuid"])
    return {
        "schema": 1,
        "agent_min_version": AGENT_VERSION,
        "poll_interval": 15,
        "node": {"uuid": node["uuid"], "name": node["name"], "role": node["role"]},
        "links": [_link_payload(link, node) for link in links],
    }


def heartbeat(node: dict[str, Any], payload: dict[str, Any], observed_ip: str) -> None:
    state = payload.get("state") if isinstance(payload.get("state"), dict) else {}
    advertise_host = str(payload.get("advertise_host") or "").strip()
    update_tunnel_node_seen(
        node["uuid"],
        observed_ip=observed_ip or node.get("observed_ip", ""),
        advertise_host=_validate_host(advertise_host) if advertise_host else node.get("advertise_host", ""),
        state=state,
        agent_version=str(payload.get("agent_version") or node.get("agent_version") or "")[:32],
        capabilities=payload.get("capabilities") if isinstance(payload.get("capabilities"), dict) else node.get("capabilities", {}),
    )
    link_states = state.get("links") if isinstance(state.get("links"), list) else []
    for item in link_states:
        if not isinstance(item, dict):
            continue
        link_uuid = str(item.get("uuid") or "")
        transport = str(item.get("transport") or "")
        if transport not in {"direct", "reverse", "down", "pending"}:
            continue
        link = get_tunnel_link(link_uuid)
        if link and node["uuid"] == link.get("iran_node_uuid"):
            update_tunnel_link(link_uuid, active_transport=transport)


def node_online(node: dict[str, Any], max_age: int = 50) -> bool:
    value = node.get("last_seen")
    if not value:
        return False
    try:
        seen = datetime.fromisoformat(str(value))
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        return (_now() - seen).total_seconds() <= max_age
    except ValueError:
        return False


def link_view(link: dict[str, Any]) -> dict[str, Any]:
    iran = get_tunnel_node(str(link.get("iran_node_uuid"))) if link.get("iran_node_uuid") else None
    foreign = get_tunnel_node(str(link.get("foreign_node_uuid"))) if link.get("foreign_node_uuid") else None
    return {
        **link,
        "iran_node": iran,
        "foreign_node": foreign,
        "iran_online": bool(iran and node_online(iran)),
        "foreign_online": bool(foreign and node_online(foreign)),
        "ready": bool(iran and foreign),
    }


def dashboard_data() -> dict[str, Any]:
    links = [link_view(item) for item in list_tunnel_links()]
    nodes = list_tunnel_nodes()
    return {
        "links": links,
        "nodes": nodes,
        "online_nodes": sum(1 for node in nodes if node_online(node)),
        "healthy_links": sum(1 for link in links if link["ready"] and link["iran_online"] and link["foreign_online"] and link.get("active_transport") in {"direct", "reverse"}),
    }
