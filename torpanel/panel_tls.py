from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from .db import get_setting, list_locations, list_tunnel_links

CLOUDFLARE_HTTPS_PORTS = (443, 2053, 2083, 2087, 2096, 8443)
DEFAULT_PANEL_HTTPS_PORT = 2096


class PanelTLSError(RuntimeError):
    pass


def xui_public_host(base_url: str) -> str:
    parsed = urlparse((base_url or "").strip())
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise PanelTLSError("برای استفاده از SSL پنل، آدرس 3x-ui باید HTTPS و دارای دامنه معتبر باشد.")
    host = parsed.hostname.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise PanelTLSError("آدرس 3x-ui باید با دامنه باز شود؛ IP مستقیم برای SSL پنل قابل قبول نیست.")


def xui_public_port(base_url: str) -> int:
    parsed = urlparse((base_url or "").strip())
    if parsed.port:
        return int(parsed.port)
    return 443 if parsed.scheme.lower() == "https" else 80


def validate_panel_https_port(port: int, *, xui_base_url: str = "") -> int:
    try:
        port = int(port)
    except (TypeError, ValueError) as exc:
        raise PanelTLSError("پورت HTTPS پنل معتبر نیست.") from exc
    if port not in CLOUDFLARE_HTTPS_PORTS:
        allowed = ", ".join(str(x) for x in CLOUDFLARE_HTTPS_PORTS)
        raise PanelTLSError(f"پورت HTTPS پنل باید یکی از پورت‌های سازگار با Cloudflare باشد: {allowed}")

    reserved: dict[int, str] = {}
    if xui_base_url:
        try:
            reserved[xui_public_port(xui_base_url)] = "خود پنل 3x-ui"
        except ValueError:
            pass

    cdn_port_raw = get_setting("xui_cdn_port", "")
    if get_setting("xui_managed_inbound_mode", "legacy") == "cloudflare" and cdn_port_raw:
        try:
            reserved[int(cdn_port_raw)] = "Inbound مشترک Cloudflare"
        except ValueError:
            pass

    for loc in list_locations():
        for key, label in (
            ("gateway_port", f"Gateway لوکیشن {loc.get('name') or loc.get('slug')}"),
            ("xui_inbound_port", f"Inbound لوکیشن {loc.get('name') or loc.get('slug')}"),
        ):
            try:
                value = int(loc.get(key) or 0)
            except (TypeError, ValueError):
                continue
            if value:
                reserved[value] = label

    for link in list_tunnel_links():
        for key, label in (
            ("foreign_wg_port", "WireGuard Tunnel"),
            ("iran_frp_control_port", "FRP control"),
            ("iran_frp_proxy_port", "FRP reverse proxy"),
        ):
            try:
                value = int(link.get(key) or 0)
            except (TypeError, ValueError):
                continue
            if value:
                reserved[value] = label

    if port in reserved:
        raise PanelTLSError(f"پورت {port} با {reserved[port]} تداخل دارد.")
    return port


def panel_public_url() -> str:
    if get_setting("panel_tls_enabled", "0") != "1":
        return ""
    host = get_setting("panel_tls_public_host", "").strip()
    try:
        port = int(get_setting("panel_tls_port", str(DEFAULT_PANEL_HTTPS_PORT)) or DEFAULT_PANEL_HTTPS_PORT)
    except ValueError:
        port = DEFAULT_PANEL_HTTPS_PORT
    if not host:
        return ""
    suffix = "" if port == 443 else f":{port}"
    return f"https://{host}{suffix}"
