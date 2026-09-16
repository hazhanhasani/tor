from __future__ import annotations

import ipaddress
import json
import shlex
import time
from pathlib import Path
from urllib.parse import urlparse

from flask import Blueprint, flash, jsonify, redirect, render_template, request, send_file, session, url_for

from .db import (
    get_setting,
    get_tunnel_link,
    get_tunnel_node,
    list_locations,
    list_tunnel_links,
    set_setting,
    update_tunnel_link,
)
from .panel_sync import pasarguard_inbounds, sync_all_panels, xui_inbounds
from .routing_state import (
    delete_tunnel_panel_tags,
    explicit_route_conflicts,
    set_tunnel_panel_tags,
    tunnel_panel_tags,
)
from .runtime import apply_runtime
from .security import decrypt_secret, validate_csrf
from .tunnels import (
    AGENT_VERSION,
    TunnelError,
    authenticate_node,
    create_link,
    dashboard_data,
    delete_link,
    desired_config,
    enroll_node,
    heartbeat,
    issue_enrollment,
    link_view,
)

bp = Blueprint("tunnels", __name__)
ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


@bp.before_request
def protect_admin_routes():
    if request.path.startswith("/api/tunnels/"):
        return None
    if not session.get("authenticated"):
        return redirect(url_for("login", next=request.path))
    return None


def _bearer() -> str:
    raw = request.headers.get("Authorization", "").strip()
    if raw.lower().startswith("bearer "):
        return raw[7:].strip()
    return ""


def _controller_url() -> str:
    configured = get_setting("tunnel_public_url", "").strip().rstrip("/")
    if configured:
        return configured
    return request.host_url.rstrip("/")


def _node_command(controller: str, token: str, name: str) -> str:
    allow_http = " --allow-http" if controller.startswith("http://") else ""
    return (
        f"curl -fsSL {shlex.quote(controller + '/api/tunnels/bootstrap.sh')} | sudo bash -s -- "
        f"--panel {shlex.quote(controller)} --token {shlex.quote(token)} "
        f"--name {shlex.quote(name)}{allow_http}"
    )


def _upgrade_command(controller: str) -> str:
    allow_http = " --allow-http" if controller.startswith("http://") else ""
    return (
        f"curl -fsSL {shlex.quote(controller + '/api/tunnels/bootstrap.sh')} | sudo bash -s -- "
        f"--panel {shlex.quote(controller)} --upgrade{allow_http}"
    )


def _mask_host(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return "—"
    try:
        ip = ipaddress.ip_address(value)
        if ip.version == 4:
            parts = value.split(".")
            return f"{parts[0]}.{parts[1]}.***.***"
        return str(ip).split(":", 2)[0] + ":***:***"
    except ValueError:
        if len(value) <= 6:
            return "***"
        return value[:3] + "***" + value[-3:]


def _provider_inbounds() -> tuple[list[dict], list[dict], list[str]]:
    xui_rows: list[dict] = []
    pg_rows: list[dict] = []
    errors: list[str] = []
    try:
        xui_rows = xui_inbounds()
    except Exception as exc:
        errors.append(f"3x-ui: {exc}")
    try:
        pg_rows = pasarguard_inbounds()
    except Exception as exc:
        errors.append(f"PasarGuard: {exc}")
    return xui_rows, pg_rows, errors


def _fabric_setting_key(node_uuid: str) -> str:
    return f"tunnel_port_fabric_inventory:{str(node_uuid)}"


def _saved_inventory(node_uuid: str) -> dict:
    raw = get_setting(_fabric_setting_key(node_uuid), "{}")
    try:
        value = json.loads(raw or "{}")
    except Exception:
        return {}
    if not isinstance(value, dict):
        return {}
    inventory = value.get("inventory")
    return inventory if isinstance(inventory, dict) else {}


def _foreign_inventory(view: dict) -> dict:
    node = view.get("foreign_node") or {}
    uuid = str(node.get("uuid") or "")
    return _saved_inventory(uuid) if uuid else {}


def _detail_context(link_uuid: str, tokens: dict[str, str] | None = None):
    link = get_tunnel_link(link_uuid)
    if not link:
        raise TunnelError("Tunnel پیدا نشد.")
    view = link_view(link)
    controller = _controller_url()
    tokens = tokens or {}
    commands: dict[str, str] = {}
    if tokens.get("iran"):
        commands["iran"] = _node_command(controller, tokens["iran"], f"Iran · {link['name']}")
    if tokens.get("foreign"):
        commands["foreign"] = _node_command(controller, tokens["foreign"], f"Foreign · {link['name']}")
    xui_rows, pg_rows, provider_errors = _provider_inbounds()
    return {
        "link": view,
        "controller_url": controller,
        "commands": commands,
        "masked_iran_host": _mask_host((view.get("iran_node") or {}).get("advertise_host") or (view.get("iran_node") or {}).get("observed_ip") or ""),
        "masked_foreign_host": _mask_host((view.get("foreign_node") or {}).get("advertise_host") or (view.get("foreign_node") or {}).get("observed_ip") or ""),
        "xui_inbounds": xui_rows,
        "pasarguard_inbounds": pg_rows,
        "xui_selected": tunnel_panel_tags(link_uuid, "xui"),
        "pasarguard_selected": tunnel_panel_tags(link_uuid, "pasarguard"),
        "provider_errors": provider_errors,
        "agent_version": AGENT_VERSION,
        "upgrade_command": _upgrade_command(controller),
        "foreign_tor_inventory": _foreign_inventory(view),
    }


def _format_conflicts(conflicts: dict[str, list[str]]) -> str:
    return "؛ ".join(f"{owner}: {', '.join(tags)}" for owner, tags in conflicts.items())


def _flash_sync(results: dict[str, dict]) -> None:
    labels = {"xui": "3x-ui", "pasarguard": "PasarGuard"}
    synced = [labels[k] for k, row in results.items() if row.get("ok") is True]
    if synced:
        flash("Routing Tunnel روی " + ", ".join(synced) + " همگام شد.", "success")
    for key, row in results.items():
        if row.get("ok") is False:
            flash(f"Sync {labels[key]} ناموفق بود: {row.get('error')}", "warning")


def _sanitize_inventory(value: object) -> dict:
    if not isinstance(value, dict):
        return {"installed": False, "locations": [], "ports": [], "location_count": 0, "port_count": 0}
    installed = bool(value.get("installed"))
    version = str(value.get("version") or "")[:32]
    locations: list[dict] = []
    global_ports: set[int] = set()
    raw_locations = value.get("locations") if isinstance(value.get("locations"), list) else []
    for raw in raw_locations[:512]:
        if not isinstance(raw, dict):
            continue
        ports: set[int] = set()
        raw_ports = raw.get("ports") if isinstance(raw.get("ports"), list) else []
        for item in raw_ports:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                ports.add(port)
                global_ports.add(port)
        locations.append({
            "slug": str(raw.get("slug") or "")[:96],
            "name": str(raw.get("name") or "")[:160],
            "country_code": str(raw.get("country_code") or "")[:8].upper(),
            "ports": sorted(ports),
        })
    raw_global_ports = value.get("ports") if isinstance(value.get("ports"), list) else []
    for item in raw_global_ports:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            global_ports.add(port)
    raw_errors = value.get("errors") if isinstance(value.get("errors"), list) else []
    errors = [str(x)[:500] for x in raw_errors[:20]]
    return {
        "installed": installed,
        "version": version,
        "locations": locations,
        "ports": sorted(global_ports),
        "location_count": len(locations),
        "port_count": len(global_ports),
        "errors": errors,
    }


def _port_fabric_config(node: dict) -> dict:
    links: list[dict] = []
    role = str(node.get("role") or "")
    if role == "iran":
        for link in list_tunnel_links():
            if not link.get("enabled") or str(link.get("iran_node_uuid") or "") != str(node.get("uuid") or ""):
                continue
            foreign = get_tunnel_node(str(link.get("foreign_node_uuid") or "")) if link.get("foreign_node_uuid") else None
            if not foreign or not foreign.get("enabled"):
                continue
            inventory = _sanitize_inventory(_saved_inventory(str(foreign.get("uuid") or "")))
            ports = inventory.get("ports") if inventory.get("installed") else []
            short = str(link.get("uuid") or "").replace("-", "")[:8]
            links.append({
                "uuid": str(link.get("uuid") or ""),
                "name": str(link.get("name") or ""),
                "ready": bool(ports and foreign),
                "interface": f"tlm{short[:7]}",
                "iran_ip": str(link.get("iran_overlay_ip") or ""),
                "foreign_ip": str(link.get("foreign_overlay_ip") or ""),
                "ports": ports,
                "locations": inventory.get("locations") or [],
                "foreign_tor_version": inventory.get("version") or "",
                "active_transport": str(link.get("active_transport") or "pending"),
            })
    return {
        "schema": 1,
        "poll_interval": 15,
        "node": {"uuid": node.get("uuid"), "name": node.get("name"), "role": role},
        "links": links,
    }


@bp.get("/tunnels")
def tunnel_index():
    data = dashboard_data()
    return render_template("tunnels.html", **data, controller_url=_controller_url())


@bp.post("/tunnels/controller-url")
def tunnel_controller_url():
    validate_csrf(request.form.get("_csrf"))
    value = request.form.get("controller_url", "").strip().rstrip("/")
    if value:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return render_template("error_inline.html", message="Controller URL معتبر نیست."), 400
    set_setting("tunnel_public_url", value)
    return redirect(url_for("tunnels.tunnel_index"))


@bp.post("/tunnels/new")
def tunnel_new():
    validate_csrf(request.form.get("_csrf"))
    try:
        link = create_link(
            request.form.get("name", ""),
            request.form.get("mode", "auto"),
            request.form.get("kill_switch") == "on",
            int(request.form.get("health_timeout", "45") or 45),
        )
        tokens = {
            "iran": issue_enrollment(link["uuid"], "iran"),
            "foreign": issue_enrollment(link["uuid"], "foreign"),
        }
        return render_template("tunnel_detail.html", **_detail_context(link["uuid"], tokens))
    except (TunnelError, ValueError) as exc:
        data = dashboard_data()
        return render_template("tunnels.html", **data, controller_url=_controller_url(), tunnel_error=str(exc)), 400


@bp.get("/tunnels/<link_uuid>")
def tunnel_detail(link_uuid: str):
    try:
        return render_template("tunnel_detail.html", **_detail_context(link_uuid))
    except TunnelError:
        return ("Not found", 404)


@bp.post("/tunnels/<link_uuid>/enrollment/<role>")
def tunnel_enrollment(link_uuid: str, role: str):
    validate_csrf(request.form.get("_csrf"))
    try:
        token = issue_enrollment(link_uuid, role)
        return render_template("tunnel_detail.html", **_detail_context(link_uuid, {role: token}))
    except TunnelError as exc:
        return render_template("error_inline.html", message=str(exc)), 400


@bp.post("/tunnels/<link_uuid>/mode")
def tunnel_mode(link_uuid: str):
    validate_csrf(request.form.get("_csrf"))
    link = get_tunnel_link(link_uuid)
    if not link:
        return ("Not found", 404)
    mode = request.form.get("mode", "auto").strip().lower()
    if mode not in {"auto", "direct", "reverse"}:
        return render_template("error_inline.html", message="حالت Tunnel معتبر نیست."), 400
    kill_switch = request.form.get("kill_switch") == "on"
    try:
        timeout = int(request.form.get("health_timeout", link.get("health_timeout", 45)))
    except ValueError:
        timeout = 45
    timeout = max(15, min(timeout, 300))
    update_tunnel_link(link_uuid, mode=mode, kill_switch=kill_switch, health_timeout=timeout)
    return redirect(url_for("tunnels.tunnel_detail", link_uuid=link_uuid))


@bp.post("/tunnels/<link_uuid>/routing")
def tunnel_routing(link_uuid: str):
    validate_csrf(request.form.get("_csrf"))
    link = get_tunnel_link(link_uuid)
    if not link:
        return ("Not found", 404)
    xui_tags = [x for x in request.form.getlist("xui_inbound_tags") if x]
    pg_tags = [x for x in request.form.getlist("pasarguard_inbound_tags") if x]
    locations = list_locations()
    links = list_tunnel_links()
    xui_conflicts = explicit_route_conflicts(
        "xui", xui_tags, locations=locations, tunnel_links=links, exclude_link_uuid=link_uuid
    )
    if xui_conflicts:
        return render_template(
            "error_inline.html", message="Inboundهای 3x-ui قبلاً Route شده‌اند: " + _format_conflicts(xui_conflicts)
        ), 400
    pg_conflicts = explicit_route_conflicts(
        "pasarguard", pg_tags, locations=locations, tunnel_links=links, exclude_link_uuid=link_uuid
    )
    if pg_conflicts:
        return render_template(
            "error_inline.html", message="Inboundهای PasarGuard قبلاً Route شده‌اند: " + _format_conflicts(pg_conflicts)
        ), 400
    set_tunnel_panel_tags(link_uuid, "xui", xui_tags)
    set_tunnel_panel_tags(link_uuid, "pasarguard", pg_tags)
    results = sync_all_panels(locations, decrypt_secret)
    _flash_sync(results)
    return redirect(url_for("tunnels.tunnel_detail", link_uuid=link_uuid))


@bp.post("/tunnels/<link_uuid>/delete")
def tunnel_delete(link_uuid: str):
    validate_csrf(request.form.get("_csrf"))
    try:
        delete_tunnel_panel_tags(link_uuid)
        delete_link(link_uuid)
        try:
            apply_runtime()
        except Exception as exc:
            flash(f"Tunnel حذف شد، ولی بازنشانی خودکار مسیر Tor خطا داشت: {exc}", "warning")
        _flash_sync(sync_all_panels(list_locations(), decrypt_secret))
    except TunnelError:
        return ("Not found", 404)
    return redirect(url_for("tunnels.tunnel_index"))


@bp.get("/api/tunnels/bootstrap.sh")
def tunnel_bootstrap_script():
    response = send_file(SCRIPTS / "tlm-node-bootstrap.sh", mimetype="text/x-shellscript", conditional=True)
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@bp.get("/api/tunnels/agent.py")
def tunnel_agent_script():
    response = send_file(SCRIPTS / "tlm-node-agent.py", mimetype="text/x-python", conditional=True)
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@bp.get("/api/tunnels/port-fabric.py")
def tunnel_port_fabric_script():
    response = send_file(SCRIPTS / "tlm-port-fabric.py", mimetype="text/x-python", conditional=True)
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@bp.post("/api/tunnels/enroll")
def tunnel_api_enroll():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid-json"}), 400
    try:
        node, token, link = enroll_node(payload, request.remote_addr or "")
        return jsonify({
            "ok": True,
            "node_uuid": node["uuid"],
            "role": node["role"],
            "link_uuid": link["uuid"],
            "agent_token": token,
        })
    except TunnelError as exc:
        return jsonify({"error": str(exc)}), 401


@bp.get("/api/tunnels/nodes/<node_uuid>/desired")
def tunnel_api_desired(node_uuid: str):
    try:
        node = authenticate_node(node_uuid, _bearer())
        return jsonify(desired_config(node))
    except TunnelError as exc:
        return jsonify({"error": str(exc)}), 401


@bp.post("/api/tunnels/nodes/<node_uuid>/heartbeat")
def tunnel_api_heartbeat(node_uuid: str):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid-json"}), 400
    try:
        node = authenticate_node(node_uuid, _bearer())
        heartbeat(node, payload, request.remote_addr or "")
        tor_sync: dict[str, object] = {"ok": None, "skipped": True}
        if node.get("role") == "iran" and list_locations():
            try:
                apply_runtime()
                tor_sync = {"ok": True}
            except Exception as exc:
                tor_sync = {"ok": False, "error": str(exc)[:500]}
        return jsonify({"ok": True, "tor_sync": tor_sync})
    except TunnelError as exc:
        return jsonify({"error": str(exc)}), 401


@bp.get("/api/tunnels/nodes/<node_uuid>/port-fabric")
def tunnel_api_port_fabric(node_uuid: str):
    try:
        node = authenticate_node(node_uuid, _bearer())
        return jsonify(_port_fabric_config(node))
    except TunnelError as exc:
        return jsonify({"error": str(exc)}), 401


@bp.post("/api/tunnels/nodes/<node_uuid>/port-fabric/inventory")
def tunnel_api_port_fabric_inventory(node_uuid: str):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid-json"}), 400
    try:
        node = authenticate_node(node_uuid, _bearer())
        inventory = _sanitize_inventory(payload.get("inventory"))
        set_setting(
            _fabric_setting_key(node_uuid),
            json.dumps({"inventory": inventory, "updated_at": int(time.time())}, ensure_ascii=False, separators=(",", ":")),
        )
        return jsonify({
            "ok": True,
            "port_count": inventory.get("port_count", 0),
            "location_count": inventory.get("location_count", 0),
        })
    except TunnelError as exc:
        return jsonify({"error": str(exc)}), 401
