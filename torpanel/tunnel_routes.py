from __future__ import annotations

import ipaddress
import shlex
from pathlib import Path
from urllib.parse import urlparse

from flask import Blueprint, Response, jsonify, redirect, render_template, request, send_file, session, url_for

from .db import get_setting, get_tunnel_link, list_tunnel_nodes, set_setting, update_tunnel_link
from .security import validate_csrf
from .tunnels import (
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
    return {
        "link": view,
        "controller_url": controller,
        "commands": commands,
        "masked_iran_host": _mask_host((view.get("iran_node") or {}).get("advertise_host") or (view.get("iran_node") or {}).get("observed_ip") or ""),
        "masked_foreign_host": _mask_host((view.get("foreign_node") or {}).get("advertise_host") or (view.get("foreign_node") or {}).get("observed_ip") or ""),
    }


@bp.get("/tunnels")
def tunnel_index():
    data = dashboard_data()
    return render_template(
        "tunnels.html",
        **data,
        controller_url=_controller_url(),
    )


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
        return render_template(
            "tunnels.html", **data, controller_url=_controller_url(), tunnel_error=str(exc)
        ), 400


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


@bp.post("/tunnels/<link_uuid>/delete")
def tunnel_delete(link_uuid: str):
    validate_csrf(request.form.get("_csrf"))
    try:
        delete_link(link_uuid)
    except TunnelError:
        return ("Not found", 404)
    return redirect(url_for("tunnels.tunnel_index"))


# Node bootstrap and authenticated agent control plane ------------------------
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
        return jsonify({"ok": True})
    except TunnelError as exc:
        return jsonify({"error": str(exc)}), 401
