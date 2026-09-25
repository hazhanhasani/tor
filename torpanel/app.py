from __future__ import annotations

import base64
import json
import re
import secrets
import sqlite3
from functools import wraps

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from .countries import TOR_COUNTRIES, TOR_COUNTRY_BY_CODE
from .config import (
    ADMIN_PASSWORD_HASH,
    ADMIN_USERNAME,
    FLASK_SECRET_KEY,
    PANEL_PUBLIC_HOST,
    PANEL_TLS_ENABLED,
)
from .db import (
    create_location,
    delete_location,
    get_location,
    get_setting,
    init_db,
    list_locations,
    list_tunnel_links,
    next_socks_port,
    set_setting,
    update_location,
)
from .panel_sync import pasarguard_inbounds as load_pasarguard_inbounds
from .panel_tls import (
    CLOUDFLARE_HTTPS_PORTS as PANEL_HTTPS_PORTS,
    DEFAULT_PANEL_HTTPS_PORT,
    PanelTLSError,
    panel_public_url,
    validate_panel_https_port,
    xui_public_host,
)
from .panel_sync import sync_all_panels, xui_inbounds as load_xui_inbounds
from .pasarguard import (
    PasarGuardClient,
    PasarGuardError,
    current_settings as pasarguard_current_settings,
    normalize_api_key as normalize_pasarguard_api_key,
)
from .routing_state import (
    delete_pasarguard_tor_tags,
    explicit_route_conflicts,
    pasarguard_tor_tags,
    set_pasarguard_tor_tags,
)
from .runtime import apply_panel_tls, apply_runtime, journal_tail, services_active, test_exit, unit_state
from .security import csrf_token, decrypt_secret, encrypt_secret, validate_csrf
from .sync_job import launch_sync_job, sync_job_state
from .tunnel_routes import bp as tunnel_bp
from .update import cached_update_available, current_version, latest_release, trigger_update, update_log_tail, update_state
from .xui import XUIClient, XUIError, current_settings as xui_current_settings, normalize_api_token
from .xui_cdn import (
    CDN_MANAGED_REMARK,
    CDN_MANAGED_TAG,
    CDNProfileError,
    managed_cdn_client_uri,
    normalize_cdn_domain,
    normalize_cdn_port,
    normalize_ws_path,
)
from .warp import WARP_DOMAIN_PRESETS, WarpAssistError, normalize_warp_domains


def _format_conflicts(conflicts: dict[str, list[str]]) -> str:
    rows = []
    for owner, tags in conflicts.items():
        rows.append(f"{owner}: {', '.join(tags)}")
    return "؛ ".join(rows)


def make_app() -> Flask:
    if not FLASK_SECRET_KEY:
        raise RuntimeError("TORPANEL_FLASK_SECRET_KEY is not configured")
    if not ADMIN_PASSWORD_HASH:
        raise RuntimeError("TORPANEL_ADMIN_PASSWORD_HASH is not configured")
    app = Flask(__name__)
    app.secret_key = FLASK_SECRET_KEY
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=bool(PANEL_TLS_ENABLED),
        MAX_CONTENT_LENGTH=1024 * 1024,
    )
    init_db()
    app.register_blueprint(tunnel_bp)
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def enforce_https_public_host():
        if not PANEL_TLS_ENABLED or not PANEL_PUBLIC_HOST or request.path == "/healthz":
            return None
        host = request.host.partition(":")[0].strip("[]").lower()
        if host != PANEL_PUBLIC_HOST:
            return ("این پنل فقط از دامنه HTTPS تنظیم‌شده قابل دسترسی است.", 421)
        return None

    @app.after_request
    def panel_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if PANEL_TLS_ENABLED:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("authenticated"):
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)
        return wrapped

    def flash_sync_results(results: dict[str, dict], success_text: str = "Routeها همگام شدند.") -> None:
        names = {"xui": "3x-ui", "pasarguard": "PasarGuard"}
        successful = [names[key] for key, row in results.items() if row.get("ok") is True]
        failed = [(names[key], row.get("error") or "خطای نامشخص") for key, row in results.items() if row.get("ok") is False]
        if successful:
            flash(f"{success_text} پنل‌ها: {', '.join(successful)}.", "success")
        for name, error in failed:
            flash(f"Sync با {name} ناموفق بود: {error}", "warning")

    @app.context_processor
    def update_context():
        authenticated = bool(session.get("authenticated"))
        return {
            "update_badge": bool(authenticated and cached_update_available()),
            "ui_current_version": current_version(),
            "ui_configured": bool(authenticated and get_setting("xui_base_url") and get_setting("xui_api_token")),
            "ui_pasarguard_configured": bool(
                authenticated
                and get_setting("pasarguard_base_url")
                and get_setting("pasarguard_api_key")
                and get_setting("pasarguard_core_id", "0") not in {"", "0"}
            ),
            "ui_transport_mode": get_setting("tor_transport_mode", "direct") if authenticated else "direct",
        }

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": current_version()}

    @app.get("/login")
    def login():
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        validate_csrf(request.form.get("_csrf"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session.clear()
            session["authenticated"] = True
            csrf_token()
            return redirect(url_for("dashboard"))
        flash("نام کاربری یا رمز عبور نادرست است.", "danger")
        return redirect(url_for("login"))

    @app.post("/logout")
    @login_required
    def logout():
        validate_csrf(request.form.get("_csrf"))
        session.clear()
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        locations = list_locations()
        active_states = services_active([str(loc["slug"]) for loc in locations])
        for loc in locations:
            loc["active"] = active_states.get(str(loc["slug"]), False)
        active_count = sum(1 for loc in locations if loc["active"])
        enabled_count = sum(1 for loc in locations if loc["enabled"])
        configured = bool(get_setting("xui_base_url") and get_setting("xui_api_token"))
        pasarguard_configured = bool(
            get_setting("pasarguard_base_url")
            and get_setting("pasarguard_api_key")
            and get_setting("pasarguard_core_id", "0") not in {"", "0"}
        )
        gateway_state = unit_state("tor-location-gateway.service")
        update_info = update_state()
        recent_locations = list(reversed(locations[-4:]))
        return render_template(
            "dashboard.html",
            locations=locations,
            recent_locations=recent_locations,
            active_count=active_count,
            enabled_count=enabled_count,
            configured=configured,
            pasarguard_configured=pasarguard_configured,
            gateway_state=gateway_state,
            update_info=update_info,
            transport_mode=get_setting("tor_transport_mode", "direct") or "direct",
        )

    @app.get("/")
    @login_required
    def index():
        locations = list_locations()
        active_states = services_active([str(loc["slug"]) for loc in locations])
        for loc in locations:
            loc["active"] = active_states.get(str(loc["slug"]), False)
        configured = bool(get_setting("xui_base_url") and get_setting("xui_api_token"))
        xui_cfg = xui_current_settings()
        if xui_cfg.managed_inbound_mode == "cloudflare":
            for loc in locations:
                try:
                    loc["cdn_client_uri"] = managed_cdn_client_uri(loc, xui_cfg, decrypt_secret)
                except Exception:
                    loc["cdn_client_uri"] = ""
        countries = sorted({str(loc["country_code"]).upper() for loc in locations})
        return render_template(
            "index.html",
            locations=locations,
            configured=configured,
            countries=countries,
            xui_managed_inbound_mode=xui_cfg.managed_inbound_mode,
            xui_cdn_domain=xui_cfg.cdn_domain,
            xui_cdn_port=xui_cfg.cdn_port,
            sync_state=sync_job_state(),
        )

    @app.route("/settings", methods=["GET", "POST"])
    @login_required
    def settings():
        if request.method == "POST":
            validate_csrf(request.form.get("_csrf"))
            base_url = request.form.get("xui_base_url", "").strip()
            token = normalize_api_token(request.form.get("xui_api_token", ""))
            gateway_host = request.form.get("gateway_host", "").strip()
            verify_tls = "1" if request.form.get("xui_verify_tls") == "on" else "0"
            test_url = request.form.get("xui_outbound_test_url", "https://www.google.com/generate_204").strip()
            managed_inbound_mode = request.form.get("xui_managed_inbound_mode", "legacy").strip().lower()
            cdn_domain = request.form.get("xui_cdn_domain", "").strip()
            cdn_port_raw = request.form.get("xui_cdn_port", "8443").strip()
            cdn_ws_path = request.form.get("xui_cdn_ws_path", "").strip()
            cdn_reject_unknown_sni = "1" if request.form.get("xui_cdn_reject_unknown_sni") == "on" else "0"
            tor_transport_mode = request.form.get("tor_transport_mode", "direct").strip().lower()
            tor_bridge_lines = request.form.get("tor_bridge_lines", "").strip()
            xui_warp_enabled = "1" if request.form.get("xui_warp_enabled") == "on" else "0"
            xui_warp_mode = request.form.get("xui_warp_mode", "domains").strip().lower()
            xui_warp_custom_domains = request.form.get("xui_warp_custom_domains", "").strip()
            xui_warp_domain_presets = request.form.getlist("xui_warp_domain_presets")
            xui_warp_inbound_tags = [
                str(x).strip() for x in request.form.getlist("xui_warp_inbound_tags") if str(x).strip()
            ]
            if base_url and not re.match(r"^https?://", base_url, re.I):
                flash("آدرس 3x-ui باید با http:// یا https:// شروع شود.", "danger")
                return redirect(url_for("settings"))
            if managed_inbound_mode not in {"legacy", "cloudflare"}:
                flash("پروفایل Inbound مدیریت‌شده معتبر نیست.", "danger")
                return redirect(url_for("settings"))
            if managed_inbound_mode == "cloudflare":
                if not cdn_ws_path:
                    cdn_ws_path = "/edge-" + secrets.token_urlsafe(18).replace("_", "").replace("-", "")
                try:
                    cdn_domain = normalize_cdn_domain(cdn_domain, base_url)
                    cdn_port = normalize_cdn_port(cdn_port_raw)
                    cdn_ws_path = normalize_ws_path(cdn_ws_path)
                except CDNProfileError as exc:
                    flash(str(exc), "danger")
                    return redirect(url_for("settings"))
                reserved_tunnel_ports = {
                    int(link.get(key) or 0)
                    for link in list_tunnel_links()
                    for key in ("foreign_wg_port", "iran_frp_control_port", "iran_frp_proxy_port")
                    if int(link.get(key) or 0) > 0
                }
                if cdn_port in reserved_tunnel_ports:
                    flash("پورت CDN با یکی از پورت‌های زیرساخت Hybrid Tunnel تداخل دارد.", "danger")
                    return redirect(url_for("settings"))
            else:
                try:
                    cdn_port = int(cdn_port_raw or 8443)
                except ValueError:
                    cdn_port = 8443

            if xui_warp_mode not in {"domains", "all"}:
                flash("حالت WARP معتبر نیست.", "danger")
                return redirect(url_for("settings"))
            try:
                warp_domains = normalize_warp_domains([
                    *xui_warp_domain_presets,
                    *xui_warp_custom_domains.splitlines(),
                ])
            except WarpAssistError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("settings"))
            if xui_warp_enabled == "1" and xui_warp_mode == "domains" and not warp_domains:
                flash("برای WARP دامنه‌ای حداقل یک سایت انتخاب یا وارد کنید.", "danger")
                return redirect(url_for("settings"))
            if (
                xui_warp_enabled == "1"
                and not xui_warp_inbound_tags
                and managed_inbound_mode == "cloudflare"
            ):
                xui_warp_inbound_tags = [
                    get_setting("xui_cdn_runtime_tag", CDN_MANAGED_TAG) or CDN_MANAGED_TAG
                ]

            if tor_transport_mode not in {"direct", "obfs4"}:
                flash("حالت اتصال Tor معتبر نیست.", "danger")
                return redirect(url_for("settings"))
            if tor_transport_mode == "obfs4":
                bridge_rows = [x.strip() for x in tor_bridge_lines.splitlines() if x.strip() and not x.strip().startswith("#")]
                if not bridge_rows:
                    flash("برای حالت obfs4 حداقل یک Bridge لازم است.", "danger")
                    return redirect(url_for("settings"))
                for row in bridge_rows:
                    normalized = row[7:].strip() if row.lower().startswith("bridge ") else row
                    if not normalized.lower().startswith("obfs4 "):
                        flash("همه Bridgeها باید از نوع obfs4 باشند.", "danger")
                        return redirect(url_for("settings"))
            set_setting("xui_base_url", base_url.rstrip("/"))
            if token:
                set_setting("xui_api_token", encrypt_secret(token))
            set_setting("gateway_host", gateway_host)
            set_setting("xui_verify_tls", verify_tls)
            set_setting("xui_outbound_test_url", test_url)
            set_setting("xui_managed_inbound_mode", managed_inbound_mode)
            set_setting("xui_cdn_domain", cdn_domain)
            set_setting("xui_cdn_port", str(cdn_port))
            set_setting("xui_cdn_ws_path", cdn_ws_path)
            set_setting("xui_cdn_reject_unknown_sni", cdn_reject_unknown_sni)
            set_setting("tor_transport_mode", tor_transport_mode)
            set_setting("tor_bridge_lines", tor_bridge_lines)
            set_setting("xui_warp_enabled", xui_warp_enabled)
            set_setting("xui_warp_mode", xui_warp_mode)
            set_setting("xui_warp_domains_json", json.dumps(warp_domains, ensure_ascii=False))
            set_setting("xui_warp_inbound_tags", json.dumps(xui_warp_inbound_tags, ensure_ascii=False))
            # v1.10.0 used a separate local warp-cli proxy in the Tor Gateway.
            # Native 3x-ui WARP replaces it; disable the legacy path explicitly.
            set_setting("warp_assist_enabled", "0")
            try:
                apply_runtime()
                flash("تنظیمات 3x-ui و Tor ذخیره و اعمال شد.", "success")
            except Exception as exc:
                flash(f"تنظیمات ذخیره شد، ولی اعمال تنظیمات Tor خطا داشت: {exc}", "warning")
            try:
                flash_sync_results(
                    sync_all_panels(list_locations(), decrypt_secret),
                    "Inbound و Routeهای مدیریت‌شده Reconcile شدند.",
                )
            except Exception as exc:
                flash(f"تنظیمات ذخیره شد، ولی Sync پنل‌ها خطا داشت: {exc}", "warning")
            return redirect(url_for("settings"))

        bridge_lines = get_setting("tor_bridge_lines", "")
        bridge_count = len([x for x in bridge_lines.splitlines() if x.strip() and not x.strip().startswith("#")])
        try:
            xui_warp_domains = json.loads(get_setting("xui_warp_domains_json", '["check-host.net"]') or "[]")
            if not isinstance(xui_warp_domains, list):
                xui_warp_domains = ["check-host.net"]
        except Exception:
            xui_warp_domains = ["check-host.net"]
        try:
            xui_warp_inbound_tags = json.loads(get_setting("xui_warp_inbound_tags", "[]") or "[]")
            if not isinstance(xui_warp_inbound_tags, list):
                xui_warp_inbound_tags = []
        except Exception:
            xui_warp_inbound_tags = []

        xui_warp_available_inbounds: list[dict] = []
        xui_warp_status = {
            "registered": False,
            "outbound": False,
            "error": "",
        }
        if get_setting("xui_base_url") and get_setting("xui_api_token"):
            try:
                warp_client = XUIClient(xui_current_settings())
                xui_warp_available_inbounds = warp_client.list_inbounds()
                cfg_now = warp_client.get_xray_config()
                cfg_outbounds = cfg_now.get("outbounds") if isinstance(cfg_now.get("outbounds"), list) else []
                xui_warp_status["outbound"] = any(
                    isinstance(row, dict)
                    and str(row.get("tag") or "") == "warp"
                    and str(row.get("protocol") or "").lower() == "wireguard"
                    for row in cfg_outbounds
                )
                try:
                    xui_warp_status["registered"] = bool(warp_client.warp_data())
                except Exception:
                    xui_warp_status["registered"] = False
            except Exception as exc:
                xui_warp_status["error"] = str(exc)
        if get_setting("xui_managed_inbound_mode", "legacy") == "cloudflare":
            managed_cdn_row = next(
                (
                    row for row in xui_warp_available_inbounds
                    if str(row.get("tag") or "") == CDN_MANAGED_TAG
                    or str(row.get("remark") or "") == CDN_MANAGED_REMARK
                ),
                None,
            )
            runtime_cdn_tag = (
                str((managed_cdn_row or {}).get("tag") or "")
                or get_setting("xui_cdn_runtime_tag", CDN_MANAGED_TAG)
                or CDN_MANAGED_TAG
            )
            if managed_cdn_row is None:
                xui_warp_available_inbounds.insert(0, {
                    "id": None,
                    "tag": runtime_cdn_tag,
                    "remark": "Cloudflare CDN مدیریت‌شده",
                    "protocol": "vless",
                    "port": int(get_setting("xui_cdn_port", "8443") or 8443),
                })
            if not xui_warp_inbound_tags:
                xui_warp_inbound_tags = [runtime_cdn_tag]
            else:
                previous_runtime_tag = get_setting("xui_cdn_runtime_tag", "") or ""
                replaceable = {CDN_MANAGED_TAG}
                if previous_runtime_tag:
                    replaceable.add(previous_runtime_tag)
                xui_warp_inbound_tags = [
                    runtime_cdn_tag if str(tag) in replaceable else str(tag)
                    for tag in xui_warp_inbound_tags
                ]
        return render_template(
            "settings.html",
            xui_base_url=get_setting("xui_base_url"),
            gateway_host=get_setting("gateway_host"),
            xui_verify_tls=get_setting("xui_verify_tls", "1") == "1",
            xui_outbound_test_url=get_setting("xui_outbound_test_url", "https://www.google.com/generate_204"),
            xui_managed_inbound_mode=get_setting("xui_managed_inbound_mode", "legacy") or "legacy",
            xui_cdn_domain=get_setting("xui_cdn_domain", ""),
            xui_cdn_port=get_setting("xui_cdn_port", "8443") or "8443",
            xui_cdn_ws_path=get_setting("xui_cdn_ws_path", ""),
            xui_cdn_reject_unknown_sni=get_setting("xui_cdn_reject_unknown_sni", "1") == "1",
            has_token=bool(get_setting("xui_api_token")),
            tor_transport_mode=get_setting("tor_transport_mode", "direct") or "direct",
            tor_bridge_lines=bridge_lines,
            bridge_count=bridge_count,
            pasarguard_base_url=get_setting("pasarguard_base_url"),
            pasarguard_core_id=get_setting("pasarguard_core_id", ""),
            pasarguard_gateway_host=get_setting("pasarguard_gateway_host") or get_setting("gateway_host"),
            pasarguard_verify_tls=get_setting("pasarguard_verify_tls", "1") == "1",
            pasarguard_restart_nodes=get_setting("pasarguard_restart_nodes", "1") == "1",
            pasarguard_has_key=bool(get_setting("pasarguard_api_key")),
            panel_tls_enabled=get_setting("panel_tls_enabled", "0") == "1",
            panel_tls_port=get_setting("panel_tls_port", str(DEFAULT_PANEL_HTTPS_PORT)) or str(DEFAULT_PANEL_HTTPS_PORT),
            panel_tls_public_host=get_setting("panel_tls_public_host", ""),
            panel_tls_public_url=panel_public_url(),
            panel_https_ports=PANEL_HTTPS_PORTS,
            panel_tls_cloudflare_fallback=get_setting("panel_tls_cloudflare_fallback", "1") == "1",
            panel_tls_cloudflare_origin_ca=get_setting("panel_tls_cloudflare_origin_ca", "0") == "1",
            panel_tls_cloudflare_origin_expires=get_setting("panel_tls_cloudflare_origin_expires", ""),
            panel_tls_cloudflare_origin_id=get_setting("panel_tls_cloudflare_origin_id", ""),
            panel_tls_last_source=get_setting("panel_tls_last_source", ""),
            panel_tls_last_error=get_setting("panel_tls_last_error", ""),
            xui_warp_enabled=get_setting("xui_warp_enabled", "0") == "1",
            xui_warp_mode=get_setting("xui_warp_mode", "domains") or "domains",
            xui_warp_domains=xui_warp_domains,
            xui_warp_inbound_tags=xui_warp_inbound_tags,
            xui_warp_domain_presets=WARP_DOMAIN_PRESETS,
            xui_warp_available_inbounds=xui_warp_available_inbounds,
            xui_warp_status=xui_warp_status,
        )

    @app.post("/settings/panel-tls")
    @login_required
    def settings_panel_tls():
        validate_csrf(request.form.get("_csrf"))
        enabled = request.form.get("panel_tls_enabled") == "on"
        keys = (
            "panel_tls_enabled",
            "panel_tls_public_host",
            "panel_tls_port",
            "panel_tls_source_cert",
            "panel_tls_source_key",
            "panel_tls_cloudflare_fallback",
            "panel_tls_cloudflare_origin_ca",
            "panel_tls_cloudflare_api_token",
        )
        previous = {key: get_setting(key, "") for key in keys}
        try:
            if not enabled:
                set_setting("panel_tls_enabled", "0")
                output = apply_panel_tls()
                flash(
                    "HTTPS اختصاصی پنل غیرفعال شد؛ سرویس تا چند ثانیه دیگر به HTTP اضطراری روی پورت 8787 برمی‌گردد.",
                    "warning",
                )
                if output:
                    flash(output, "success")
                return redirect(url_for("settings"))

            cfg = xui_current_settings()
            if not cfg.base_url.strip("/") or not cfg.api_token:
                raise PanelTLSError("ابتدا اتصال 3x-ui و API Token را ذخیره کنید.")
            host = xui_public_host(cfg.base_url)
            port = validate_panel_https_port(
                request.form.get("panel_tls_port", str(DEFAULT_PANEL_HTTPS_PORT)),
                xui_base_url=cfg.base_url,
            )
            xui_client = XUIClient(cfg)
            inbound_conflicts = [
                row for row in xui_client.list_inbounds()
                if int(row.get("port") or 0) == int(port)
            ]
            if inbound_conflicts:
                names = ", ".join(
                    str(row.get("remark") or row.get("tag") or row.get("id") or "Inbound")
                    for row in inbound_conflicts[:5]
                )
                raise PanelTLSError(
                    f"پورت HTTPS پنل {port} در 3x-ui توسط Inbound دیگری استفاده می‌شود ({names}). "
                    "یک پورت HTTPS آزاد دیگر انتخاب کنید."
                )
            fallback_requested = request.form.get("panel_tls_cloudflare_fallback") == "on"
            try:
                certs = xui_client.get_web_cert_files()
            except Exception:
                if not fallback_requested:
                    raise
                certs = {"webCertFile": "", "webKeyFile": ""}
            set_setting("panel_tls_enabled", "1")
            set_setting("panel_tls_public_host", host)
            set_setting("panel_tls_port", str(port))
            set_setting("panel_tls_source_cert", certs["webCertFile"])
            set_setting("panel_tls_source_key", certs["webKeyFile"])
            origin_ca_requested = request.form.get("panel_tls_cloudflare_origin_ca") == "on"
            origin_ca_token = request.form.get("panel_tls_cloudflare_api_token", "").strip()
            set_setting(
                "panel_tls_cloudflare_fallback",
                "1" if fallback_requested else "0",
            )
            set_setting(
                "panel_tls_cloudflare_origin_ca",
                "1" if origin_ca_requested else "0",
            )
            if origin_ca_token:
                set_setting("panel_tls_cloudflare_api_token", encrypt_secret(origin_ca_token))
            output = apply_panel_tls()
            suffix = "" if port == 443 else f":{port}"
            url = f"https://{host}{suffix}"
            fallback_used = "cloudflare-full-selfsigned" in (output or "")
            origin_ca_used = "cloudflare-origin-ca" in (output or "")
            if origin_ca_used:
                flash(
                    f"HTTPS پنل روی {url} با Cloudflare Origin CA فعال شد و با Full (strict) سازگار است.",
                    "success",
                )
            elif fallback_used:
                flash(
                    f"HTTPS پنل روی {url} فعال شد. چون Private Key گواهی 3x-ui روی Host قابل دسترس نبود، "
                    "Origin TLS محلی ساخته شد. برای این دامنه در Cloudflare حالت SSL/TLS را روی Full بگذارید، نه Full (strict).",
                    "warning",
                )
            else:
                flash(
                    f"SSL محلی 3x-ui برای پنل فعال شد. بعد از Restart از {url} وارد شوید؛ دسترسی معمول با IP پذیرفته نمی‌شود.",
                    "success",
                )
            if output:
                flash(output, "warning" if fallback_used else "success")
        except Exception as exc:
            for key, value in previous.items():
                set_setting(key, value)
            try:
                apply_panel_tls()
            except Exception:
                pass
            flash(f"فعال‌سازی HTTPS پنل انجام نشد: {exc}", "danger")
        return redirect(url_for("settings"))

    @app.post("/settings/warp-test")
    @login_required
    def settings_warp_test():
        validate_csrf(request.form.get("_csrf"))
        try:
            cfg = xui_current_settings()
            client = XUIClient(cfg)
            config = client.get_xray_config()
            config, repaired = client.ensure_warp_outbound(config)
            if repaired:
                client.update_xray_config(config)
            outbounds = config.get("outbounds") if isinstance(config.get("outbounds"), list) else []
            warp = next(
                (row for row in outbounds if isinstance(row, dict) and str(row.get("tag") or "") == "warp"),
                None,
            )
            if not warp:
                raise XUIError("Outbound با tag=warp در 3x-ui قابل ایجاد یا بازیابی نبود.")
            result = client.test_outbound(warp, outbounds)
            details = []
            for key in ("ipv4", "ipv6", "country", "warp"):
                if result.get(key):
                    details.append(f"{key}={result[key]}")
            warp_state = str(result.get("warp") or "").lower()
            if warp_state in {"on", "plus"}:
                flash("WARP خود 3x-ui سالم است" + (f"؛ {' · '.join(details)}" if details else ""), "success")
            else:
                flash(
                    "Outbound WARP در 3x-ui وجود دارد، اما تست Cloudflare آن را فعال تشخیص نداد"
                    + (f"؛ {' · '.join(details)}" if details else ""),
                    "warning",
                )
        except Exception as exc:
            flash(f"تست WARP در 3x-ui ناموفق بود: {exc}", "danger")
        return redirect(url_for("settings"))

    @app.post("/settings/test")
    @login_required
    def settings_test():
        validate_csrf(request.form.get("_csrf"))
        try:
            cfg = xui_current_settings()
            if not cfg.base_url.strip("/") or not cfg.api_token:
                raise XUIError("ابتدا URL و API Token پنل را ذخیره کنید.")
            client = XUIClient(cfg)
            result = client.test_connection()
            suffix = ""
            if cfg.managed_inbound_mode == "cloudflare":
                certs = client.get_web_cert_files()
                suffix = f" Certificate پنل شناسایی شد: {certs['webCertFile']}."
            version_bits = []
            if result.get("panel_version"):
                version_bits.append(f"3x-ui v{result['panel_version']}")
            if result.get("xray_version"):
                version_bits.append(f"Xray {result['xray_version']}")
            versions = f"؛ {' · '.join(version_bits)}" if version_bits else ""
            flash(f"اتصال موفق بود؛ {result['inbound_count']} ورودی در 3x-ui پیدا شد{versions}.{suffix}", "success")
        except Exception as exc:
            flash(str(exc), "danger")
        return redirect(url_for("settings"))

    @app.post("/settings/pasarguard")
    @login_required
    def settings_pasarguard():
        validate_csrf(request.form.get("_csrf"))
        base_url = request.form.get("pasarguard_base_url", "").strip().rstrip("/")
        api_key = normalize_pasarguard_api_key(request.form.get("pasarguard_api_key", ""))
        core_raw = request.form.get("pasarguard_core_id", "").strip()
        gateway_host = request.form.get("pasarguard_gateway_host", "").strip()
        if base_url and not re.match(r"^https?://", base_url, re.I):
            flash("آدرس PasarGuard باید با http:// یا https:// شروع شود.", "danger")
            return redirect(url_for("settings"))
        try:
            core_id = int(core_raw or 0)
        except ValueError:
            flash("Core ID پاسارگارد معتبر نیست.", "danger")
            return redirect(url_for("settings"))
        if core_id < 0:
            flash("Core ID پاسارگارد معتبر نیست.", "danger")
            return redirect(url_for("settings"))
        set_setting("pasarguard_base_url", base_url)
        if api_key:
            set_setting("pasarguard_api_key", encrypt_secret(api_key))
        set_setting("pasarguard_core_id", str(core_id) if core_id else "")
        set_setting("pasarguard_gateway_host", gateway_host)
        set_setting("pasarguard_verify_tls", "1" if request.form.get("pasarguard_verify_tls") == "on" else "0")
        set_setting("pasarguard_restart_nodes", "1" if request.form.get("pasarguard_restart_nodes") == "on" else "0")
        flash("تنظیمات PasarGuard ذخیره شد.", "success")
        return redirect(url_for("settings"))

    @app.post("/settings/pasarguard/test")
    @login_required
    def settings_pasarguard_test():
        validate_csrf(request.form.get("_csrf"))
        try:
            cfg = pasarguard_current_settings()
            if not cfg.base_url.strip("/") or not cfg.api_key:
                raise PasarGuardError("ابتدا URL و API Key پاسارگارد را ذخیره کنید.")
            result = PasarGuardClient(cfg).test_connection()
            selected = result.get("selected_core") or {}
            suffix = f" Core انتخابی: {selected.get('name') or selected.get('id')}." if selected else ""
            flash(f"اتصال PasarGuard موفق بود؛ {result['core_count']} Core پیدا شد.{suffix}", "success")
        except Exception as exc:
            flash(str(exc), "danger")
        return redirect(url_for("settings"))

    @app.get("/updates")
    @login_required
    def updates():
        release = None
        try:
            release = latest_release(force=False)
        except Exception as exc:
            flash(f"بررسی Release ممکن نشد: {exc}", "warning")
        return render_template(
            "updates.html",
            current_version=current_version(),
            release=release,
            state=update_state(),
            log_tail=update_log_tail(),
        )

    @app.post("/updates/check")
    @login_required
    def updates_check():
        validate_csrf(request.form.get("_csrf"))
        try:
            info = latest_release(force=True)
            if info["update_available"]:
                if info["package_ready"]:
                    flash(f"نسخه جدید {info['tag']} آماده نصب است.", "success")
                else:
                    flash(f"نسخه {info['tag']} منتشر شده ولی Assets بروزرسانی کامل نیست.", "warning")
            else:
                flash("همین حالا آخرین نسخه نصب است.", "success")
        except Exception as exc:
            flash(str(exc), "danger")
        return redirect(url_for("updates"))

    @app.post("/updates/install")
    @login_required
    def updates_install():
        validate_csrf(request.form.get("_csrf"))
        tag = request.form.get("tag", "").strip()
        try:
            state = update_state()
            if state.get("status") == "running":
                raise RuntimeError("یک بروزرسانی دیگر در حال اجرا است.")
            trigger_update(tag)
            flash("بروزرسانی در سرویس مستقل شروع شد. پنل هنگام Restart ممکن است چند لحظه در دسترس نباشد.", "success")
        except Exception as exc:
            flash(str(exc), "danger")
        return redirect(url_for("updates"))

    @app.get("/logs")
    @login_required
    def logs():
        locations = list_locations()
        sources = [
            {"key": "panel", "label": "Web Panel", "unit": "tor-location-panel.service"},
            {"key": "gateway", "label": "Xray Gateway", "unit": "tor-location-gateway.service"},
            {"key": "update", "label": "Updater", "unit": "tor-location-manager-update.service"},
        ]
        for loc in locations:
            sources.append({"key": f"tor:{loc['slug']}", "label": f"Tor {loc['country_code']} · {loc['name']}", "unit": f"tor-location@{loc['slug']}.service"})
        source_map = {item["key"]: item for item in sources}
        selected = request.args.get("source", "panel")
        if selected not in source_map:
            selected = "panel"
        selected_source = source_map[selected]
        if selected == "update":
            log_text = update_log_tail(180) or "هنوز لاگ بروزرسانی ثبت نشده است."
        else:
            log_text = journal_tail(selected_source["unit"], 160)
        health = []
        for item in sources:
            state = unit_state(item["unit"])
            health.append({**item, **state})
        return render_template("logs.html", sources=sources, selected=selected, selected_source=selected_source, log_text=log_text, health=health)

    def available_xui_inbounds():
        try:
            return load_xui_inbounds()
        except Exception as exc:
            flash(f"خواندن ورودی‌های 3x-ui ممکن نشد: {exc}", "warning")
            return []

    def available_pasarguard_inbounds():
        try:
            return load_pasarguard_inbounds()
        except Exception as exc:
            flash(f"خواندن Inboundهای PasarGuard ممکن نشد: {exc}", "warning")
            return []

    def next_gateway_port(exclude_location_id: int | None = None) -> int:
        used: set[int] = {8787}
        for loc in list_locations():
            if exclude_location_id and int(loc["id"]) == int(exclude_location_id):
                continue
            for key in ("gateway_port", "socks_port", "xui_inbound_port"):
                value = int(loc.get(key) or 0)
                if value:
                    used.add(value)
        for link in list_tunnel_links():
            for key in ("foreign_wg_port", "iran_frp_control_port", "iran_frp_proxy_port"):
                value = int(link.get(key) or 0)
                if value:
                    used.add(value)
        for key in ("xui_cdn_port", "panel_tls_port"):
            try:
                value = int(get_setting(key, "0") or 0)
            except ValueError:
                value = 0
            if value:
                used.add(value)
        for port in range(31000, 40000):
            if port not in used:
                return port
        for port in range(40001, 60000):
            if port not in used:
                return port
        raise ValueError("پورت آزاد برای Tor Gateway پیدا نشد.")

    def validate_location_form(existing_id: int | None = None):
        name = request.form.get("name", "").strip()
        country_code = request.form.get("country_code", "").strip().upper()
        gateway_port_raw = request.form.get("gateway_port", "").strip()
        xui_inbound_port_raw = request.form.get("xui_inbound_port", "").strip()
        inbound_tags = [x for x in request.form.getlist("inbound_tags") if x]
        pg_inbound_tags = [x for x in request.form.getlist("pasarguard_inbound_tags") if x]
        enabled = request.form.get("enabled") == "on"
        country = TOR_COUNTRY_BY_CODE.get(country_code)
        if country is None:
            raise ValueError("کشور خروجی Tor معتبر نیست؛ یک کشور را از فهرست انتخاب کنید.")
        if not name:
            name = country["name"]
        cloudflare_mode = get_setting("xui_managed_inbound_mode", "legacy") == "cloudflare"
        existing = get_location(existing_id) if existing_id else None
        if cloudflare_mode:
            if existing and int(existing.get("gateway_port") or 0):
                gateway_port = int(existing["gateway_port"])
            else:
                gateway_port = next_gateway_port(existing_id)
        elif gateway_port_raw:
            try:
                gateway_port = int(gateway_port_raw)
            except ValueError:
                raise ValueError("پورت Gateway معتبر نیست.")
            if not 1024 <= gateway_port <= 65535:
                raise ValueError("پورت Gateway باید بین 1024 و 65535 باشد.")
        else:
            gateway_port = next_gateway_port(existing_id)

        if cloudflare_mode:
            # Cloudflare mode uses one shared TLS/WebSocket inbound for every
            # location, so per-location public inbound ports are intentionally disabled.
            xui_inbound_port = 0
        elif xui_inbound_port_raw:
            try:
                xui_inbound_port = int(xui_inbound_port_raw)
            except ValueError:
                raise ValueError("پورت Inbound در 3x-ui معتبر نیست.")
            if not 1024 <= xui_inbound_port <= 65535:
                raise ValueError("پورت Inbound در 3x-ui باید بین 1024 و 65535 باشد.")
            if xui_inbound_port == gateway_port:
                raise ValueError("پورت Inbound 3x-ui و پورت Tor Gateway باید متفاوت باشند.")
        else:
            xui_inbound_port = 0

        locations = list_locations()
        existing_slug = str(existing.get("slug")) if existing else None
        for loc in locations:
            if existing_id and loc["id"] == existing_id:
                continue
            if loc["gateway_port"] == gateway_port:
                raise ValueError("این پورت Gateway قبلاً استفاده شده است.")
            if xui_inbound_port and int(loc.get("xui_inbound_port") or 0) == xui_inbound_port:
                raise ValueError("این پورت Inbound قبلاً برای لوکیشن دیگری استفاده شده است.")
        links = list_tunnel_links()
        xui_conflicts = explicit_route_conflicts(
            "xui", inbound_tags, locations=locations, tunnel_links=links, exclude_location_slug=existing_slug
        )
        if xui_conflicts:
            raise ValueError("Inbound 3x-ui قبلاً Route شده است: " + _format_conflicts(xui_conflicts))
        pg_conflicts = explicit_route_conflicts(
            "pasarguard", pg_inbound_tags, locations=locations, tunnel_links=links, exclude_location_slug=existing_slug
        )
        if pg_conflicts:
            raise ValueError("Inbound پاسارگارد قبلاً Route شده است: " + _format_conflicts(pg_conflicts))
        return name, country_code, gateway_port, xui_inbound_port, inbound_tags, pg_inbound_tags, enabled

    @app.route("/locations/new", methods=["GET", "POST"])
    @login_required
    def location_new():
        if request.method == "POST":
            validate_csrf(request.form.get("_csrf"))
            try:
                name, cc, gateway_port, xui_inbound_port, inbound_tags, pg_tags, enabled = validate_location_form()
                slug = f"{cc.lower()}-{secrets.token_hex(3)}"
                transport_seed = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
                create_location({
                    "slug": slug, "name": name, "country_code": cc, "socks_port": next_socks_port(),
                    "gateway_port": gateway_port, "xui_inbound_port": xui_inbound_port,
                    # ss_* are legacy database column names kept for in-place upgrades.
                    # The encrypted seed now derives VLESS/REALITY credentials.
                    "ss_method": "vless-reality", "ss_password": encrypt_secret(transport_seed),
                    "inbound_tags": inbound_tags, "enabled": enabled,
                })
                set_pasarguard_tor_tags(slug, pg_tags)
            except (ValueError, sqlite3.IntegrityError) as exc:
                flash(str(exc), "danger")
            else:
                # The Location is already committed at this point. A runtime/API
                # failure must not make the create form look as if nothing was
                # saved; that caused retries to hit "port already used".
                try:
                    apply_runtime()
                    results = sync_all_panels(list_locations(), decrypt_secret)
                    flash_sync_results(results, "لوکیشن ساخته شد و Routeها Reconcile شدند.")
                except Exception as exc:
                    flash(
                        f"لوکیشن ساخته و ذخیره شد، اما Reconcile کامل نشد: {exc}. "
                        "از صفحه لوکیشن‌ها می‌توانی دوباره Sync را اجرا کنی.",
                        "warning",
                    )
                return redirect(url_for("index"))
        return render_template(
            "location_form.html",
            location=None,
            inbounds=available_xui_inbounds(),
            pasarguard_inbounds=available_pasarguard_inbounds(),
            pasarguard_tags=[],
            xui_managed_inbound_mode=get_setting("xui_managed_inbound_mode", "legacy") or "legacy",
            xui_cdn_domain=get_setting("xui_cdn_domain", ""),
            xui_cdn_port=get_setting("xui_cdn_port", "8443") or "8443",
            tor_countries=TOR_COUNTRIES,
        )

    @app.route("/locations/<int:location_id>/edit", methods=["GET", "POST"])
    @login_required
    def location_edit(location_id: int):
        location = get_location(location_id)
        if not location:
            return ("Not found", 404)
        if request.method == "POST":
            validate_csrf(request.form.get("_csrf"))
            try:
                name, cc, gateway_port, xui_inbound_port, inbound_tags, pg_tags, enabled = validate_location_form(location_id)
                update_location(location_id, {
                    **location, "name": name, "country_code": cc, "gateway_port": gateway_port,
                    "xui_inbound_port": xui_inbound_port, "inbound_tags": inbound_tags, "enabled": enabled,
                })
                set_pasarguard_tor_tags(str(location["slug"]), pg_tags)
                apply_runtime()
                results = sync_all_panels(list_locations(), decrypt_secret)
                flash_sync_results(results, "لوکیشن به‌روزرسانی شد و Routeها Reconcile شدند.")
                return redirect(url_for("index"))
            except (ValueError, sqlite3.IntegrityError, RuntimeError) as exc:
                flash(str(exc), "danger")
                location = get_location(location_id)
        return render_template(
            "location_form.html",
            location=location,
            inbounds=available_xui_inbounds(),
            pasarguard_inbounds=available_pasarguard_inbounds(),
            pasarguard_tags=pasarguard_tor_tags(str(location["slug"])),
            xui_managed_inbound_mode=get_setting("xui_managed_inbound_mode", "legacy") or "legacy",
            xui_cdn_domain=get_setting("xui_cdn_domain", ""),
            xui_cdn_port=get_setting("xui_cdn_port", "8443") or "8443",
            tor_countries=TOR_COUNTRIES,
        )

    @app.post("/locations/<int:location_id>/delete")
    @login_required
    def location_delete(location_id: int):
        validate_csrf(request.form.get("_csrf"))
        location = get_location(location_id)
        if not location:
            return ("Not found", 404)
        delete_pasarguard_tor_tags(str(location["slug"]))
        delete_location(location_id)
        try:
            apply_runtime()
            results = sync_all_panels(list_locations(), decrypt_secret)
            flash_sync_results(results, "لوکیشن حذف شد و Routeهای مدیریت‌شده پاک شدند.")
        except Exception as exc:
            flash(f"لوکیشن حذف شد، ولی اعمال نهایی خطا داشت: {exc}", "warning")
        return redirect(url_for("index"))

    @app.post("/locations/<int:location_id>/test")
    @login_required
    def location_test(location_id: int):
        validate_csrf(request.form.get("_csrf"))
        location = get_location(location_id)
        if not location:
            return ("Not found", 404)
        try:
            result = test_exit(location)
            actual = (result.get("country_code") or "?").upper()
            expected = location["country_code"].upper()
            ip = result.get("ip") or "?"
            city = result.get("city") or ""
            if actual == expected:
                flash(f"خروجی Tor صحیح است: {actual} — {ip} {city}", "success")
            else:
                flash(f"خروجی فعلی {actual} — {ip} است؛ کشور مورد انتظار {expected} بود.", "warning")
        except Exception as exc:
            flash(str(exc), "danger")
        return redirect(url_for("index"))

    @app.get("/sync/status")
    @login_required
    def sync_status():
        return jsonify(sync_job_state())

    @app.post("/sync")
    @login_required
    def sync():
        validate_csrf(request.form.get("_csrf"))
        try:
            if launch_sync_job():
                flash(
                    "بازسازی و Sync در پس‌زمینه شروع شد؛ وضعیت عملیات در همین صفحه نمایش داده می‌شود.",
                    "success",
                )
            else:
                flash("یک عملیات Sync در حال اجراست؛ عملیات تکراری شروع نشد.", "warning")
        except Exception as exc:
            flash(f"شروع Sync ناموفق بود: {exc}", "danger")
        return redirect(url_for("index"))

    return app
