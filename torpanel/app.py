from __future__ import annotations

import base64
import re
import secrets
import sqlite3
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from .config import ADMIN_PASSWORD_HASH, ADMIN_USERNAME, FLASK_SECRET_KEY
from .db import create_location, delete_location, get_location, get_setting, init_db, list_locations, next_socks_port, set_setting, update_location
from .runtime import apply_runtime, service_active, test_exit
from .security import csrf_token, decrypt_secret, encrypt_secret, validate_csrf
from .update import cached_update_available, current_version, latest_release, trigger_update, update_log_tail, update_state
from .xui import XUIClient, XUIError, current_settings, sync_locations


def make_app() -> Flask:
    if not FLASK_SECRET_KEY:
        raise RuntimeError("TORPANEL_FLASK_SECRET_KEY is not configured")
    if not ADMIN_PASSWORD_HASH:
        raise RuntimeError("TORPANEL_ADMIN_PASSWORD_HASH is not configured")
    app = Flask(__name__)
    app.secret_key = FLASK_SECRET_KEY
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=1024 * 1024)
    init_db()
    app.jinja_env.globals["csrf_token"] = csrf_token

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("authenticated"):
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)
        return wrapped

    @app.context_processor
    def update_context():
        return {"update_badge": bool(session.get("authenticated") and cached_update_available())}

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
            session.clear(); session["authenticated"] = True; csrf_token()
            return redirect(url_for("index"))
        flash("نام کاربری یا رمز عبور نادرست است.", "danger")
        return redirect(url_for("login"))

    @app.post("/logout")
    @login_required
    def logout():
        validate_csrf(request.form.get("_csrf")); session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def index():
        locations = list_locations()
        for loc in locations:
            loc["active"] = service_active(loc["slug"])
        configured = bool(get_setting("xui_base_url") and get_setting("xui_api_token"))
        return render_template("index.html", locations=locations, configured=configured)

    @app.route("/settings", methods=["GET", "POST"])
    @login_required
    def settings():
        if request.method == "POST":
            validate_csrf(request.form.get("_csrf"))
            base_url = request.form.get("xui_base_url", "").strip()
            token = request.form.get("xui_api_token", "").strip()
            gateway_host = request.form.get("gateway_host", "").strip()
            verify_tls = "1" if request.form.get("xui_verify_tls") == "on" else "0"
            test_url = request.form.get("xui_outbound_test_url", "https://www.google.com/generate_204").strip()
            if base_url and not re.match(r"^https?://", base_url, re.I):
                flash("آدرس 3x-ui باید با http:// یا https:// شروع شود.", "danger")
                return redirect(url_for("settings"))
            set_setting("xui_base_url", base_url.rstrip("/"))
            if token:
                set_setting("xui_api_token", encrypt_secret(token))
            set_setting("gateway_host", gateway_host)
            set_setting("xui_verify_tls", verify_tls)
            set_setting("xui_outbound_test_url", test_url)
            flash("تنظیمات ذخیره شد.", "success")
            return redirect(url_for("settings"))
        return render_template("settings.html", xui_base_url=get_setting("xui_base_url"), gateway_host=get_setting("gateway_host"),
                               xui_verify_tls=get_setting("xui_verify_tls", "1") == "1",
                               xui_outbound_test_url=get_setting("xui_outbound_test_url", "https://www.google.com/generate_204"),
                               has_token=bool(get_setting("xui_api_token")))

    @app.post("/settings/test")
    @login_required
    def settings_test():
        validate_csrf(request.form.get("_csrf"))
        try:
            cfg = current_settings()
            if not cfg.base_url.strip("/") or not cfg.api_token:
                raise XUIError("ابتدا URL و API Token پنل را ذخیره کنید.")
            result = XUIClient(cfg).test_connection()
            flash(f"اتصال موفق بود؛ {result['inbound_count']} ورودی در 3x-ui پیدا شد.", "success")
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
            flash("بروزرسانی در سرویس مستقل شروع شد. این صفحه ممکن است هنگام Restart چند لحظه در دسترس نباشد.", "success")
        except Exception as exc:
            flash(str(exc), "danger")
        return redirect(url_for("updates"))

    def available_inbounds():
        try:
            cfg = current_settings()
            if not cfg.base_url.strip("/") or not cfg.api_token:
                return []
            return XUIClient(cfg).list_inbounds()
        except Exception as exc:
            flash(f"خواندن ورودی‌های 3x-ui ممکن نشد: {exc}", "warning")
            return []

    def validate_location_form(existing_id: int | None = None):
        name = request.form.get("name", "").strip()
        country_code = request.form.get("country_code", "").strip().upper()
        gateway_port_raw = request.form.get("gateway_port", "").strip()
        inbound_tags = [x for x in request.form.getlist("inbound_tags") if x]
        enabled = request.form.get("enabled") == "on"
        if not name:
            raise ValueError("نام لوکیشن الزامی است.")
        if not re.fullmatch(r"[A-Z]{2}", country_code):
            raise ValueError("کد کشور باید دو حرفی باشد؛ مانند DE یا NL.")
        try:
            gateway_port = int(gateway_port_raw)
        except ValueError:
            raise ValueError("پورت Gateway معتبر نیست.")
        if not 1024 <= gateway_port <= 65535:
            raise ValueError("پورت Gateway باید بین 1024 و 65535 باشد.")
        for loc in list_locations():
            if existing_id and loc["id"] == existing_id:
                continue
            if loc["gateway_port"] == gateway_port:
                raise ValueError("این پورت Gateway قبلاً استفاده شده است.")
            overlap = set(loc["inbound_tags"]) & set(inbound_tags)
            if overlap:
                raise ValueError("یک ورودی 3x-ui نمی‌تواند هم‌زمان به دو لوکیشن Tor متصل باشد: " + ", ".join(sorted(overlap)))
        return name, country_code, gateway_port, inbound_tags, enabled

    @app.route("/locations/new", methods=["GET", "POST"])
    @login_required
    def location_new():
        if request.method == "POST":
            validate_csrf(request.form.get("_csrf"))
            try:
                name, cc, gateway_port, inbound_tags, enabled = validate_location_form()
                slug = f"{cc.lower()}-{secrets.token_hex(3)}"
                password = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
                create_location({"slug": slug, "name": name, "country_code": cc, "socks_port": next_socks_port(),
                                 "gateway_port": gateway_port, "ss_method": "2022-blake3-aes-128-gcm",
                                 "ss_password": encrypt_secret(password), "inbound_tags": inbound_tags, "enabled": enabled})
                apply_runtime()
                try:
                    sync_locations(list_locations(enabled_only=True), decrypt_secret)
                    flash("لوکیشن ساخته شد و 3x-ui همگام‌سازی شد.", "success")
                except Exception as exc:
                    flash(f"لوکیشن ساخته شد، ولی Sync با 3x-ui ناموفق بود: {exc}", "warning")
                return redirect(url_for("index"))
            except (ValueError, sqlite3.IntegrityError, RuntimeError) as exc:
                flash(str(exc), "danger")
        return render_template("location_form.html", location=None, inbounds=available_inbounds())

    @app.route("/locations/<int:location_id>/edit", methods=["GET", "POST"])
    @login_required
    def location_edit(location_id: int):
        location = get_location(location_id)
        if not location:
            return ("Not found", 404)
        if request.method == "POST":
            validate_csrf(request.form.get("_csrf"))
            try:
                name, cc, gateway_port, inbound_tags, enabled = validate_location_form(location_id)
                update_location(location_id, {**location, "name": name, "country_code": cc, "gateway_port": gateway_port,
                                              "inbound_tags": inbound_tags, "enabled": enabled})
                apply_runtime()
                try:
                    sync_locations(list_locations(enabled_only=True), decrypt_secret)
                    flash("لوکیشن و تنظیمات 3x-ui به‌روزرسانی شد.", "success")
                except Exception as exc:
                    flash(f"لوکیشن ذخیره شد، ولی Sync ناموفق بود: {exc}", "warning")
                return redirect(url_for("index"))
            except (ValueError, sqlite3.IntegrityError, RuntimeError) as exc:
                flash(str(exc), "danger"); location = get_location(location_id)
        return render_template("location_form.html", location=location, inbounds=available_inbounds())

    @app.post("/locations/<int:location_id>/delete")
    @login_required
    def location_delete(location_id: int):
        validate_csrf(request.form.get("_csrf"))
        location = get_location(location_id)
        if not location:
            return ("Not found", 404)
        delete_location(location_id)
        try:
            apply_runtime(); sync_locations(list_locations(enabled_only=True), decrypt_secret)
            flash("لوکیشن حذف شد و Route آن از 3x-ui پاک شد.", "success")
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
            actual = (result.get("country_code") or "?").upper(); expected = location["country_code"].upper()
            ip = result.get("ip") or "?"; city = result.get("city") or ""
            if actual == expected:
                flash(f"خروجی Tor صحیح است: {actual} — {ip} {city}", "success")
            else:
                flash(f"خروجی فعلی {actual} — {ip} است؛ کشور مورد انتظار {expected} بود.", "warning")
        except Exception as exc:
            flash(str(exc), "danger")
        return redirect(url_for("index"))

    @app.post("/sync")
    @login_required
    def sync():
        validate_csrf(request.form.get("_csrf"))
        try:
            apply_runtime(); sync_locations(list_locations(enabled_only=True), decrypt_secret)
            flash("Tor و 3x-ui با موفقیت همگام‌سازی شدند.", "success")
        except Exception as exc:
            flash(str(exc), "danger")
        return redirect(url_for("index"))

    return app
