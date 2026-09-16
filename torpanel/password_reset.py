from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import secrets
import string
import time

from flask import flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .config import ADMIN_PASSWORD_HASH, ADMIN_USERNAME, FLASK_SECRET_KEY
from .db import get_setting, init_db, set_setting
from .security import csrf_token, validate_csrf

PASSWORD_OVERRIDE_KEY = "admin_password_hash_override"
RECOVERY_HASH_KEY = "admin_password_recovery_hash"
RECOVERY_EXPIRES_KEY = "admin_password_recovery_expires"
RECOVERY_ATTEMPTS_KEY = "admin_password_recovery_attempts"
RECOVERY_MAX_ATTEMPTS = 5
RECOVERY_TTL_SECONDS = 600
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _normalize_code(value: str) -> str:
    return "".join(ch for ch in (value or "").upper() if ch in string.ascii_uppercase + string.digits)


def _code_digest(code: str) -> str:
    if not FLASK_SECRET_KEY:
        raise RuntimeError("TORPANEL_FLASK_SECRET_KEY is not configured")
    return hmac.new(
        FLASK_SECRET_KEY.encode("utf-8"),
        _normalize_code(code).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _clear_recovery() -> None:
    set_setting(RECOVERY_HASH_KEY, "")
    set_setting(RECOVERY_EXPIRES_KEY, "0")
    set_setting(RECOVERY_ATTEMPTS_KEY, "0")


def effective_admin_password_hash() -> str:
    try:
        override = get_setting(PASSWORD_OVERRIDE_KEY, "") or ""
    except Exception:
        override = ""
    return override or ADMIN_PASSWORD_HASH


def issue_recovery_code(ttl_seconds: int = RECOVERY_TTL_SECONDS, *, now: int | None = None) -> str:
    if ttl_seconds < 60 or ttl_seconds > 3600:
        raise ValueError("Recovery code TTL must be between 60 and 3600 seconds.")
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(12))
    issued_at = int(time.time() if now is None else now)
    set_setting(RECOVERY_HASH_KEY, _code_digest(raw))
    set_setting(RECOVERY_EXPIRES_KEY, str(issued_at + ttl_seconds))
    set_setting(RECOVERY_ATTEMPTS_KEY, "0")
    return "-".join(raw[i : i + 4] for i in range(0, 12, 4))


def _validate_new_password(password: str) -> None:
    if len(password) < 10:
        raise ValueError("رمز عبور جدید باید حداقل ۱۰ کاراکتر باشد.")
    if len(password) > 256:
        raise ValueError("رمز عبور جدید بیش از حد طولانی است.")


def set_admin_password(password: str) -> None:
    _validate_new_password(password)
    set_setting(PASSWORD_OVERRIDE_KEY, generate_password_hash(password))
    _clear_recovery()


def reset_password_with_code(code: str, password: str, *, now: int | None = None) -> None:
    _validate_new_password(password)
    expected = get_setting(RECOVERY_HASH_KEY, "") or ""
    try:
        expires = int(get_setting(RECOVERY_EXPIRES_KEY, "0") or "0")
    except ValueError:
        expires = 0
    try:
        attempts = int(get_setting(RECOVERY_ATTEMPTS_KEY, "0") or "0")
    except ValueError:
        attempts = 0
    current = int(time.time() if now is None else now)

    if not expected:
        raise ValueError("کد بازیابی فعالی وجود ندارد. ابتدا از SSH کد بازیابی بسازید.")
    if current > expires:
        _clear_recovery()
        raise ValueError("کد بازیابی منقضی شده است. از SSH یک کد جدید بسازید.")
    if attempts >= RECOVERY_MAX_ATTEMPTS:
        _clear_recovery()
        raise ValueError("تعداد تلاش‌های ناموفق بیش از حد مجاز است. کد جدید بسازید.")

    supplied = _code_digest(code)
    if not hmac.compare_digest(expected, supplied):
        attempts += 1
        set_setting(RECOVERY_ATTEMPTS_KEY, str(attempts))
        remaining = RECOVERY_MAX_ATTEMPTS - attempts
        if remaining <= 0:
            _clear_recovery()
            raise ValueError("کد بازیابی نامعتبر بود و غیرفعال شد. کد جدید بسازید.")
        raise ValueError(f"کد بازیابی نامعتبر است. {remaining} تلاش باقی مانده است.")

    set_admin_password(password)


def register_password_recovery(app) -> None:
    @app.before_request
    def password_override_login():
        if request.path != "/login" or request.method != "POST":
            return None
        override = get_setting(PASSWORD_OVERRIDE_KEY, "") or ""
        if not override:
            return None
        validate_csrf(request.form.get("_csrf"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and check_password_hash(override, password):
            session.clear()
            session["authenticated"] = True
            csrf_token()
            return redirect(url_for("dashboard"))
        flash("نام کاربری یا رمز عبور نادرست است.", "danger")
        return redirect(url_for("login"))

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            validate_csrf(request.form.get("_csrf"))
            code = request.form.get("recovery_code", "").strip()
            password = request.form.get("new_password", "")
            confirmation = request.form.get("confirm_password", "")
            if password != confirmation:
                flash("تکرار رمز عبور با رمز جدید یکسان نیست.", "danger")
                return redirect(url_for("forgot_password"))
            try:
                reset_password_with_code(code, password)
                session.clear()
                flash("رمز عبور با موفقیت تغییر کرد. اکنون با رمز جدید وارد شوید.", "success")
                return redirect(url_for("login"))
            except ValueError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("forgot_password"))
        return render_template("forgot_password.html")


def _prompt_password() -> str:
    first = getpass.getpass("New admin password: ")
    second = getpass.getpass("Repeat new admin password: ")
    if first != second:
        raise ValueError("Passwords do not match.")
    return first


def main() -> int:
    parser = argparse.ArgumentParser(description="Tor Location Manager password recovery")
    sub = parser.add_subparsers(dest="command", required=True)
    issue = sub.add_parser("issue", help="Issue a one-time recovery code for the login page")
    issue.add_argument("--ttl", type=int, default=RECOVERY_TTL_SECONDS, help="Code lifetime in seconds (60-3600)")
    sub.add_parser("reset", help="Reset the admin password directly from SSH")
    args = parser.parse_args()

    init_db()
    if args.command == "issue":
        code = issue_recovery_code(args.ttl)
        print("One-time recovery code:")
        print(code)
        print(f"Valid for {args.ttl // 60} minute(s), maximum {RECOVERY_MAX_ATTEMPTS} attempts.")
        print("Open the panel login page and choose: فراموشی / ریست رمز عبور")
        return 0

    if args.command == "reset":
        password = _prompt_password()
        set_admin_password(password)
        print("Admin password updated. No service restart is required when the panel is running.")
        print("If the panel is stopped, restart it with: systemctl restart tor-location-panel.service")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
