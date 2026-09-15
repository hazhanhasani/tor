from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from .config import FERNET_KEY


def _fernet() -> Fernet:
    if not FERNET_KEY:
        raise RuntimeError("TORPANEL_FERNET_KEY is not configured")
    return Fernet(FERNET_KEY.encode("ascii"))


def encrypt_secret(value: str) -> str:
    if not value:
        return ""
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise RuntimeError("Stored secret cannot be decrypted") from exc


def csrf_token() -> str:
    import secrets
    from flask import session
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def validate_csrf(value: str | None) -> None:
    import secrets
    from flask import abort, session
    expected = session.get("_csrf", "")
    if not value or not expected or not secrets.compare_digest(value, expected):
        abort(400, "Invalid CSRF token")
