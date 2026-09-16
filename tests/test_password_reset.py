import torpanel.password_reset as pr
from werkzeug.security import check_password_hash


def _memory_settings(monkeypatch):
    store = {}
    monkeypatch.setattr(pr, "get_setting", lambda key, default="": store.get(key, default))
    monkeypatch.setattr(pr, "set_setting", lambda key, value: store.__setitem__(key, value))
    monkeypatch.setattr(pr, "FLASK_SECRET_KEY", "test-recovery-secret")
    return store


def test_recovery_code_resets_password_and_is_single_use(monkeypatch):
    store = _memory_settings(monkeypatch)
    code = pr.issue_recovery_code(ttl_seconds=600, now=1000)
    pr.reset_password_with_code(code, "StrongPassword123!", now=1001)
    assert check_password_hash(store[pr.PASSWORD_OVERRIDE_KEY], "StrongPassword123!")
    assert store[pr.RECOVERY_HASH_KEY] == ""


def test_bad_recovery_code_counts_attempts(monkeypatch):
    store = _memory_settings(monkeypatch)
    pr.issue_recovery_code(ttl_seconds=600, now=1000)
    try:
        pr.reset_password_with_code("WRONG-CODE", "StrongPassword123!", now=1001)
    except ValueError as exc:
        assert "4" in str(exc)
    else:
        raise AssertionError("invalid recovery code should fail")
    assert store[pr.RECOVERY_ATTEMPTS_KEY] == "1"


def test_expired_recovery_code_is_cleared(monkeypatch):
    store = _memory_settings(monkeypatch)
    code = pr.issue_recovery_code(ttl_seconds=60, now=1000)
    try:
        pr.reset_password_with_code(code, "StrongPassword123!", now=1061)
    except ValueError as exc:
        assert "منقضی" in str(exc)
    else:
        raise AssertionError("expired recovery code should fail")
    assert store[pr.RECOVERY_HASH_KEY] == ""


def test_password_policy(monkeypatch):
    _memory_settings(monkeypatch)
    try:
        pr.set_admin_password("short")
    except ValueError as exc:
        assert "۱۰" in str(exc)
    else:
        raise AssertionError("short password should fail")
