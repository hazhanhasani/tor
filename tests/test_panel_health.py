from types import SimpleNamespace

from torpanel import runtime


def test_bulk_health_checks_single_call_for_many_locations(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        assert kwargs["timeout"] == 5
        statuses = ["active" if i % 2 == 0 else "inactive"
                    for i in range(len(args) - 4)]
        return SimpleNamespace(stdout="\n".join(statuses) + "\n", returncode=3)

    monkeypatch.setattr(runtime.subprocess, "run", fake_run)
    names = [f"fi-{i}" for i in range(30)]
    states = runtime.services_active(names)
    assert len(calls) == 1
    assert states["fi-0"] is True
    assert states["fi-1"] is False
    assert states["fi-28"] is True


def test_bulk_health_handles_timeout_without_blocking_dashboard(monkeypatch):
    import subprocess

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired("systemctl", 5)

    monkeypatch.setattr(runtime.subprocess, "run", fake_run)
    assert runtime.services_active(["fi-a", "fi-b"]) == {
        "fi-a": False, "fi-b": False,
    }


def test_bulk_health_rejects_invalid_service_names(monkeypatch):
    import pytest

    with pytest.raises(ValueError, match="Invalid"):
        runtime.services_active(["bad;rm -rf"])
