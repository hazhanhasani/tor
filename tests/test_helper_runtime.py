import base64
import json
from types import SimpleNamespace

from cryptography.fernet import Fernet

import torpanel.helper as helper
from torpanel.security import encrypt_secret


def _prepare(monkeypatch, tmp_path):
    instance = tmp_path / "instances"
    tor_data = tmp_path / "tor"
    instance.mkdir()
    tor_data.mkdir()
    monkeypatch.setattr(helper, "INSTANCE_DIR", instance)
    monkeypatch.setattr(helper, "TOR_DATA_DIR", tor_data)
    monkeypatch.setattr(helper, "GATEWAY_CONFIG", tmp_path / "gateway.json")
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper, "init_db", lambda: None)
    monkeypatch.setattr(helper, "local_tor_tunnel_source_ip", lambda: "")
    monkeypatch.setattr(helper, "ensure_owner", lambda *args: None)
    monkeypatch.setattr(helper, "ensure_group", lambda *args: None)
    monkeypatch.setattr(helper, "get_setting", lambda key, default="": default)
    commands = []
    def fake_run(*args, **kwargs):
        commands.append(args)
        return SimpleNamespace(returncode=0, stdout="")
    monkeypatch.setattr(helper, "run", fake_run)
    return instance, tor_data, commands


def test_disabling_location_preserves_guard_state(monkeypatch, tmp_path):
    instance, tor_data, commands = _prepare(monkeypatch, tmp_path)
    (instance / "fi-disabled").mkdir()
    state = tor_data / "fi-disabled"
    state.mkdir()
    (state / "state").write_text("guard data must survive", encoding="utf-8")
    monkeypatch.setattr(helper, "list_locations", lambda enabled_only=False: [])
    helper.apply()
    assert (state / "state").read_text() == "guard data must survive"
    assert not (instance / "fi-disabled").exists()
    assert ("systemctl", "daemon-reload") in commands


def test_noop_sync_does_not_enable_or_restart_active_locations(monkeypatch, tmp_path):
    instance, tor_data, commands = _prepare(monkeypatch, tmp_path)
    loc = {
        "slug": "fi-test", "gateway_port": 31001, "socks_port": 19050,
        "country_code": "FI", "ss_method": "vless-reality",
        "ss_password": encrypt_secret(base64.b64encode(b"x" * 32).decode()),
    }
    monkeypatch.setattr(helper, "list_locations", lambda enabled_only=False: [loc])
    monkeypatch.setattr(helper, "service_active", lambda unit: True)
    monkeypatch.setattr(helper, "services_active", lambda units: {unit: True for unit in units})
    torrc_path = instance / "fi-test" / "torrc"
    torrc_path.parent.mkdir()
    torrc_path.write_text(helper.torrc_for(loc), encoding="utf-8")
    encoded = json.dumps(helper.gateway_config([loc]), indent=2, ensure_ascii=False) + "\n"
    helper.GATEWAY_CONFIG.write_text(encoded, encoding="utf-8")
    helper.apply()
    assert not any(args[0:2] == ("systemctl", "restart") for args in commands)
    assert not any(args[0:2] == ("systemctl", "enable") for args in commands)


def test_bulk_systemctl_checks_are_batched(monkeypatch):
    commands = []
    def fake_run(*args, **kwargs):
        commands.append(args)
        assert kwargs["timeout"] == 6
        return SimpleNamespace(
            returncode=3,
            stdout="\n".join(
                "active" if i % 2 == 0 else "inactive"
                for i in range(len(args) - 3)
            ) + "\n",
        )
    monkeypatch.setattr(helper, "run", fake_run)
    units = [f"tor-location@fi-{i}.service" for i in range(130)]
    statuses = helper.services_active(units)
    assert len(commands) == 3
    assert statuses[units[0]] is True
    assert statuses[units[1]] is False
    assert statuses[units[64]] is True


def test_unknown_systemd_response_does_not_restart_every_location(monkeypatch):
    import pytest
    monkeypatch.setattr(
        helper, "run", lambda *args, **kwargs:
        SimpleNamespace(returncode=1, stdout="permission denied"),
    )
    with pytest.raises(RuntimeError, match="incomplete"):
        helper.services_active(["tor-location@fi.service"])
