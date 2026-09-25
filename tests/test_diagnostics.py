import os

import pytest
import requests

from torpanel import diagnostics as diag


class Response:
    def __init__(self, chunks=None, payload=None):
        self.chunks = chunks or []
        self.payload = payload or {}
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def raise_for_status(self):
        return None
    def json(self):
        return self.payload
    def iter_content(self, chunk_size):
        yield from self.chunks


class Session:
    def __init__(self):
        self.trust_env = True
        self.calls = []
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def get(self, url, **kwargs):
        assert self.trust_env is False
        assert kwargs["proxies"]["https"] == "socks5h://127.0.0.1:19050"
        assert kwargs["timeout"][0] <= 7
        self.calls.append(url)
        if url == diag.EXIT_CHECK_URL:
            return Response(payload={"ip": "203.0.113.3", "country_code": "fi"})
        return Response(chunks=[b"0" * (128 * 1024), b"1" * (128 * 1024)])


def test_tor_exit_and_download_measurements_use_remote_dns(monkeypatch):
    created = []
    monkeypatch.setattr(diag.requests, "Session", lambda: (created.append(Session()), created[-1])[1])
    exit_result = diag.probe_exit(19050)
    speed = diag.probe_speed(19050, diag.SPEED_URLS[0])
    assert exit_result["country_code"] == "FI"
    assert speed["bytes"] == diag.MAX_BYTES
    assert speed["kib_per_second"] > 0
    assert all(s.trust_env is False for s in created)


def test_fixed_endpoints_and_maximum_bytes():
    with pytest.raises(ValueError):
        diag.probe_speed(19050, "https://example.com/arbitrary")
    with pytest.raises(ValueError):
        diag.probe_speed(19050, diag.SPEED_URLS[0], max_bytes=10 * 1024 * 1024)


def test_failed_socks_does_not_call_any_outside_endpoint(monkeypatch):
    monkeypatch.setattr(diag, "check_socks_port", lambda port: False)
    monkeypatch.setattr(diag, "probe_exit", lambda port: pytest.fail("network used"))
    result = diag.measure_location({
        "slug": "fi-test", "country_code": "FI", "socks_port": 19050,
    })
    assert result["speed"] is None
    assert result["exit"] is None
    assert result["socks_ready"] is False
    assert result["errors"]


def test_speed_endpoint_fallback(monkeypatch):
    monkeypatch.setattr(diag, "check_socks_port", lambda port: True)
    monkeypatch.setattr(diag, "probe_exit", lambda port: {
        "ip": "203.0.113.3", "country_code": "FI",
    })
    attempted = []
    def fake_speed(port, url):
        attempted.append(url)
        if len(attempted) == 1:
            raise requests.exceptions.HTTPError("403")
        return {"bytes": 262144, "kib_per_second": 100.0}
    monkeypatch.setattr(diag, "probe_speed", fake_speed)
    result = diag.measure_location({
        "slug": "fi-test", "country_code": "FI", "socks_port": 19050,
    })
    assert result["speed"]["kib_per_second"] == 100.0
    assert attempted == list(diag.SPEED_URLS)
    assert len(result["errors"]) == 1


def test_double_click_diagnostic_does_not_spawn_second_worker(monkeypatch, tmp_path):
    monkeypatch.setattr(diag, "BASE_DIR", tmp_path)
    monkeypatch.setattr(diag, "get_location", lambda id: {"id": id})
    monkeypatch.setattr(diag, "diagnostic_state", lambda id: {
        "status": "running", "pid": os.getpid()
    })
    monkeypatch.setattr(diag.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("spawned twice"))
    assert diag.launch_diagnostic_job(12) is False
