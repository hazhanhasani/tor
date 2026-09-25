"""Bounded, asynchronous Tor throughput and exit diagnostics.

Never change any inbound or restart Tor during a probe. All destinations are
fixed HTTPS endpoints. SOCKS5h keeps target DNS resolution at the Tor exit.
The job reports measured latency and downloaded bytes; ICMP/client ping is not
misrepresented as end-to-end throughput.
"""
from __future__ import annotations

import fcntl
import json
import os
import socket
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from .config import BASE_DIR
from .db import get_location, get_setting, set_setting
from .sync_job import _pid_alive, sync_job_state

MAX_BYTES = 256 * 1024
EXIT_CHECK_URL = "https://ipapi.co/json/"
SPEED_URLS = (
    "https://speed.cloudflare.com/__down?bytes=262144",
    "https://proof.ovh.net/files/1Mb.dat",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_key(location_id: int) -> str:
    return f"location_diag_{int(location_id)}"


def diagnostic_state(location_id: int) -> dict[str, Any]:
    raw = get_setting(state_key(location_id), "")
    try:
        result = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        result = {}
    return result if isinstance(result, dict) else {}


def _write_state(location_id: int, data: dict[str, Any]) -> None:
    set_setting(
        state_key(location_id),
        json.dumps(data, ensure_ascii=False, separators=(",", ":")),
    )


def _socks_proxy(port: int) -> dict[str, str]:
    if not 1 <= int(port) <= 65535:
        raise ValueError("Invalid local Tor SOCKS port")
    proxy = f"socks5h://127.0.0.1:{int(port)}"
    return {"http": proxy, "https": proxy}


def _session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False  # Ignore cloud host HTTP_PROXY/DNS shortcuts.
    return session


def check_socks_port(port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def probe_exit(port: int, timeout: float = 14.0) -> dict[str, Any]:
    with _session() as session:
        started = time.monotonic()
        response = session.get(
            EXIT_CHECK_URL,
            proxies=_socks_proxy(port),
            timeout=(min(7, timeout), timeout),
            headers={"User-Agent": "TorLocationManager-Diagnostic/1"},
        )
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("Exit lookup returned invalid JSON")
    return {
        "ip": str(payload.get("ip") or "")[:64],
        "country_code": str(payload.get("country_code") or "")[:8].upper(),
        "provider": "ipapi.co (geolocation estimate)",
        "seconds": round(time.monotonic() - started, 2),
    }


def probe_speed(
    port: int, url: str, *, max_bytes: int = MAX_BYTES, timeout: float = 16.0
) -> dict[str, Any]:
    if url not in SPEED_URLS:
        raise ValueError("Only fixed performance endpoints may be tested")
    if not 1024 <= max_bytes <= MAX_BYTES:
        raise ValueError("Invalid bounded download size")
    began = time.monotonic()
    received = 0
    with _session() as session:
        with session.get(
            url, proxies=_socks_proxy(port), timeout=(min(7, timeout), timeout),
            headers={"User-Agent": "TorLocationManager-Diagnostic/1"},
            stream=True,
        ) as response:
            response.raise_for_status()
            first_byte = None
            for chunk in response.iter_content(chunk_size=16 * 1024):
                if not chunk:
                    continue
                if first_byte is None:
                    first_byte = time.monotonic()
                received += min(len(chunk), max_bytes - received)
                if received >= max_bytes:
                    break
    elapsed = max(time.monotonic() - began, 0.001)
    if received < 1024:
        raise RuntimeError("Test endpoint returned too few bytes for a speed test")
    return {
        "endpoint": url.split("/")[2],
        "bytes": received,
        "seconds": round(elapsed, 2),
        "first_byte_seconds": round((first_byte or time.monotonic()) - began, 2),
        "kib_per_second": round((received / 1024) / elapsed, 1),
    }


def measure_location(location: dict[str, Any]) -> dict[str, Any]:
    port = int(location["socks_port"])
    report: dict[str, Any] = {
        "location": str(location["slug"]),
        "expected_country": str(location["country_code"]).upper(),
        "socks_ready": check_socks_port(port),
        "exit": None,
        "speed": None,
        "errors": [],
    }
    if not report["socks_ready"]:
        report["errors"].append(
            "پورت SOCKS داخلی Tor در دسترس نیست؛ وضعیت سرویس را بررسی کنید."
        )
        return report
    try:
        report["exit"] = probe_exit(port)
    except (requests.RequestException, OSError, ValueError) as exc:
        report["errors"].append(
            "بررسی IP خروجی ناموفق بود: " + type(exc).__name__
        )

    for url in SPEED_URLS:
        try:
            report["speed"] = probe_speed(port, url)
            break
        except (requests.RequestException, OSError, ValueError, RuntimeError) as exc:
            report["errors"].append(
                url.split("/")[2] + ": " + type(exc).__name__
            )
    return report


def launch_diagnostic_job(location_id: int) -> bool:
    location_id = int(location_id)
    if not get_location(location_id):
        raise ValueError("Location does not exist")
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = BASE_DIR / f"diagnostic-{location_id}.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        previous = diagnostic_state(location_id)
        if (
            previous.get("status") in {"queued", "running"}
            and _pid_alive(int(previous.get("pid") or 0))
        ):
            return False
        state = {
            "status": "queued", "pid": 0, "started_at": _now(),
            "message": "تست دانلود واقعی از داخل Tor در صف اجراست.",
            "report": {},
        }
        _write_state(location_id, state)
        try:
            log_path = BASE_DIR / "diagnostics.log"
            with log_path.open("ab", buffering=0) as log:
                worker = subprocess.Popen(
                    [sys.executable, "-m", "torpanel.diagnostics", "run", str(location_id)],
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                    start_new_session=True,
                )
        except OSError as exc:
            state.update({"status": "failed", "message": type(exc).__name__})
            _write_state(location_id, state)
            raise
        state["pid"] = worker.pid
        _write_state(location_id, state)
        return True


def run_diagnostic_job(location_id: int) -> int:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    with (BASE_DIR / f"diagnostic-{location_id}.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        location = get_location(location_id)
        if location is None:
            return 1
        state = {
            "status": "running", "pid": os.getpid(),
            "started_at": _now(), "message": "در حال دانلود آزمایشی از Tor…",
            "report": {},
        }
        _write_state(location_id, state)
        try:
            report = measure_location(location)
            if not report["socks_ready"]:
                status = "failed"
            elif report["speed"] and report["exit"]:
                status = "success"
            else:
                status = "partial"
            state.update({
                "status": status,
                "message": (
                    "تست کامل شد؛ سرعت دانلود و IP گزارش‌شده را بررسی کنید."
                    if status == "success" else
                    "تست کامل نبود؛ جزئیات خطاها و سرویس Tor را بررسی کنید."
                ),
                "report": report,
                "finished_at": _now(),
            })
            _write_state(location_id, state)
            return 0 if status in {"success", "partial"} else 1
        except Exception as exc:
            traceback.print_exc()
            state.update({
                "status": "failed", "message": type(exc).__name__,
                "finished_at": _now(),
            })
            _write_state(location_id, state)
            return 1


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] != "run":
        raise SystemExit("usage: python -m torpanel.diagnostics run <location-id>")
    raise SystemExit(run_diagnostic_job(int(sys.argv[2])))


if __name__ == "__main__":
    main()
