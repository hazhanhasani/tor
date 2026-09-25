from __future__ import annotations

import re
import shlex
import subprocess
from typing import Any

import requests

from .config import HELPER_CMD, TLS_HELPER_CMD


class RuntimeErrorPanel(RuntimeError):
    pass


def apply_runtime() -> None:
    result = subprocess.run(
        shlex.split(HELPER_CMD), text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=90,
    )
    if result.returncode != 0:
        raise RuntimeErrorPanel(result.stdout.strip() or "Runtime helper failed")


def apply_panel_tls() -> str:
    result = subprocess.run(
        shlex.split(TLS_HELPER_CMD), text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=45,
    )
    if result.returncode != 0:
        raise RuntimeErrorPanel(result.stdout.strip() or "Panel TLS helper failed")
    return result.stdout.strip()


def unit_state(unit: str) -> dict[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9@_.-]+\.service", unit):
        raise ValueError("Invalid systemd unit")
    result = subprocess.run(
        ["systemctl", "show", unit, "--property=ActiveState", "--property=SubState", "--no-pager"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=6, check=False,
    )
    values: dict[str, str] = {"active": "unknown", "sub": "unknown"}
    for raw in result.stdout.splitlines():
        if raw.startswith("ActiveState="):
            values["active"] = raw.split("=", 1)[1].strip() or "unknown"
        elif raw.startswith("SubState="):
            values["sub"] = raw.split("=", 1)[1].strip() or "unknown"
    return values


def unit_active(unit: str) -> bool:
    try:
        return unit_state(unit).get("active") == "active"
    except Exception:
        return False


def service_active(slug: str) -> bool:
    return unit_active(f"tor-location@{slug}.service")


def services_active(slugs: list[str]) -> dict[str, bool]:
    """Resolve the entire location list with one systemctl call per batch.

    The dashboard previously spawned one process per location (up to six
    seconds each); during a sync this could make web requests look offline.
    """
    results = {slug: False for slug in slugs}
    if not slugs:
        return results
    for offset in range(0, len(slugs), 64):
        batch = slugs[offset:offset + 64]
        units = [f"tor-location@{slug}.service" for slug in batch]
        if any(not re.fullmatch(r"[A-Za-z0-9@_.-]+\\.service", unit) for unit in units):
            raise ValueError("Invalid service unit")
        try:
            check = subprocess.run(
                ["systemctl", "is-active", "--", *units], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5, check=False,
            )
            statuses = check.stdout.splitlines()
            if len(statuses) == len(batch):
                results.update(
                    {slug: status.strip() == "active"
                     for slug, status in zip(batch, statuses)}
                )
        except (OSError, subprocess.TimeoutExpired):
            # Health info is supplementary; the panel must remain responsive.
            continue
    return results


def journal_tail(unit: str, lines: int = 100) -> str:
    if not re.fullmatch(r"[A-Za-z0-9@_.-]+\.service", unit):
        raise ValueError("Invalid systemd unit")
    lines = max(20, min(int(lines), 300))
    result = subprocess.run(
        ["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "--output=short-iso"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=8, check=False,
    )
    text = result.stdout.strip()
    if result.returncode != 0 and not text:
        return "لاگ این سرویس در دسترس کاربر پنل نیست."
    return text or "هنوز لاگی برای این سرویس ثبت نشده است."


def restart_location(slug: str) -> None:
    apply_runtime()


def test_exit(location: dict[str, Any]) -> dict[str, Any]:
    port = int(location["socks_port"])
    proxy = f"socks5h://127.0.0.1:{port}"
    proxies = {"http": proxy, "https": proxy}
    try:
        r = requests.get(
            "https://ipapi.co/json/", proxies=proxies, timeout=25,
            headers={"User-Agent": "TorLocationManager/1.0"},
        )
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        raise RuntimeErrorPanel(f"Tor exit test failed: {exc}") from exc
    return {
        "ip": data.get("ip"), "country_code": data.get("country_code"),
        "country_name": data.get("country_name"), "city": data.get("city"),
        "expected_country_code": location["country_code"],
    }
