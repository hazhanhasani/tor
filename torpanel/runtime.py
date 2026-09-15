from __future__ import annotations

import shlex
import subprocess
from typing import Any

import requests

from .config import HELPER_CMD


class RuntimeErrorPanel(RuntimeError):
    pass


def apply_runtime() -> None:
    result = subprocess.run(
        shlex.split(HELPER_CMD), text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=90,
    )
    if result.returncode != 0:
        raise RuntimeErrorPanel(result.stdout.strip() or "Runtime helper failed")


def service_active(slug: str) -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", f"tor-location@{slug}.service"], timeout=5
    )
    return result.returncode == 0


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
