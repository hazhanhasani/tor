from __future__ import annotations

import re
from typing import Iterable

import requests


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
GEOSITE_RE = re.compile(r"^geosite:[A-Za-z0-9][A-Za-z0-9._@-]*$", re.I)

WARP_COMPANION_TOKENS = ("domain:challenges.cloudflare.com",)

WARP_DOMAIN_PRESETS = (
    ("geosite:apple", "Apple"),
    ("geosite:meta", "Meta / Instagram / Facebook"),
    ("geosite:google", "Google"),
    ("geosite:openai", "OpenAI / ChatGPT"),
    ("geosite:spotify", "Spotify"),
    ("geosite:netflix", "Netflix"),
    ("geosite:reddit", "Reddit"),
    ("geosite:speedtest", "Speedtest"),
    ("youtube.com", "YouTube"),
    ("github.com", "GitHub"),
    ("discord.com", "Discord"),
    ("check-host.net", "Check-Host"),
)


class WarpAssistError(ValueError):
    pass


def normalize_warp_domains(raw: str | Iterable[str]) -> list[str]:
    rows = raw.splitlines() if isinstance(raw, str) else list(raw)
    result: list[str] = []
    seen: set[str] = set()
    for item in rows:
        value = str(item or "").strip().lower().rstrip(".")
        if not value or value.startswith("#"):
            continue
        if value.startswith("geosite:"):
            if not GEOSITE_RE.fullmatch(value):
                raise WarpAssistError(f"لیست WARP معتبر نیست: {item}")
        else:
            if value.startswith("https://") or value.startswith("http://"):
                value = value.split("://", 1)[1].split("/", 1)[0]
            if ":" in value and not value.startswith("["):
                value = value.split(":", 1)[0]
            if value.startswith("*."):
                value = value[2:]
            if not DOMAIN_RE.fullmatch(value):
                raise WarpAssistError(f"دامنه WARP Assist معتبر نیست: {item}")
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def xray_domain_rules(domains: Iterable[str]) -> list[str]:
    normalized = normalize_warp_domains(domains)
    rules: list[str] = []
    for value in normalized:
        token = value if value.startswith("geosite:") else f"domain:{value}"
        if token not in rules:
            rules.append(token)
    if rules:
        for token in WARP_COMPANION_TOKENS:
            if token not in rules:
                rules.append(token)
    return rules


def test_warp_proxy(port: int, timeout: int = 12) -> dict[str, str | bool]:
    try:
        port = int(port)
    except (TypeError, ValueError) as exc:
        raise WarpAssistError("پورت WARP Proxy معتبر نیست.") from exc
    if not 1024 <= port <= 65535:
        raise WarpAssistError("پورت WARP Proxy باید بین 1024 و 65535 باشد.")
    proxy = f"socks5h://127.0.0.1:{port}"
    try:
        response = requests.get(
            "https://www.cloudflare.com/cdn-cgi/trace",
            proxies={"http": proxy, "https": proxy},
            timeout=timeout,
        )
        response.raise_for_status()
    except Exception as exc:
        raise WarpAssistError(
            f"WARP Proxy روی 127.0.0.1:{port} در دسترس نیست: {exc}"
        ) from exc
    values: dict[str, str] = {}
    for row in response.text.splitlines():
        if "=" in row:
            key, value = row.split("=", 1)
            values[key.strip()] = value.strip()
    warp = values.get("warp", "").lower()
    if warp not in {"on", "plus"}:
        raise WarpAssistError(
            f"Proxy پاسخ داد ولی Cloudflare WARP فعال نیست (warp={warp or 'unknown'})."
        )
    return {
        "ok": True,
        "warp": warp,
        "ip": values.get("ip", ""),
        "colo": values.get("colo", ""),
        "loc": values.get("loc", ""),
    }
