from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from .config import (
    BASE_DIR,
    DOWNLOAD_PROXY,
    GITHUB_API_BASE,
    RELEASE_MIRROR_BASE,
    UPDATE_REPO,
    UPDATE_STATE_PATH,
    UPDATER_CMD,
    VERSION_FILE,
)

SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
CACHE_FILE = BASE_DIR / "release-cache.json"
CACHE_MAX_AGE_SECONDS = 1800


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = SEMVER_RE.fullmatch((value or "").strip())
    if not match:
        raise ValueError(f"Invalid semantic version: {value}")
    return tuple(int(part) for part in match.groups())


def current_version() -> str:
    candidates = [VERSION_FILE, Path(__file__).resolve().parent.parent / "VERSION"]
    for path in candidates:
        try:
            value = path.read_text(encoding="utf-8").strip()
            _version_tuple(value)
            return value.lstrip("v")
        except (OSError, ValueError):
            continue
    return "0.0.0"


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _cached_release() -> dict[str, Any] | None:
    try:
        age = datetime.now(timezone.utc).timestamp() - CACHE_FILE.stat().st_mtime
        if age > CACHE_MAX_AGE_SECONDS:
            return None
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def cached_update_available() -> bool:
    cached = _cached_release()
    return bool(cached and cached.get("update_available") and cached.get("package_ready"))


def _request_json(url: str) -> requests.Response:
    proxies = None
    if DOWNLOAD_PROXY:
        proxies = {"http": DOWNLOAD_PROXY, "https": DOWNLOAD_PROXY}
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            response = requests.get(
                url,
                timeout=(8, 15),
                headers={"Accept": "application/vnd.github+json", "User-Agent": "TorLocationManager-Updater"},
                proxies=proxies,
            )
            return response
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < 2:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"اتصال به سرویس بروزرسانی برقرار نشد: {last_exc}")


def latest_release(force: bool = False) -> dict[str, Any]:
    if not force:
        cached = _cached_release()
        if cached:
            return cached

    api = f"{GITHUB_API_BASE}/repos/{UPDATE_REPO}/releases/latest"
    response = _request_json(api)
    if response.status_code == 404:
        raise RuntimeError("هنوز GitHub Release رسمی برای پروژه منتشر نشده است.")
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise RuntimeError(
            f"بررسی بروزرسانی با HTTP {response.status_code} ناموفق بود. "
            "در شبکه محدود می‌توانید TORPANEL_DOWNLOAD_PROXY یا TORPANEL_GITHUB_API_BASE را تنظیم کنید."
        ) from exc
    raw = response.json()
    tag = str(raw.get("tag_name") or "").strip()
    _version_tuple(tag)

    asset_name = f"tor-location-manager-{tag}.tar.gz"
    checksum_name = f"{asset_name}.sha256"
    assets = {str(a.get("name")): a for a in raw.get("assets", []) if isinstance(a, dict)}
    package_asset = assets.get(asset_name)
    checksum_asset = assets.get(checksum_name)
    package_digest = str((package_asset or {}).get("digest") or "")
    trusted_digest_ready = package_digest.startswith("sha256:")

    result = {
        "tag": tag,
        "version": tag.lstrip("v"),
        "name": str(raw.get("name") or tag),
        "published_at": raw.get("published_at"),
        "html_url": raw.get("html_url"),
        "notes": str(raw.get("body") or "")[:5000],
        "package_ready": bool(package_asset and (checksum_asset or trusted_digest_ready)),
        "asset_name": asset_name,
        "checksum_name": checksum_name,
        "package_digest": package_digest,
        "restricted_network_ready": bool(package_asset),
        "mirror_configured": bool(RELEASE_MIRROR_BASE),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    result["update_available"] = _version_tuple(result["version"]) > _version_tuple(current_version())
    try:
        _atomic_json(CACHE_FILE, result)
    except OSError:
        pass
    return result


def update_state() -> dict[str, Any]:
    try:
        return json.loads(UPDATE_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {"status": "idle"}


def update_log_tail(limit: int = 80) -> str:
    log_path = BASE_DIR / "update.log"
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-limit:])
    except OSError:
        return ""


def trigger_update(tag: str) -> None:
    _version_tuple(tag)
    info = latest_release(force=True)
    if info["tag"] != tag:
        raise RuntimeError("نسخه انتخاب‌شده دیگر آخرین Release نیست؛ صفحه را دوباره بررسی کنید.")
    if not info["package_ready"]:
        raise RuntimeError("Release کامل نیست؛ بسته نصب یا digest معتبر آن در دسترس نیست.")
    if not info["update_available"]:
        raise RuntimeError("نسخه جدیدتری برای نصب وجود ندارد.")

    command = shlex.split(UPDATER_CMD) + [tag]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("شروع سرویس بروزرسانی ناموفق بود: " + completed.stdout.strip())
