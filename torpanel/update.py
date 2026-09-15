from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from .config import BASE_DIR, UPDATE_REPO, UPDATE_STATE_PATH, UPDATER_CMD, VERSION_FILE

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


def latest_release(force: bool = False) -> dict[str, Any]:
    if not force:
        cached = _cached_release()
        if cached:
            return cached

    api = f"https://api.github.com/repos/{UPDATE_REPO}/releases/latest"
    response = requests.get(
        api,
        timeout=8,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "TorLocationManager-Updater"},
    )
    if response.status_code == 404:
        raise RuntimeError("هنوز GitHub Release رسمی برای پروژه منتشر نشده است.")
    response.raise_for_status()
    raw = response.json()
    tag = str(raw.get("tag_name") or "").strip()
    _version_tuple(tag)

    asset_name = f"tor-location-manager-{tag}.tar.gz"
    checksum_name = f"{asset_name}.sha256"
    assets = {str(a.get("name")): a for a in raw.get("assets", []) if isinstance(a, dict)}
    package_asset = assets.get(asset_name)
    checksum_asset = assets.get(checksum_name)

    result = {
        "tag": tag,
        "version": tag.lstrip("v"),
        "name": str(raw.get("name") or tag),
        "published_at": raw.get("published_at"),
        "html_url": raw.get("html_url"),
        "notes": str(raw.get("body") or "")[:5000],
        "package_ready": bool(package_asset and checksum_asset),
        "asset_name": asset_name,
        "checksum_name": checksum_name,
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
        raise RuntimeError("Release کامل نیست؛ فایل بسته یا checksum آن در Assets وجود ندارد.")
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
