from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import BASE_DIR
from .db import get_setting, list_locations, set_setting
from .panel_sync import sync_all_panels
from .runtime import apply_runtime
from .security import decrypt_secret

_STATE_KEY = "background_sync_state_json"
_LOCK_PATH = BASE_DIR / "sync.lock"
_LOG_PATH = BASE_DIR / "sync.log"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_state(state: dict[str, Any]) -> None:
    set_setting(_STATE_KEY, json.dumps(state, ensure_ascii=False, separators=(",", ":")))


def sync_job_state() -> dict[str, Any]:
    raw = get_setting(_STATE_KEY, "")
    if not raw:
        return {"status": "idle", "message": ""}
    try:
        state = json.loads(raw)
    except (TypeError, ValueError):
        return {"status": "idle", "message": ""}
    return state if isinstance(state, dict) else {"status": "idle", "message": ""}


def _prepare_log() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if _LOG_PATH.exists() and _LOG_PATH.stat().st_size > 1024 * 1024:
            _LOG_PATH.replace(_LOG_PATH.with_suffix(".log.1"))
    except OSError:
        pass


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def launch_sync_job() -> bool:
    """Start one detached worker and return immediately to the web request."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    lock_handle = _LOCK_PATH.open("a+")
    try:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False

        previous = sync_job_state()
        if (
            previous.get("status") in {"queued", "running"}
            and _pid_alive(int(previous.get("pid") or 0))
        ):
            # The launcher lock lasts only until the child is started. Check
            # its saved PID too, so a second click cannot queue another worker.
            return False

        job_id = uuid.uuid4().hex
        queued = {
            "job_id": job_id,
            "status": "queued",
            "message": "Sync در صف اجرا قرار گرفت.",
            "started_at": _now(),
            "finished_at": "",
            "pid": 0,
            "results": {},
        }
        _write_state(queued)
        _prepare_log()
        try:
            with _LOG_PATH.open("ab", buffering=0) as log:
                proc = subprocess.Popen(
                    [sys.executable, "-m", "torpanel.sync_job", "run", job_id],
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    close_fds=True,
                )
        except Exception as exc:
            queued.update({
                "status": "failed",
                "message": f"شروع worker ناموفق بود: {exc}",
                "finished_at": _now(),
            })
            _write_state(queued)
            raise

        queued["pid"] = proc.pid
        _write_state(queued)
        return True
    finally:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        finally:
            lock_handle.close()


def run_sync_job(job_id: str) -> int:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    with _LOCK_PATH.open("a+") as lock_handle:
        # The launcher briefly holds this lock while spawning us. Waiting here
        # makes the start atomic and also serializes jobs across Gunicorn workers.
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        state = {
            "job_id": job_id,
            "status": "running",
            "message": "در حال بازسازی Tor و همگام‌سازی پنل‌ها…",
            "started_at": _now(),
            "finished_at": "",
            "pid": os.getpid(),
            "results": {},
        }
        _write_state(state)
        try:
            try:
                os.nice(5)
            except OSError:
                pass
            print(f"[{_now()}] sync job {job_id} started", flush=True)
            state["message"] = "در حال بررسی و اعمال تغییرات Tor…"
            _write_state(state)
            apply_runtime()
            state["message"] = "در حال همگام‌سازی امن مسیرهای پنل‌ها…"
            _write_state(state)
            results = sync_all_panels(list_locations(), decrypt_secret)
            failed = {
                key: str(row.get("error") or "خطای نامشخص")
                for key, row in results.items()
                if row.get("ok") is False
            }
            succeeded = [
                key for key, row in results.items()
                if row.get("ok") is True
            ]
            if failed and succeeded:
                status = "partial"
                message = "Sync انجام شد، اما " + "؛ ".join(
                    f"{key}: {error}" for key, error in failed.items()
                )
            elif failed:
                status = "failed"
                message = "Sync ناموفق بود: " + "؛ ".join(
                    f"{key}: {error}" for key, error in failed.items()
                )
            else:
                status = "success"
                message = "Tor، Tunnel و پنل‌ها با موفقیت Reconcile شدند."
            state.update({
                "status": status,
                "message": message,
                "finished_at": _now(),
                "results": results,
            })
            _write_state(state)
            print(f"[{_now()}] sync job {job_id} finished: {status}", flush=True)
            return 0 if status in {"success", "partial"} else 1
        except Exception as exc:
            state.update({
                "status": "failed",
                "message": str(exc),
                "finished_at": _now(),
            })
            _write_state(state)
            print(f"[{_now()}] sync job {job_id} failed: {exc}", flush=True)
            return 1
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "run":
        raise SystemExit(run_sync_job(sys.argv[2]))
    raise SystemExit("usage: python -m torpanel.sync_job run <job-id>")


if __name__ == "__main__":
    main()
