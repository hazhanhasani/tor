import json

import torpanel.sync_job as sync_job


def test_sync_job_state_defaults_to_idle(monkeypatch):
    monkeypatch.setattr(sync_job, "get_setting", lambda key, default="": default)
    assert sync_job.sync_job_state() == {"status": "idle", "message": ""}


def test_sync_job_state_reads_persisted_json(monkeypatch):
    payload = {"status": "running", "message": "working", "pid": 123}
    monkeypatch.setattr(
        sync_job,
        "get_setting",
        lambda key, default="": json.dumps(payload),
    )
    assert sync_job.sync_job_state() == payload


def test_second_launch_is_ignored_while_worker_pid_is_alive(monkeypatch, tmp_path):
    import os

    monkeypatch.setattr(sync_job, "BASE_DIR", tmp_path)
    monkeypatch.setattr(sync_job, "_LOCK_PATH", tmp_path / "sync.lock")
    monkeypatch.setattr(sync_job, "sync_job_state", lambda: {
        "status": "running", "pid": os.getpid(),
    })
    monkeypatch.setattr(
        sync_job.subprocess, "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("second worker must not be started")
        ),
    )
    assert sync_job.launch_sync_job() is False
