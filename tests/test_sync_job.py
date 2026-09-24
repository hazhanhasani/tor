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
