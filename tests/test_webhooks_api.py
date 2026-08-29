from pathlib import Path

from configsentinel.api import create_app
from configsentinel.webhooks import LocalWebhookQueue, make_audit_event


def test_api_exposes_versioned_openapi_contract():
    app = create_app()
    paths = {route.path for route in app.routes}
    assert "/api/v1/audit" in paths
    assert "/api/v1/health" in paths
    schema = app.openapi()
    assert schema["info"]["version"] == "0.4.0"
    assert "/api/v1/audit" in schema["paths"]


def test_local_webhook_queue_persists_redacted_audit_event(tmp_path: Path):
    report = {
        "audit": {
            "audit_id": "audit-1",
            "vendor": "cisco_ios",
            "input_sha256": "a" * 64,
        },
        "summary": {"failed_count": 1},
        "findings": [{"finding_id": "f1", "secret": "must-not-be-forwarded"}],
    }
    event = make_audit_event(report)
    queue = LocalWebhookQueue(tmp_path / "events.jsonl")
    queue.enqueue(event)
    loaded = queue.read()
    assert loaded[0].event_type == "audit.completed"
    assert loaded[0].payload["finding_ids"] == ["f1"]
    assert "must-not-be-forwarded" not in (tmp_path / "events.jsonl").read_text(
        encoding="utf-8"
    )
