import json

from configsentinel.siem import render_siem

REPORT = {
    "audit": {"audit_id": "a-1", "vendor": "cisco_ios"},
    "findings": [
        {
            "finding_id": "f-1",
            "control_id": "SSH",
            "status": "FAIL",
            "severity": "HIGH",
            "confidence": 0.9,
            "evidence": [{"line": 2, "excerpt": "secret-value"}],
        },
        {
            "finding_id": "f-2",
            "control_id": "NTP",
            "status": "PASS",
            "severity": "LOW",
            "confidence": 1.0,
            "evidence": [{"line": 4, "excerpt": "ok"}],
        },
    ],
}


def test_jsonl_export_is_structured_and_review_scoped():
    events = [json.loads(line) for line in render_siem(REPORT).splitlines()]
    assert len(events) == 1
    assert events[0]["control_id"] == "SSH"
    assert "secret-value" not in json.dumps(events)


def test_cef_and_leef_export_headers():
    assert render_siem(REPORT, fmt="cef").startswith(
        "CEF:0|VEYRONIX|ConfigSentinel AI|"
    )
    assert render_siem(REPORT, fmt="leef").startswith(
        "LEEF:2.0|VEYRONIX|ConfigSentinel AI|"
    )
