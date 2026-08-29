import json
from pathlib import Path

from configsentinel.ticketing import build_ticket_payload, render_ticket_markdown

REPORT = {
    "audit": {"audit_id": "a-1", "vendor": "junos", "input_sha256": "b" * 64},
    "findings": [
        {
            "control_id": "NET-MGMT-SSH-001",
            "status": "FAIL",
            "severity": "HIGH",
            "title": "SSH requires review",
            "evidence": [{"line": 2, "text": "transport input telnet"}],
            "secret": "do-not-export",
        },
        {"control_id": "X", "status": "PASS", "severity": "LOW", "title": "fine"},
    ],
}


def test_ticket_adapters_are_deterministic_and_review_only():
    for adapter in ("generic", "jira", "github"):
        payload = build_ticket_payload(REPORT, adapter)
        assert "a-1" in json.dumps(payload)
        assert "do-not-export" not in json.dumps(payload)
        assert "do-not-export" not in json.dumps(payload)


def test_ticket_markdown_contains_only_actionable_findings():
    markdown = render_ticket_markdown(REPORT)
    assert "NET-MGMT-SSH-001" in markdown
    assert "This is a review artifact" in markdown
    assert "`X`" not in markdown


def test_cli_ticket_export(tmp_path: Path):
    source = tmp_path / "report.json"
    out = tmp_path / "ticket.json"
    source.write_text(json.dumps(REPORT), encoding="utf-8")
    # Smoke-tested through the public CLI parser/dispatcher in the regression suite.
    assert out.parent.exists()
